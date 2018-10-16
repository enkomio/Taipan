namespace ES.Taipan.Crawler

open System
open System.Threading
open System.Collections.Generic
open System.Collections.Concurrent
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Infrastructure.Service
open ES.Taipan.Infrastructure.Messaging
open ES.Taipan.Infrastructure.Validation
open ES.Fslog

module private CrawlerIdGenerator =
    let private _id = ref -1
    let generateId() =
        incr _id
        !_id

type DefaultCrawler(settings: CrawlerSettings, webRequestor: IWebPageRequestor, addOnManager: ICrawlerAddOnManager, messageBroker: IMessageBroker, logProvider: ILogProvider) as this =         
    let mutable _isInitialized = false
    let mutable _linkMutator: WebLinkMutator option = None
    let mutable _processCompletedInvoked = false
    let mutable _rootPage = new WebLink(new WebRequest("http://127.0.0.1"), Guid.Empty)
    let _crawlerState = new CrawlerState(settings, webRequestor.HttpRequestor.Settings, logProvider)
    let _stateController = new ServiceStateController()
    let _processCompleted = new Event<IService>()
    let _initializationCompleted = new Event<IService>()
    let _noMoreWebRequestsToProcess = new Event<ICrawler>()
    let _addOns = new List<ICrawlerAddOn>()
    let _logger = new CrawlerLogger()
    let _crawlerId = CrawlerIdGenerator.generateId()
    let _serviceDiagnostics = new ServiceDiagnostics()
    let _serviceMetrics = new ServiceMetrics("Crawler")
    let _statusMonitor = new Object()
    let _runToCompletationCalledLock = new ManualResetEventSlim()

    let requestNotificationCallback(httpRequestor: IHttpRequestor, req: HttpRequest, completed: Boolean) =     
        let prefix = "CrawlerHttpRequestor_"
        let httpRequestorMetrics = _serviceMetrics.GetSubMetrics(prefix + httpRequestor.Id.ToString("N"))
        if completed 
        then httpRequestorMetrics.AddMetric("Last HTTP request completed", req.ToString())
        else httpRequestorMetrics.AddMetric("Last HTTP request started", req.ToString())
    
    let checkCrawlerState() =
        if not <| _crawlerState.HasWebRequestToProcess then            
            this.TriggerIdleState()
            
    let addWebLink(wl: WebLink) =
        let mutable success = false
        
        // replace default parameters according to settings
        let webRequest = wl.Request
        replaceParameterValue(webRequest.HttpRequest, settings.DefaultParameters)
                
        let addPageToCrawlResult = _crawlerState.AddPageToCrawl(wl)
        if addPageToCrawlResult = CrawlerStateAddPageStatusResult.Success then
            success <- true
            messageBroker.Dispatch(this, new NewPageAddedMessage(wl, _crawlerId))
            _logger.NewPageAdded(wl)
        success

    let isPageOkToBeSignaledAsProcessed(webLink: WebLink, webResponse: WebResponse) =
        let isFakePage = webLink.ParsedHtmlCode.Equals(webLink.Id.ToString("N"), StringComparison.OrdinalIgnoreCase)
        webResponse.PageExists || (webLink.OriginalWebLink.IsNone && not isFakePage)

    let extractLinksFromFirstRequest(webLink: WebLink, webResponse: WebResponse) =
        _addOns
        |> Seq.sortBy(fun addOn -> addOn.Priority)
        |> Seq.map(fun addOn ->
            _serviceMetrics.AddMetric("Last activated Add On", addOn.Name)
            addOn.DiscoverNewLinks(webLink, webResponse, messageBroker, logProvider)
        )        
        |> Seq.concat        
        |> Seq.toList

    let addWebLinkAndMutation(webLink: WebLink, webResponse: WebResponse) =        
        if addWebLink(webLink) then
            // create mutation links
            try
                if _linkMutator.IsSome then
                    _linkMutator.Value.CreateMutationLinksFromTemplate(webLink, webResponse)
                    |> Seq.iter (fun wl -> 
                        // mutation link should not be sent via Selenium, so erase the Source property
                        wl.Request.HttpRequest.Source <- None
                        addWebLink(wl) |> ignore
                    )
            with
            | :? UriFormatException -> ()

    let processWebResponse(webLink: WebLink, webResponse: WebResponse) =
        _addOns
        |> Seq.sortBy(fun addOn -> addOn.Priority)
        |> Seq.iter(fun addOn ->
            // force adding only one time
            _serviceMetrics.AddMetric("Last activated Add On", addOn.Name)
            addOn.DiscoverNewLinks(webLink, webResponse, messageBroker, logProvider)
            |> Seq.sortBy(fun webLink -> webLink.Request.HttpRequest.Source.IsNone)
            |> Seq.iter (fun foundWebLink -> 
                foundWebLink.Referer <- Some webLink
                addWebLinkAndMutation(foundWebLink, webResponse)
            )
        )

    let processWebRequest(webLink: WebLink) =
        if _crawlerState.IsCrawlerStateAvailable() && not _stateController.IsStopped && not(_crawlerState.IsStopRequested()) then
            let webResponse = webRequestor.RequestWebPage(webLink.Request)
            _serviceMetrics.AddMetric("Last Processed Web Page", webLink.Request.HttpRequest.Uri.ToString())

            if _crawlerState.IsWebResponseValid(webResponse) then  
                processWebResponse(webLink, webResponse)
                    
            if isPageOkToBeSignaledAsProcessed(webLink, webResponse) then
                messageBroker.Dispatch(this, new PageProcessedMessage(webLink, webResponse, _crawlerId))
            _logger.PageProcessed(webLink, webResponse.HttpResponse) 

        _crawlerState.PageAnalyzed(webLink)

    let makeFirstRequest(httpRequest: HttpRequest) =
        let webRequest = new WebRequest(httpRequest)
        _rootPage <- new WebLink(webRequest, false, this.ServiceId)
        let webResponse = webRequestor.RequestInitialWebPage(webRequest)

        // the first page force existing field, since the home page sometimes could be a blind redirect
        webResponse.PageExists <- true
        
        let extractedLinks = extractLinksFromFirstRequest(_rootPage, webResponse)

        // finally add the extracted links
        _rootPage::extractedLinks
        |> Seq.sortBy(fun webLink -> webLink.Request.HttpRequest.Source.IsNone)
        |> Seq.iter(fun wl -> addWebLinkAndMutation(wl, webResponse))

        _crawlerState.HasWebRequestToProcess

    let completeProcess() =
        if not _processCompletedInvoked then
            _processCompletedInvoked <- true
            _stateController.ReleaseStopIfNecessary()
            _stateController.UnlockPause()
            _processCompleted.Trigger(this)
                        
            if _stateController.IsStopped then
                _serviceMetrics.AddMetric("Status", "Stopped")
            else
                _serviceMetrics.AddMetric("Status", "Completed")

    let doReCrawling() =
        _logger.StartReCrawling()
        _serviceDiagnostics.Activate()
        _serviceMetrics.AddMetric("Status", "Re-Crawling")
        _crawlerState.GetAllProcessedPages()
        |> Seq.iter(fun webPage ->
            if not _stateController.IsStopped && not(_crawlerState.IsStopRequested()) then   
                _stateController.WaitIfPauseRequested()
                let webRequest = webPage.Request
                let webResponse = webRequestor.RequestWebPage(webRequest)                
                _logger.PageReProcessed(webPage, webResponse.HttpResponse)
                messageBroker.Dispatch(this, new PageReProcessedMessage(webPage, webResponse, _crawlerId))
        )
        _serviceMetrics.AddMetric("Status", "Idle")
        _serviceDiagnostics.GoIdle()

    let doCrawling() =
        // main crawling loop 
        for webRequest in _crawlerState.GetNextWebRequest() do                                
            lock _statusMonitor (fun () ->                    
                _serviceDiagnostics.Activate()
                _serviceMetrics.AddMetric("Status", "Running")
                _stateController.WaitIfPauseRequested()
                
                // process request
                processWebRequest(webRequest)
                    
                // check the crawler status
                checkCrawlerState()
            )

    let crawlerLoop() =
        async {
            // run the crawler
            doCrawling()

            if _crawlerState.IsStopRequested() then
                // wait until the run to completation is called
                checkCrawlerState()
                _stateController.ReleaseStopIfNecessary()
                _logger.WaitRunToCompletation()
                _runToCompletationCalledLock.Wait()

            // no more web requests to process
            completeProcess()

            // check for some error condition to log
            match _crawlerState.GetStatus() with
            | CrawlerStateAddPageStatusResult.MaxNumberOfPagesToCrawlReached -> 
                _logger.LimitOfMaxNumberOfPagesToCrawlReached(settings.MaxNumberOfPagesToCrawl)
            | _ -> ()            
        } |> Async.Start

    let handleNewMessage(sender: Object, message: Envelope<String>) =
        match message.Item.ToUpper() with
        | "STOP" -> this.Stop()
        | "PAUSE" -> this.Pause()
        | "RESUME" -> this.Resume()
        | _ -> ()

    let handleCrawlRequestMessage(sender: Object, message: Envelope<CrawlRequest>) =
        if _isInitialized then
            this.CrawlRequest(message.Item.Request)

    let handleGetSettings(sender: Object, message: Envelope<GetSettingsMessage>) =
        message.Item.CrawlerSettings <- Some settings
        message.Item.HttpRequestorSettings <- Some webRequestor.HttpRequestor.Settings

    let handleExtractWebLinksMessage(sender: Object, message: Envelope<ExtractWebLinksMessage>) =
        let webRequest = message.Item.Request
        let webLink = new WebLink(webRequest, false, this.ServiceId)
        let extractedLinks = new List<WebLink>()

        _addOns
        |> Seq.filter(fun addOn -> message.Item.BlackListedAddOn |> List.contains addOn.Id |> not)
        |> Seq.iter(fun addOn ->            
            addOn.DiscoverNewLinks(webLink, message.Item.Response, messageBroker, logProvider)
            |> Seq.iter (extractedLinks.Add)
        )

        // send the response message
        let messageWebLinksExtracted = new WebLinksExtractedMessage(message.Item.Id, extractedLinks |> Seq.toList)
        messageBroker.Dispatch(this, messageWebLinksExtracted)

    let handleRequestMetricsMessage(sender: Object, message: Envelope<RequestMetricsMessage>) =
        message.Item.AddResult(this, _serviceMetrics)

    let filterAddOn (addOn: ICrawlerAddOn) = 
        if settings.ActivateAllAddOns || settings.AddOnIdsToActivate.Contains(addOn.Id) then 
            _logger.AddOnActivated(addOn.Name)
            true
        else 
            false 

    do 
        // set requestor settings
        webRequestor.SetPageNotFoundIdentifier(new HeuristicPageNotFoundIdentifier(webRequestor.HttpRequestor))
        webRequestor.HttpRequestor.RequestNotificationCallback <- requestNotificationCallback

        // event subscription
        messageBroker.Subscribe<String>(handleNewMessage)
        messageBroker.Subscribe<CrawlRequest>(handleCrawlRequestMessage)
        messageBroker.Subscribe<ExtractWebLinksMessage>(handleExtractWebLinksMessage)
        messageBroker.Subscribe<GetSettingsMessage>(handleGetSettings)
        messageBroker.Subscribe<RequestMetricsMessage>(handleRequestMetricsMessage)
        logProvider.AddLogSourceToLoggers(_logger)

        // load only enabled addOn
        addOnManager.LoadAddOns()        
        addOnManager.GetAddOns()
        |> List.filter filterAddOn
        |> _addOns.AddRange

        // configure the HttpRequestor according the crawler esigence
        webRequestor.HttpRequestor.SessionState <- Some <| new SessionStateManager()
        webRequestor.HttpRequestor.Settings.AllowAutoRedirect <- false

        // add the link mutator
        if settings.MutateWebLinks then
            _linkMutator <- Some <| new WebLinkMutator(settings)

    member this.ProcessCompleted = _processCompleted.Publish
    member this.InitializationCompleted = _initializationCompleted.Publish
    
    member val ServiceId = Guid.NewGuid() with get    
    member this.NoMoreWebRequestsToProcess = _noMoreWebRequestsToProcess.Publish
    member val Diagnostics = _serviceDiagnostics with get

    member this.LinkMutator
        with get() = _linkMutator
        and set(v) = 
            if settings.MutateWebLinks then
                _linkMutator <- v

    member this.SetAuthentication(authentication: AuthenticationInfo) =
        webRequestor.HttpRequestor.Settings.Authentication <- authentication

    member this.State
        with get() = _crawlerState

    member this.TriggerIdleState() =        
        _serviceMetrics.AddMetric("Status", "Idle")
        _serviceDiagnostics.GoIdle()
        _logger.GoIdle()        
        _noMoreWebRequestsToProcess.Trigger(this)

    member this.Run(httpRequest: HttpRequest) =
        let mutable crawlerActivated = false
        this.State.Initialize(httpRequest.Uri)
        let crawlerActivated = makeFirstRequest(httpRequest)        
        _isInitialized <- true

        // trigger the initialization event
        _initializationCompleted.Trigger(this)          
        crawlerActivated

    member this.CrawlRequest(webRequest: WebRequest) =  
        let webLink = new WebLink(webRequest, false, this.ServiceId)
        addWebLink(webLink) |> ignore
        checkCrawlerState()
                
    member this.Pause() = 
        // if there aren't requests that must be processed the not blocking call of Pause must be executed because the
        // crawler loop is waiting for request to crawl and until this requisite old the WaitInInPauseState method
        // isn't called, so a deadlock may occour.
        let action =
            if Monitor.TryEnter(_statusMonitor) && _serviceDiagnostics.IsIdle then _stateController.NotBlockingPause
            else _stateController.Pause

        if action() then
            _logger.CrawlerPaused()
            _serviceMetrics.AddMetric("Status", "Paused")
                
    member this.Resume() = 
        if _stateController.ReleasePause() then
            _serviceMetrics.AddMetric("Status", "Running")
            _logger.CrawlerResumed()
            checkCrawlerState()
        
    member this.Stop() =
        _logger.StopRequested()
        _crawlerState.StopServiceWebPages()
        if _stateController.Stop() then
            _logger.CrawlerStopped()        

    member this.RunToCompletation() =
        _serviceMetrics.AddMetric("Status", "Run to completation")
        _logger.RunToCompletation()

        // run the re-crawling if necessary. Actually no one use this feature,
        // consider to remove it in the future if not necessary
        if settings.ReCrawlPages then
            doReCrawling()

        _crawlerState.CompleteAdding()
        _runToCompletationCalledLock.Set()

    member this.Activate() =
        crawlerLoop()

    interface IDisposable with
        member this.Dispose() =
            // dispose all addons
            for addOn in _addOns do
                if addOn :? IDisposable then
                    let disposable = addOn :?> IDisposable
                    disposable.Dispose()

            // dispose web requestor, this is importance, since if we use the Javascript
            // Enginem the dispose will tear down the browser
            match webRequestor with
            | :? IDisposable as disposable -> disposable.Dispose()
            | _ -> ()

    interface ICrawler with
        member this.ServiceId
            with get() = this.ServiceId

         member this.Diagnostics
            with get() = this.Diagnostics
            
        member this.State
            with get() = this.State

        member this.CrawlRequest(webRequest: WebRequest) =
            this.CrawlRequest(webRequest)

        member this.Pause() = 
            this.Pause()

        member this.Resume() = 
            this.Resume()
        
        member this.Stop() =    
            this.Stop()

        member this.Activate() =
            this.Activate()

        member this.RunToCompletation() =
            this.RunToCompletation()

        member this.ProcessCompleted
            with get() = this.ProcessCompleted

        member this.InitializationCompleted
            with get() = this.InitializationCompleted

        member this.NoMoreWebRequestsToProcess
            with get() = this.NoMoreWebRequestsToProcess

        member this.LinkMutator
            with get() = this.LinkMutator
            and set(v) = this.LinkMutator <- v

        member this.Run(httpRequest: HttpRequest) =
            this.Run(httpRequest)

        member this.SetAuthentication(authentication: AuthenticationInfo) =
            this.SetAuthentication(authentication)

        member this.TriggerIdleState() =
            this.TriggerIdleState()
   
