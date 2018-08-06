namespace ES.Taipan.Application

open System
open System.Text
open System.Net
open System.Threading
open System.Collections.Concurrent
open System.Diagnostics
open System.Reflection
open Autofac
open ES.Taipan.Infrastructure.Messaging
open ES.Taipan.Infrastructure.Service
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Fingerprinter
open ES.Taipan.Inspector
open ES.Taipan.Crawler
open ES.Taipan.Discoverer
open ES.Fslog

type internal ScanLogger() =
    inherit LogSource("Scan")
                
    [<Log(1, Message = "All services stopped", Level = LogLevel.Informational)>]
    member this.ScanStopped() =
        this.WriteLog(1, [||])

    [<Log(2, Message = "All services paused", Level = LogLevel.Informational)>]
    member this.ScanPaused() =
        this.WriteLog(2, [||])

    [<Log(3, Message = "All services resumed", Level = LogLevel.Informational)>]
    member this.ScanResumed() =
        this.WriteLog(3, [||])

    [<Log(4, Message = "Start scan of: {0} [{1}]", Level = LogLevel.Informational)>]
    member this.ScanStarted(ip: String, scanContext: ScanContext) =
        this.WriteLog(4, [|scanContext.StartRequest.HttpRequest.Uri; ip|])

    [<Log(5, Message = "Scan engine version: {0}", Level = LogLevel.Informational)>]
    member this.ScanEngineUsed() =
        let scanEngineVersion = FileVersionInfo.GetVersionInfo(Assembly.GetCallingAssembly().Location).ProductVersion
        this.WriteLog(5, [|scanEngineVersion|])

    [<Log(6, Message = "Completed scan of: {0} in {1} seconds", Level = LogLevel.Informational)>]
    member this.ScanCompleted(scanContext: ScanContext, seconds: Int32) =
        this.WriteLog(6, [|scanContext.StartRequest.HttpRequest.Uri; seconds|])

    [<Log(7, Message = "Using template: {0} [{1}]", Level = LogLevel.Informational)>]
    member this.UsedTemplate(template: TemplateProfile) =
        this.WriteLog(7, [|template.Name; template.Id|])
                
    [<Log(8, Message = "{0}", Level = LogLevel.Critical)>]
    member this.FatalScanError(e: Exception) =
        let exceptionError = new StringBuilder()
        let populateField(ex: Exception) =
            ignore(
                exceptionError.AppendLine(),
                exceptionError.AppendLine("Exception Message=" + ex.Message),
                exceptionError.AppendLine("Exception Source=" + ex.Source),
                exceptionError.AppendLine("*** Exception Stack trace follow:"),
                exceptionError.AppendLine(),
                exceptionError.AppendLine(ex.StackTrace),
                exceptionError.AppendLine()
            )
        populateField(e)

        if e.InnerException <> null then
            ignore(
                exceptionError.AppendLine(),
                exceptionError.AppendLine("*** Inner Exception Details"),
                exceptionError.AppendLine()
            )
            populateField(e.InnerException)

        this.WriteLog(8, [|exceptionError.ToString()|])

    [<Log(9, Message = "All services started", Level = LogLevel.Informational)>]
    member this.AllServicesStarted() =        
        this.WriteLog(9, Array.empty)

    [<Log(10, Message = "Unable to connect to host '{0}' port {1}. {2}", Level = LogLevel.Error)>]
    member this.HostPortNotReachable(host: String, port: Int32, errorMessage: String) =
        this.WriteLog(10, [|host; port; errorMessage|])

    [<Log(11, Message = "Start assessment step for web site: {0}", Level = LogLevel.Informational)>]
    member this.StartAssessment(uri: String) =
        this.WriteLog(11, [|uri|])

type ScanState =
    | Created
    | Running
    | Paused
    | Stopped
    | Completed
    | Error

    override this.ToString() =
        match this with
        | Error -> "Error"
        | Created -> "Created"
        | Running -> "Running"
        | Paused -> "Parsed"
        | Stopped -> "Stopped"
        | Completed -> "Completed"

type ScanMetrics() =
    inherit ServiceMetrics("Scan")

    member this.LastHttpRequestStarted(req: HttpRequest) =
        this.AddMetric("Last HTTP request started", req.ToString())

    member this.LastHttpRequestCompleted(req: HttpRequest) =
        this.AddMetric("Last HTTP request completed", req.ToString())

type Scan(scanContext: ScanContext, logProvider: ILogProvider) as this =        
    let _serviceMetrics = new ScanMetrics()    
    let _waitLock = new ManualResetEventSlim(false)
    let _serviceCompletedLock = new Object()

    // local storage for assessment phase
    let _newResourceDiscoveredMessageList = new ConcurrentQueue<NewResourceDiscoveredMessage>()
    let _pageProcessedMessageList = new ConcurrentQueue<PageProcessedMessage>()
    let _pageReProcessedMessage = new ConcurrentQueue<PageReProcessedMessage>()
    let mutable _assessmentPhaseStarted = false
    let mutable _stopRequested = false

    let _logger = new ScanLogger()
    let mutable _container : IContainer option = None
    let mutable _messageBroker : IMessageBroker option = None
    let mutable _scanWorkflow: ScanWorkflow option = None
    let mutable _serviceCompletedFunctionCalled = false
        
    do logProvider.AddLogSourceToLoggers(_logger)
    
    // events definition
    let _processStarted = new Event<Scan>()
    let _processCompleted = new Event<Scan>()
    let _pageProcessed = new Event<PageProcessedMessage>()
    let _pageReProcessed = new Event<PageReProcessedMessage>()
    let _webServerFingerprinted = new Event<WebServerFingerprint>()
    let _newSecurityIssueFound = new Event<NewSecurityIssueFoundMessage>()
    let _newApplicationIdentified = new Event<NewWebApplicationIdentifiedMessage>()
    let _newResourceDiscovered = new Event<NewResourceDiscoveredMessage>()    
    
    let serviceCompleted (inIdleState: Boolean) (service: IService) =
        lock _serviceCompletedLock (fun() ->
            _scanWorkflow.Value.ServiceCompleted(service, inIdleState)    
            if _scanWorkflow.Value.AllServicesCompleted() && not _serviceCompletedFunctionCalled then  
                _serviceCompletedFunctionCalled <- true
                this.FinishedAt <- DateTime.UtcNow
                _processCompleted.Trigger(this)                
                if this.State = ScanState.Running then 
                    this.State <- ScanState.Completed
                _logger.ScanCompleted(scanContext, this.GetDuration())
        )        

    let requestNotificationCallback(req: HttpRequest, completed: Boolean) = 
        if completed then _serviceMetrics.LastHttpRequestCompleted(req)
        else _serviceMetrics.LastHttpRequestStarted(req)

    let checkForJourneyScanRequest(scanContext: ScanContext) =
        if scanContext.Template.HttpRequestorSettings.Journey.Paths |> Seq.isEmpty |> not then
            // enabled Journey Scan, need to force some specific settings
            scanContext.Template.RunResourceDiscoverer <- false
            scanContext.Template.RunWebAppFingerprinter <- false

    let checkForRedirectToWww(uri: Uri, httpResponse: HttpResponse) =
        if HttpUtility.isRedirect(httpResponse.StatusCode) then
            match HttpUtility.tryGetHeader( "Location", httpResponse.Headers) with
            | Some hdr -> 
                let originHost = (new UriBuilder(uri)).Host
                let redirectHost = (new UriBuilder(new Uri(hdr.Value))).Host
                if redirectHost.Equals("www." + originHost, StringComparison.OrdinalIgnoreCase) 
                then Some hdr.Value
                else None
            | None -> None
        else None

    let runAssessmentPhase() =
        if not _assessmentPhaseStarted then
            _assessmentPhaseStarted <- true
            _logger.StartAssessment(scanContext.StartRequest.HttpRequest.Uri.AbsoluteUri)

            _newResourceDiscoveredMessageList
            |> Seq.iter(fun message ->
                if not _stopRequested then
                    // notify other components
                    if scanContext.Template.RunWebAppFingerprinter then
                        _messageBroker.Value.Dispatch(this, convertNewResourceDiscoveredToFingerprintRequest(message))

                    if scanContext.Template.RunVulnerabilityScanner then
                        _messageBroker.Value.Dispatch(this, convertNewResourceDiscoveredToTestRequest(message))
            )

            _pageProcessedMessageList
            |> Seq.iter(fun message ->
                if not _stopRequested then
                    if scanContext.Template.RunWebAppFingerprinter then
                        _messageBroker.Value.Dispatch(this, convertPageProcessedToFingerprintRequest(message))

                    if scanContext.Template.RunVulnerabilityScanner then
                        _messageBroker.Value.Dispatch(this, convertPageProcessedToTestRequest(message))
            )

            _pageReProcessedMessage
            |> Seq.iter(fun message ->
                if not _stopRequested then
                    // notify other components
                    if scanContext.Template.RunVulnerabilityScanner then
                        _messageBroker.Value.Dispatch(this, convertPageReProcessedToTestRequest(message))
            )
        
    do
        if scanContext.Template.CrawlerSettings.Scope <> NavigationScope.WholeDomain then
            // need to adjust the discovere depth in order to avoid meaningless scan
            let absolutePath = scanContext.StartRequest.HttpRequest.Uri.AbsolutePath
            let directories = absolutePath.Split([|"/"|], StringSplitOptions.RemoveEmptyEntries)
            scanContext.Template.ResourceDiscovererSettings.RecursiveDepth <- scanContext.Template.ResourceDiscovererSettings.RecursiveDepth + directories.Length
        
        let builder = new ContainerBuilder()
        ignore(
            builder.RegisterType<ScanWorkflow>().WithParameter("runAssessmentPhaseCallback", runAssessmentPhase),
            builder.RegisterInstance(logProvider).As<ILogProvider>().SingleInstance(),
            builder.RegisterType<DefaultHttpRequestor>().As<IHttpRequestor>().WithParameter("requestNotificationCallback", requestNotificationCallback),
            builder.RegisterInstance(scanContext.Template.HttpRequestorSettings).As<HttpRequestorSettings>().SingleInstance(),
            builder.RegisterType<HeuristicPageNotFoundIdentifier>().As<IPageNotFoundIdentifier>().SingleInstance(),
            builder.RegisterType<DefaultWebPageRequestor>().As<IWebPageRequestor>(),
            builder.RegisterType<DefaultMessageBroker>().As<IMessageBroker>().SingleInstance(),

            builder.RegisterInstance(scanContext.Template.VulnerabilityScannerSettings).As<VulnerabilityScannerSettings>().SingleInstance(),
            builder.RegisterType<FilesystemVulnerabilityScannerAddOnManager>().As<IVulnerabilityScannerAddOnManager>(),
            builder.RegisterType<DefaultVulnerabilityScanner>().As<IVulnerabilityScanner>(),

            builder.RegisterInstance(scanContext.Template.WebAppFingerprinterSettings).As<WebAppFingerprinterSettings>().SingleInstance(),
            builder.RegisterType<FilesystemWebApplicationFingerprintRepository>().As<IWebApplicationFingerprintRepository>().SingleInstance(),
            builder.RegisterType<DefaultWebServerFingerprinter>().As<IWebServerFingerprinter>().SingleInstance(),
            builder.RegisterType<DefaultWebAppFingerprinter>().As<IWebAppFingerprinter>(),

            builder.RegisterInstance(scanContext.Template.ResourceDiscovererSettings).As<ResourceDiscovererSettings>().SingleInstance(),
            builder.RegisterType<FilesystemResourceRepository>().As<IResourceRepository>().SingleInstance(),
            builder.RegisterType<DefaultResourceDiscoverer>().As<IResourceDiscoverer>(),

            builder.RegisterInstance(scanContext.Template.CrawlerSettings).As<CrawlerSettings>().SingleInstance(),
            builder.RegisterType<FilesystemAddOnManager>().As<ICrawlerAddOnManager>(),
            builder.RegisterType<DefaultCrawler>().As<ICrawler>()
        )
        _container <- Some(builder.Build())
        _scanWorkflow <- Some(_container.Value.Resolve<ScanWorkflow>())
                
    // events objects
    member this.ProcessStarted = _processStarted.Publish
    member this.ProcessCompleted = _processCompleted.Publish
    member this.PageProcessed = _pageProcessed.Publish
    member this.PageReProcessed = _pageReProcessed.Publish
    member this.NewSecurityIssueFound = _newSecurityIssueFound.Publish
    member this.NewApplicationIdentified = _newApplicationIdentified.Publish
    member this.NewResourceDiscovered = _newResourceDiscovered.Publish
    member this.WebServerFingerprinted = _webServerFingerprinted.Publish

    abstract NewSecurityIssueFoundMessageHandle : Object * Envelope<NewSecurityIssueFoundMessage> -> unit
    default this.NewSecurityIssueFoundMessageHandle(sender: Object, envelope: Envelope<NewSecurityIssueFoundMessage>) =
        let message = envelope.Item
        _newSecurityIssueFound.Trigger(message)

    abstract NewWebApplicationIdentifiedMessageHandle : Object * Envelope<NewWebApplicationIdentifiedMessage> -> unit
    default this.NewWebApplicationIdentifiedMessageHandle(sender: Object, envelope: Envelope<NewWebApplicationIdentifiedMessage>) =
        let message = envelope.Item
        _newApplicationIdentified.Trigger(message)
        
        // notify other components
        if scanContext.Template.RunWebAppFingerprinter then
            _messageBroker.Value.Dispatch(this, convertWebApplicationIdentifiedToTestRequest(message))

    abstract NewResourceDiscoveredMessageHandle : Object * Envelope<NewResourceDiscoveredMessage> -> unit
    default this.NewResourceDiscoveredMessageHandle(sender: Object, envelope: Envelope<NewResourceDiscoveredMessage> ) =
        let message = envelope.Item
        _newResourceDiscovered.Trigger(message)
        _newResourceDiscoveredMessageList.Enqueue(message)

        if scanContext.Template.RunCrawler then
            _messageBroker.Value.Dispatch(this, convertNewResourceDiscoveredToCrawlRequest(message))

    abstract PageProcessedMessageHandler : Object * Envelope<PageProcessedMessage> -> unit
    default this.PageProcessedMessageHandler(sender: Object, envelope: Envelope<PageProcessedMessage>) =
        let message = envelope.Item
        _pageProcessed.Trigger(message)
        _pageProcessedMessageList.Enqueue(message)

        // notify other components
        if scanContext.Template.RunResourceDiscoverer then
            _messageBroker.Value.Dispatch(this, convertPageProcessedToResourceDiscovererRequest(message))
                    
    abstract PageReProcessedMessageHandler : Object * Envelope<PageReProcessedMessage> -> unit
    default this.PageReProcessedMessageHandler(sender: Object, envelope: Envelope<PageReProcessedMessage>) =
        let message = envelope.Item
        _pageReProcessed.Trigger(message)
        _pageReProcessedMessage.Enqueue(message)

    member this.GetServiceMetrics() =
        let metricMessage = new RequestMetricsMessage()
        _messageBroker.Value.Dispatch(this, metricMessage)        
        metricMessage.GetResults() 
        |> Seq.map(fun kv -> kv.Value :?> ServiceMetrics)
        |> Seq.toList
        
    member internal this.StartScanIp(ip: String) =        
        _logger.ScanStarted(ip, scanContext)
        _logger.UsedTemplate(scanContext.Template)
        
        this.State <- ScanState.Running
        _processStarted.Trigger(this)
        this.ProcessCompleted.Add(fun _ -> _waitLock.Set())
        
        let container = _container.Value

        // handlers registration        
        _messageBroker <- Some <| container.Resolve<IMessageBroker>()
        _messageBroker.Value.Subscribe<PageProcessedMessage>(this.PageProcessedMessageHandler)
        _messageBroker.Value.Subscribe<PageReProcessedMessage>(this.PageReProcessedMessageHandler)
        _messageBroker.Value.Subscribe<NewWebApplicationIdentifiedMessage>(this.NewWebApplicationIdentifiedMessageHandle)
        _messageBroker.Value.Subscribe<NewResourceDiscoveredMessage>(this.NewResourceDiscoveredMessageHandle)
        _messageBroker.Value.Subscribe<NewSecurityIssueFoundMessage>(this.NewSecurityIssueFoundMessageHandle)
        
        // fingerprint the server to guess the extension
        let webServerFingerprint = container.Resolve<IWebServerFingerprinter>()
        let serverFingerprint = webServerFingerprint.Fingerprint(scanContext.StartRequest.HttpRequest.Uri)
        _webServerFingerprinted.Trigger(serverFingerprint)

        // verify if this is a Journey Scan, if so I have to force specific settings in the template
        checkForJourneyScanRequest(scanContext)
        
        // launch vulnerability scanner
        if scanContext.Template.RunVulnerabilityScanner then
            let vulnerabilityScanner = container.Resolve<IVulnerabilityScanner>()
            _scanWorkflow.Value.AddExecutedService(vulnerabilityScanner)
            vulnerabilityScanner.NoMoreTestRequestsToProcess.Add(serviceCompleted true)
            vulnerabilityScanner.ProcessCompleted.Add(serviceCompleted false)

        // launch web application fingerprinter
        if scanContext.Template.RunWebAppFingerprinter then
            let webAppFingerprinter = container.Resolve<IWebAppFingerprinter>()
            _scanWorkflow.Value.AddExecutedService(webAppFingerprinter)
            webAppFingerprinter.NoMoreWebRequestsToProcess.Add(serviceCompleted true)
            webAppFingerprinter.ProcessCompleted.Add(serviceCompleted false)

        // launch resource discoverer
        if scanContext.Template.RunResourceDiscoverer then
            // add extension from server fingerprint
            serverFingerprint.Languages
            |> Seq.iter(fun lang ->
                lang.GetCommonExtensions()
                |> List.map scanContext.Template.ResourceDiscovererSettings.Extensions.Add
                |> ignore
            )

            // instantiate components
            let resourceDiscoverer = container.Resolve<IResourceDiscoverer>()
            _scanWorkflow.Value.AddExecutedService(resourceDiscoverer)
            resourceDiscoverer.NoMoreWebRequestsToProcess.Add(serviceCompleted true)
            resourceDiscoverer.ProcessCompleted.Add(serviceCompleted false)

        // launch crawler, this is a core service. Launch a different crawler for each authentication provided     
        let mutable crawlerRunned = true   
        if not <| scanContext.Template.RunCrawler then     
            // fake a page processed message in order to continue with all the possible services available. This message 
            // must be sent before to instantiace the crawler in order to avoid race condition with the other services
            let fakeWebLink = new WebLink(scanContext.StartRequest, new Guid())
            let noContentResponse = new WebResponse(new HttpResponse())
            this.PageProcessedMessageHandler(this, envelopWithDefaults <| new PageProcessedMessage(fakeWebLink, noContentResponse, 0))
            
            // this ensure that the crawler will not do any work
            scanContext.Template.CrawlerSettings.AllowedHosts.Clear()

            // this ensure that no parsing will be done
            scanContext.Template.CrawlerSettings.ActivateAllAddOns <- false
            scanContext.Template.CrawlerSettings.AddOnIdsToActivate.Clear()

            // create the crawler                        
            let crawler = container.Resolve<ICrawler>()
            crawler.NoMoreWebRequestsToProcess.Add(serviceCompleted true)
            crawler.ProcessCompleted.Add(serviceCompleted false)            
            _scanWorkflow.Value.AddExecutedService(crawler)

            // start the crawler but not pages will be crawled due to the settings restriction
            crawlerRunned <- crawler.Run(scanContext.StartRequest.HttpRequest)

        else
            let instantiateCrawlers(authentications: AuthenticationInfo list) =
                authentications
                |> Seq.iter(fun authentication -> 
                    let crawler = container.Resolve<ICrawler>()
                    crawler.SetAuthentication(authentication)            
                    crawler.NoMoreWebRequestsToProcess.Add(serviceCompleted true)
                    crawler.ProcessCompleted.Add(serviceCompleted false)
                    
                    _scanWorkflow.Value.AddExecutedService(crawler)

                    let scanRequestHost = scanContext.StartRequest.HttpRequest.Uri.Host
                    if not <| scanContext.Template.CrawlerSettings.AllowedHosts.Contains(scanRequestHost) then
                        scanContext.Template.CrawlerSettings.AllowedHosts.Add(scanRequestHost)
                        
                    let modifiedHost =
                        if scanRequestHost.StartsWith("www.") then scanRequestHost.Substring(4)
                        else "www." + scanRequestHost
                    if not <| scanContext.Template.CrawlerSettings.AllowedHosts.Contains(modifiedHost) then
                        scanContext.Template.CrawlerSettings.AllowedHosts.Add(modifiedHost)
                    
                    // start the crawler
                    crawlerRunned <- crawler.Run(scanContext.StartRequest.HttpRequest) || crawlerRunned
                )

            crawlerRunned <- false
                
            // Creates more than one crawler if I have authentication, in this way the not authenticated part and the authenticated
            // part will have two different crawlers. This will allow to identify possilbe EoP.            
            if scanContext.Template.HttpRequestorSettings.Authentication.Type <> AuthenticationType.NoAuthentication then
                // this is a very dirty trick. By setting the authentication to Enabled and the type to NoAuthentication,
                // I avoid to follow the Journey path for this specific case.
                instantiateCrawlers([new AuthenticationInfo(Enabled = true); scanContext.Template.HttpRequestorSettings.Authentication])
            else
                instantiateCrawlers([new AuthenticationInfo()])

        // the scan initialization can be considered done
        _scanWorkflow.Value.InitializationCompleted()
        
        if not crawlerRunned then
            _scanWorkflow.Value.GetServices()
            |> Seq.map(fun (_, srv) -> srv)
            |> Seq.filter(fun srv -> srv :? ICrawler)
            |> Seq.map(fun srv -> srv :?> ICrawler)
            |> Seq.iter(fun crawler -> crawler.TriggerIdleState())
        
        _logger.AllServicesStarted()
        
    member internal this.Start() =   
        let mutable ip : IPAddress option = None 
        let mutable hostReachable = false
        let mutable errorMessage = String.Empty
        let uri = scanContext.StartRequest.HttpRequest.Uri
            
        try
            this.StartedAt <- DateTime.UtcNow
            _logger.ScanEngineUsed()

            // try to get the IP and verify if the host is reachable
            ip <- Some(Dns.GetHostAddresses(uri.Host) |> Seq.head)
            let webRequestor = _container.Value.Resolve<IWebPageRequestor>()
            
            let mutable webResponse = webRequestor.RequestInitialWebPage(new WebRequest(uri))

            // check for redirect
            match checkForRedirectToWww(uri, webResponse.HttpResponse) with
            | Some redirectUri -> 
                scanContext.StartRequest.HttpRequest.Uri <- new Uri(redirectUri)
                webResponse <- webRequestor.RequestInitialWebPage(new WebRequest(redirectUri))
            | None -> ()

            // this is necessary to avoid leak from the ChromeDriver
            match webRequestor with
            | :? IDisposable as d -> d.Dispose()
            | _ -> ()

            let noNeededCrawler = scanContext.Template.RunResourceDiscoverer || scanContext.Template.RunWebAppFingerprinter
            hostReachable <- (webResponse.PageExists || noNeededCrawler) && webResponse.HttpResponse <> HttpResponse.Error
        with e -> 
            errorMessage <- e.Message
                        
        // if the host is reachable start the scan around a generic try/catch to avoid to crash everything :\
        match ip with
        | Some ip when hostReachable ->    
            try this.StartScanIp(ip.ToString())
            with e -> 
                _logger.FatalScanError(e)
                this.State <- ScanState.Error
                _waitLock.Set()
        | _ ->             
            _logger.HostPortNotReachable(uri.Host, uri.Port, errorMessage)
            this.State <- ScanState.Error
            _waitLock.Set()            
        
    member this.WaitForcompletation() =
        _waitLock.Wait()
                    
    member val Id = Guid.NewGuid() with get
    member val Context = scanContext with get
    member val State = Created with get, set
    member val StartedAt = DateTime.MinValue with get, set
    member val FinishedAt = DateTime.MaxValue with get, set   
     
    member this.GetDuration() =
        let timeSpan = this.FinishedAt.Subtract(this.StartedAt)
        int32 timeSpan.TotalSeconds

    member this.Pause() =
        _scanWorkflow.Value.Pause()
        _logger.ScanPaused()

    member this.Stop() =
        _stopRequested <- true
        _scanWorkflow.Value.Stop()
        _logger.ScanStopped()
        this.State <- ScanState.Stopped

    member this.Resume() =
        _scanWorkflow.Value.Resume()
        _logger.ScanResumed()

    interface IDisposable with
        member this.Dispose() =
            (_scanWorkflow.Value :> IDisposable).Dispose()