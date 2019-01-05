namespace ES.Taipan.Application

open System
open System.Net
open System.Threading
open System.Collections.Concurrent
open Autofac
open ES.Taipan.Infrastructure.Messaging
open ES.Taipan.Infrastructure.Service
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Fingerprinter
open ES.Taipan.Inspector
open ES.Taipan.Crawler
open ES.Taipan.Discoverer
open ES.Fslog
open System.Runtime.Remoting.Messaging
open System.Net.NetworkInformation

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
        
type Scan(scanContext: ScanContext, logProvider: ILogProvider) as this =        
    let _serviceMetrics = new ServiceMetrics("Scan")
    let _waitLock = new ManualResetEventSlim(false)
    let _serviceCompletedLock = new Object()

    // local storage for assessment phase
    let mutable _newResourceDiscoveredMessageList = new ConcurrentQueue<NewResourceDiscoveredMessage>()
    let mutable _pageProcessedMessageList = new ConcurrentQueue<PageProcessedMessage>()
    let mutable _pageReProcessedMessage = new ConcurrentQueue<PageReProcessedMessage>()
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
                _serviceMetrics.AddMetric("Status", "completed")
        )        

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
            _serviceMetrics.AddMetric("In run assessment phase", "true")
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

            // cleanup
            _newResourceDiscoveredMessageList <- new ConcurrentQueue<NewResourceDiscoveredMessage>()
            _pageProcessedMessageList <- new ConcurrentQueue<PageProcessedMessage>()
            _pageReProcessedMessage <- new ConcurrentQueue<PageReProcessedMessage>()

    let rec getAllMetrics(serviceMetrics: ServiceMetrics) = [
        yield serviceMetrics
        let allMetrics =
            serviceMetrics.GetAllSubMetrics() 
            |> Seq.map(fun kv -> getAllMetrics(kv.Value))
            |> Seq.concat

        yield! allMetrics
    ]

    let handleNewWebPageRequestorMessage(sender: Object, message: Envelope<NewWebPageRequestorMessage>) =
        let webPageRequestor = _container.Value.Resolve<IWebPageRequestor>()
        message.Item.WebPageRequestor <- Some webPageRequestor

    let getTaipanIp() =
        let mutable ip = "<no network>"        
        if NetworkInterface.GetIsNetworkAvailable() then
            NetworkInterface.GetAllNetworkInterfaces()
            |> Seq.filter(fun network -> network.NetworkInterfaceType = NetworkInterfaceType.Ethernet)
            |> Seq.map(fun network -> network.GetIPProperties().UnicastAddresses)
            |> Seq.concat
            |> Seq.filter(fun ip -> ip.Address.AddressFamily = System.Net.Sockets.AddressFamily.InterNetwork)
            |> Seq.tryHead
            |> function
                | Some ipInfo -> ip <- ipInfo.Address.ToString()
                | None -> ()
        ip
        
    do
        _serviceMetrics.AddMetric("Status", "created")
        if scanContext.Template.CrawlerSettings.Scope <> NavigationScope.WholeDomain then
            // need to adjust the discovere depth in order to avoid meaningless scan
            let absolutePath = scanContext.StartRequest.HttpRequest.Uri.AbsolutePath
            let directories = absolutePath.Split([|"/"|], StringSplitOptions.RemoveEmptyEntries)
            scanContext.Template.ResourceDiscovererSettings.RecursiveDepth <- scanContext.Template.ResourceDiscovererSettings.RecursiveDepth + directories.Length
        
        let builder = new ContainerBuilder()
        ignore(
            builder.RegisterType<ScanWorkflow>().WithParameter("runAssessmentPhaseCallback", runAssessmentPhase),
            builder.RegisterInstance(logProvider).As<ILogProvider>().SingleInstance(),
            builder.RegisterType<DefaultHttpRequestor>().As<IHttpRequestor>(),
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
        
        // resolve needed objects
        _container.Value.Resolve<IMessageBroker>().Subscribe(handleNewWebPageRequestorMessage)
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
        |> Seq.map(fun kv -> getAllMetrics(kv.Value :?> ServiceMetrics))
        |> Seq.concat
        |> Seq.toList
        |> fun metrics -> _serviceMetrics::metrics
        
    member internal this.StartScanIp(ip: String) =   
        _serviceMetrics.AddMetric("Status", "running")
        _logger.ScanStarted(ip, scanContext)
        _logger.TaipanIp(getTaipanIp())
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
            // request only the input page in order to continue with all the possible services available.
            let webRequestor = _container.Value.Resolve<IWebPageRequestor>()            
            let webResponse = webRequestor.RequestInitialWebPage(scanContext.StartRequest)

            // send the initial message. This message must be sent before to instantiace the crawler 
            // in order to avoid race condition with the other services
            let entryWebLink = new WebLink(scanContext.StartRequest, Guid.NewGuid())
            this.PageProcessedMessageHandler(this, envelopWithDefaults <| new PageProcessedMessage(entryWebLink, webResponse, 0))
            
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
                // this is a very dirty trick. By setting the authentication 
                // to Enabled and the type to NoAuthentication,
                // I avoid to follow the Journey path for this specific case.
                instantiateCrawlers([
                    scanContext.Template.HttpRequestorSettings.Authentication
                    
                    // TODO, until the plugin for differential analysis isn't readym this settings is not useful
                    // new AuthenticationInfo(Enabled = true)
                ])
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
            _serviceMetrics.AddMetric("Status", "started")
            this.StartedAt <- DateTime.UtcNow
            _logger.ScanEngineUsed()

            // try to get the IP and verify if the host is reachable
            ip <- Some(Dns.GetHostAddresses(uri.Host) |> Seq.head)
            let webRequestor = _container.Value.Resolve<IWebPageRequestor>()            
            webRequestor.HttpRequestor.Settings.PermanentDisableAuthentication()
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

            let noNeededCrawler = 
                scanContext.Template.RunResourceDiscoverer || 
                scanContext.Template.RunWebAppFingerprinter ||
                scanContext.Template.RunVulnerabilityScanner
            hostReachable <- (webResponse.PageExists || noNeededCrawler) && webResponse.HttpResponse <> HttpResponse.Error
        with e -> 
            _serviceMetrics.AddMetric("Status", "error")
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
            _serviceMetrics.AddMetric("Status", "error")
            _logger.HostPortNotReachable(uri.Host, uri.Port, errorMessage)
            this.State <- ScanState.Error
            _waitLock.Set()            
        
    member this.WaitForcompletation() =
        _serviceMetrics.AddMetric("Status", "wait for completation")
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
        _serviceMetrics.AddMetric("Status", "paused")
        _scanWorkflow.Value.Pause()
        _logger.ScanPaused()

    member this.Stop() =
        _serviceMetrics.AddMetric("Status", "stopped")
        _stopRequested <- true
        _scanWorkflow.Value.Stop()
        _logger.ScanStopped()
        this.State <- ScanState.Stopped

    member this.Resume() =
        _serviceMetrics.AddMetric("Status", "running")
        _scanWorkflow.Value.Resume()
        _logger.ScanResumed()

    interface IDisposable with
        member this.Dispose() =
            (_scanWorkflow.Value :> IDisposable).Dispose()