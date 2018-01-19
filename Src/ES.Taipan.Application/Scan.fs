namespace ES.Taipan.Application

open System
open System.Text
open System.Net
open System.Threading
open System.IO
open System.Diagnostics
open System.Reflection
open Autofac
open ES.Taipan.Infrastructure.Messaging
open ES.Taipan.Infrastructure.Service
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Fingerprinter
open ES.Taipan.Inspector
open ES.Taipan.Fingerprinter
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

    [<Log(4, Message = "Start scan of: {0} [{1}]. Template: {2} [{3}]", Level = LogLevel.Informational)>]
    member this.ScanStarted(ip: String, scanContext: ScanContext) =
        this.WriteLog(4, [|scanContext.StartRequest.HttpRequest.Uri; ip; scanContext.Template.Name; scanContext.Template.Id|])

    [<Log(5, Message = "Scan engine version: {0}", Level = LogLevel.Informational)>]
    member this.ScanEngineUsed() =
        let scanEngineVersion = FileVersionInfo.GetVersionInfo(Assembly.GetCallingAssembly().Location).ProductVersion
        this.WriteLog(5, [|scanEngineVersion|])

    [<Log(6, Message = "Completed scan of: {0} in {1} seconds", Level = LogLevel.Informational)>]
    member this.ScanCompleted(scanContext: ScanContext, seconds: Int32) =
        this.WriteLog(6, [|scanContext.StartRequest.HttpRequest.Uri; seconds|])

    [<Log(7, Message = "Unable to resolve host: {0}. Scan aborted.", Level = LogLevel.Error)>]
    member this.HostNotReachable(host: String) =
        this.WriteLog(7, [|host|])
        
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

    [<Log(10, Message = "Unable to connect to host '{0}' port {1}. Scan aborted.", Level = LogLevel.Error)>]
    member this.HostPortNotReachable(host: String, port: Int32) =
        this.WriteLog(10, [|host; port|])

type ScanState =
    | Created
    | Running
    | Paused
    | Stopped
    | Completed

    override this.ToString() =
        match this with
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
    let _scanWorkflow = new ScanWorkflow(logProvider)        
    let _serviceMetrics = new ScanMetrics()    
    let _waitLock = new ManualResetEventSlim(false)
    let _serviceCompletedLock = new Object()
    let _logger = new ScanLogger()
    let mutable _container : IContainer option = None
    let mutable _messageBroker : IMessageBroker option = None
    let mutable _serviceCompletedFunctionCalled = false
    
    do logProvider.AddLogSourceToLoggers(_logger)
    
    // events definition
    let _processStarted = new Event<Scan>()
    let _processCompleted = new Event<Scan>()
    let _pageProcessed = new Event<PageProcessedMessage>()
    let _webServerFingerprinted = new Event<WebServerFingerprint>()
    let _newSecurityIssueFound = new Event<NewSecurityIssueFoundMessage>()
    let _newApplicationIdentified = new Event<NewWebApplicationIdentifiedMessage>()
    let _newResourceDiscovered = new Event<NewResourceDiscoveredMessage>()    
    
    let serviceCompleted(service: IService) =
        lock _serviceCompletedLock (fun() ->
            _scanWorkflow.ServiceCompleted(service)    
            if _scanWorkflow.AllServicesCompleted() && not _serviceCompletedFunctionCalled then  
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
                
    do
        if scanContext.Template.CrawlerSettings.Scope <> NavigationScope.WholeDomain then
            // need to adjust the discovere depth in order to avoid meaningless scan
            let absolutePath = scanContext.StartRequest.HttpRequest.Uri.AbsolutePath
            let directories = absolutePath.Split([|"/"|], StringSplitOptions.RemoveEmptyEntries)
            scanContext.Template.ResourceDiscovererSettings.RecursiveDepth <- scanContext.Template.ResourceDiscovererSettings.RecursiveDepth + directories.Length
        
        let builder = new ContainerBuilder()
        ignore(
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
                
    // events objects
    member this.ProcessStarted = _processStarted.Publish
    member this.ProcessCompleted = _processCompleted.Publish
    member this.PageProcessed = _pageProcessed.Publish
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

        // notify other components
        if scanContext.Template.RunWebAppFingerprinter then
            _messageBroker.Value.Dispatch(this, convertNewResourceDiscoveredToFingerprintRequest(message))

        if scanContext.Template.RunVulnerabilityScanner then
            _messageBroker.Value.Dispatch(this, convertNewResourceDiscoveredToTestRequest(message))

        if scanContext.Template.RunCrawler then
            _messageBroker.Value.Dispatch(this, convertNewResourceDiscoveredToCrawlRequest(message))

    abstract PageProcessedMessageHandler : Object * Envelope<PageProcessedMessage> -> unit
    default this.PageProcessedMessageHandler(sender: Object, envelope: Envelope<PageProcessedMessage>) =
        let message = envelope.Item
        _pageProcessed.Trigger(message)

        // notify other components
        if scanContext.Template.RunWebAppFingerprinter then
            _messageBroker.Value.Dispatch(this, convertPageProcessedToFingerprintRequest(message))

        if scanContext.Template.RunResourceDiscoverer then
            _messageBroker.Value.Dispatch(this, convertPageProcessedToResourceDiscovererRequest(message))

        if scanContext.Template.RunVulnerabilityScanner then
            _messageBroker.Value.Dispatch(this, convertPageProcessedToTestRequest(message))

    member this.GetServiceMetrics() =
        let services =
            _scanWorkflow.GetServices()
            |> Seq.map(fun (_, service) -> service.Metrics)
            |> Seq.toList
        (_serviceMetrics :> ServiceMetrics)::_scanWorkflow.GetMetrics()::services  
        
    member internal this.StartScanIp(ip: String) =
        _logger.ScanEngineUsed()
        _logger.ScanStarted(ip, scanContext)

        this.StartedAt <- DateTime.UtcNow
        this.State <- ScanState.Running
        _processStarted.Trigger(this)
        this.ProcessCompleted.Add(fun _ -> _waitLock.Set())
        
        let container = _container.Value

        // handlers registration        
        _messageBroker <- Some <| container.Resolve<IMessageBroker>()
        _messageBroker.Value.Subscribe<PageProcessedMessage>(this.PageProcessedMessageHandler)
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
            _scanWorkflow.AddExecutedService(vulnerabilityScanner, scanContext.Template)
            vulnerabilityScanner.NoMoreTestRequestsToProcess.Add(serviceCompleted)
            vulnerabilityScanner.ProcessCompleted.Add(serviceCompleted)

        // launch web application fingerprinter
        if scanContext.Template.RunWebAppFingerprinter then
            let webAppFingerprinter = container.Resolve<IWebAppFingerprinter>()
            _scanWorkflow.AddExecutedService(webAppFingerprinter, scanContext.Template)
            webAppFingerprinter.NoMoreWebRequestsToProcess.Add(serviceCompleted)
            webAppFingerprinter.ProcessCompleted.Add(serviceCompleted)

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
            _scanWorkflow.AddExecutedService(resourceDiscoverer, scanContext.Template)
            resourceDiscoverer.NoMoreWebRequestsToProcess.Add(serviceCompleted)
            resourceDiscoverer.ProcessCompleted.Add(serviceCompleted)

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
            crawler.ProcessCompleted.Add(serviceCompleted)
            crawler.NoMoreWebRequestsToProcess.Add(serviceCompleted)                                
            _scanWorkflow.AddExecutedService(crawler, scanContext.Template)

            // start the crawler but not pages will be crawled due to the settings restriction
            crawlerRunned <- crawler.Run(scanContext.StartRequest.HttpRequest)

            if scanContext.Template.RunResourceDiscoverer then
                // send initial page to discover if activated
                _messageBroker.Value.Dispatch(this, new DiscoverRequest(scanContext.StartRequest.HttpRequest))

            if scanContext.Template.RunWebAppFingerprinter then
                // send initial page to fingerprint
                _messageBroker.Value.Dispatch(this, new FingerprintRequest(scanContext.StartRequest.HttpRequest))
        else
            let rec instantiateCrawlers(authentications: AuthenticationType list)  =
                match authentications with
                | authentication::t ->           
                    let crawler = container.Resolve<ICrawler>()
                    crawler.SetAuthentication(authentication)            
                    crawler.ProcessCompleted.Add(serviceCompleted)
                    crawler.NoMoreWebRequestsToProcess.Add(serviceCompleted)       
                         
                    _scanWorkflow.AddExecutedService(crawler, scanContext.Template)

                    let scanRequestHost = scanContext.StartRequest.HttpRequest.Uri.Host
                    if not <| scanContext.Template.CrawlerSettings.AllowedHosts.Contains(scanRequestHost) then
                        scanContext.Template.CrawlerSettings.AllowedHosts.Add(scanRequestHost)
                        
                    let modifiedHost =
                        if scanRequestHost.StartsWith("www.") then scanRequestHost.Substring(4)
                        else "www." + scanRequestHost
                    if not <| scanContext.Template.CrawlerSettings.AllowedHosts.Contains(modifiedHost) then
                        scanContext.Template.CrawlerSettings.AllowedHosts.Add(modifiedHost)
                    
                    // start the crawler
                    crawlerRunned <- crawler.Run(scanContext.StartRequest.HttpRequest)
                    instantiateCrawlers t
                | [] -> ()
                            
            instantiateCrawlers(if scanContext.Authentications |> Seq.isEmpty then [AuthenticationType.NoAuthentication] else scanContext.Authentications |> Seq.toList)

        // the scan initialization can be considered done
        _scanWorkflow.InitializationCompleted()
        
        if not crawlerRunned then
            _scanWorkflow.GetServices()
            |> Seq.map(fun (_, srv) -> srv)
            |> Seq.filter(fun srv -> srv :? ICrawler)
            |> Seq.map(fun srv -> srv :?> ICrawler)
            |> Seq.iter(fun crawler -> crawler.TriggerIdleState())
        
        _logger.AllServicesStarted()
        
    member internal this.Start() =   
        let mutable ip : IPAddress option = None 
        let mutable hostReachable = false
        let uri = scanContext.StartRequest.HttpRequest.Uri
            
        try
            // try to get the IP and verify if the host is reachable
            ip <- Some(Dns.GetHostAddresses(uri.Host) |> Seq.head)
            let webRequestor = _container.Value.Resolve<IWebPageRequestor>()
            let webResponse = webRequestor.RequestInitialWebPage(new WebRequest(uri))
            let noNeededCrawler = scanContext.Template.RunResourceDiscoverer || scanContext.Template.RunWebAppFingerprinter
            hostReachable <- webResponse.PageExists || noNeededCrawler
        with e -> 
            _logger.HostNotReachable(scanContext.StartRequest.HttpRequest.Uri.Host)
            
        // if the host is reachable start the scan around a generic try/catch to avoid to crash everything :\
        match ip with
        | Some ip when hostReachable ->    
            try this.StartScanIp(ip.ToString())
            with e -> 
                _logger.FatalScanError(e)
                _waitLock.Set()
        | _ ->             
            _logger.HostPortNotReachable(uri.Host, uri.Port)
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
        _scanWorkflow.Pause()
        _logger.ScanPaused()

    member this.Stop() =
        _scanWorkflow.Stop()
        _logger.ScanStopped()
        this.State <- ScanState.Stopped

    member this.Resume() =
        _scanWorkflow.Resume()
        _logger.ScanResumed()

    interface IDisposable with
        member this.Dispose() =
            (_scanWorkflow :> IDisposable).Dispose()