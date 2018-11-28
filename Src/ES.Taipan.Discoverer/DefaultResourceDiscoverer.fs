namespace ES.Taipan.Discoverer

open System
open System.Text.RegularExpressions
open System.Net
open System.IO
open System.Linq
open System.Threading
open System.Threading.Tasks
open System.Collections.Concurrent
open System.Collections.Generic
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Infrastructure.Messaging
open ES.Taipan.Infrastructure.Service
open ES.Taipan.Infrastructure.Threading
open ES.Fslog

type DefaultResourceDiscoverer(settings: ResourceDiscovererSettings, webRequestor: IWebPageRequestor, messageBroker: IMessageBroker, resourceRepository: IResourceRepository, logProvider: ILogProvider) as this =
    let mutable _requestsToProcess = new BlockingCollection<DiscoverRequest>()
    let mutable _processCompletedInvoked = false
    let mutable _stopRequested = false    
    let _numOfServicedRequests = ref 0
    let _numOfParallelRequestWorkers = 20
    let _cachedRequests = new List<DiscoverRequest>()
    let _discoveredDirectories = new HashSet<String>()
    let _forbiddenDirectories = new List<String>()
    let _stateController = new ServiceStateController()
    let _taskManager = new TaskManager(_stateController, true, false, _numOfParallelRequestWorkers)
    let _processCompleted = new Event<IService>()
    let _initializationCompleted = new Event<IService>()
    let _noMoreWebRequestsToProcess = new Event<IResourceDiscoverer>()
    let _logger = new ResourceDiscovererLogger()
    let _serviceDiagnostics = new ServiceDiagnostics()    
    let _serviceMetrics = new ServiceMetrics("Discoverer")
    let _statusMonitor = new Object()
    let _runToCompletationCalledLock = new ManualResetEventSlim()

    let _dictionaries =
        settings.Dictionaries
        |> Seq.map(Guid.Parse)
        |> Seq.toList
        |> resourceRepository.GetAllSelectedDictionaries

    let handleControlMessage(sender: Object, message: Envelope<String>) =
        match message.Item.ToUpper() with
        | "STOP" -> this.Stop()
        | "PAUSE" -> this.Pause()
        | "RESUME" -> this.Resume()
        | _ -> ()

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

    let processDiscoverRequest(discoverRequest: DiscoverRequest) =
        if not _stateController.IsStopped && not _stopRequested && not _requestsToProcess.IsAddingCompleted then            
            this.Discover(discoverRequest) |> ignore

    let triggerIdleState() =
        _serviceMetrics.AddMetric("Status", "Idle")
        _serviceDiagnostics.GoIdle()
        _logger.GoIdle()
        _noMoreWebRequestsToProcess.Trigger(this)

    let checkResourceDiscovererState() =
        if _requestsToProcess |> Seq.isEmpty then
            triggerIdleState()    

    let discovererLoop() =
        // main process loop
        let completed = ref false
        _initializationCompleted.Trigger(this)
        while(not !completed) do
            for discoverRequest in _requestsToProcess.GetConsumingEnumerable() do
                if not _stateController.IsStopped && not _stopRequested then
                    lock _statusMonitor (fun () ->
                        _serviceDiagnostics.Activate()
                        _serviceMetrics.AddMetric("Status", "Running")
                        processDiscoverRequest(discoverRequest)
                        checkResourceDiscovererState()
                    )

            // check for cached requests due to recursive option
            completed := true
            if _cachedRequests.Any() && not _stopRequested then
                completed := false
                _requestsToProcess <- new BlockingCollection<DiscoverRequest>()
                _cachedRequests |> Seq.iter(_requestsToProcess.Add)
                _cachedRequests.Clear()

                // set the complete adding because it was alredy called, and when the discovery process end must exit
                _requestsToProcess.CompleteAdding() 
                    
        if _stopRequested then
            // wait until the run to completation is called
            checkResourceDiscovererState()
            _stateController.ReleaseStopIfNecessary()
            _logger.WaitRunToCompletation()
            _runToCompletationCalledLock.Wait()  
            
        // no more discover requests to process
        completeProcess()  

    let handleDiscoverRequestMessage(sender: Object, discoverRequest: Envelope<DiscoverRequest>) =        
        if _requestsToProcess.IsAddingCompleted then
            _cachedRequests.Add(discoverRequest.Item)
        else
            _requestsToProcess.Add(discoverRequest.Item)

    let isDirectoryNew(request: DiscoverRequest) =
        let pathDirectory = request.Request.Uri.AbsolutePath.Trim([|'/'|])
        _discoveredDirectories.Add(pathDirectory)

    let isRecurionsSatisfied() =
        if _discoveredDirectories.Count > 1 then
            settings.BeRecursive
        else
            true
                        
    let isDepthLevelAllowed(discoverRequest: DiscoverRequest) =
        let uri = discoverRequest.Request.Uri
        let directories = uri.AbsolutePath.Split([|"/"|], StringSplitOptions.RemoveEmptyEntries)        
        directories.Length <= settings.RecursiveDepth

    let matchForbiddenDirectory(path: String) =
        _forbiddenDirectories
        |> Seq.exists(fun pattern -> Regex.IsMatch(path, pattern, RegexOptions.IgnoreCase))

    let isNotAForbiddenDirectory(discoverRequest: DiscoverRequest) =
        let uri = discoverRequest.Request.Uri
        if uri.AbsolutePath.EndsWith("/") && String.IsNullOrWhiteSpace(uri.Query) && not <| uri.AbsolutePath.Equals("/") then
            let chunks = uri.AbsolutePath.Split([|'/'|], StringSplitOptions.RemoveEmptyEntries)
            not <| matchForbiddenDirectory(chunks.Last())
        elif String.IsNullOrWhiteSpace(Path.GetExtension(uri.AbsolutePath)) then
            // no extension, could be a directory
            let page = HttpUtility.getPage(uri)
            not <| matchForbiddenDirectory(page)
        else
            // is it a page
            true

    let isRequestAllowed(discoverRequest: DiscoverRequest) =
        isDepthLevelAllowed(discoverRequest) && 
        isNotAForbiddenDirectory(discoverRequest) && 
        isDirectoryNew(discoverRequest) && 
        isRecurionsSatisfied()

    let addExtensionsIfNeeded(resources: ConcurrentQueue<Resource>) =
        let newResources = new List<Resource>()
        resources
        |> Seq.toList
        |> List.filter(fun resource -> not <| resource.Path.EndsWith("/"))
        |> List.iter(fun resource ->                        
            let mutable noExtensionResource = resource

            let extension = Path.GetExtension(resource.Path)
            if not <| String.IsNullOrWhiteSpace(extension) then
                let newPath = resource.Path.Replace(extension, String.Empty)
                noExtensionResource <- new Resource(newPath, Group = resource.Group)

                // managed blank extension option        
                if settings.UseBlankExtension && not(String.IsNullOrWhiteSpace(noExtensionResource.Path)) then
                    newResources.Add(noExtensionResource) |> ignore
        )
                    
        // finally add all the resources
        newResources
        |> Seq.filter(resources.Contains >> not)
        |> Seq.iter (resources.Enqueue)

    let isStatusCodeOkToIterate =        
        let cached = new HashSet<String>()
        fun (identifiedResource: ResourceDiscovered) ->
            // is useless to discover directories with specific status code, it will return always the same result
            if identifiedResource.Response.ResponseUri.Value.AbsolutePath.EndsWith("/") then    
                let statusCode = int identifiedResource.Response.StatusCode
                if statusCode >= 400 && statusCode < 500 then false
                else cached.Add(identifiedResource.Request.Uri.AbsolutePath)
            else true

    let resourceIdentified(identifiedResource: ResourceDiscovered) =
        _logger.ResourceFound(identifiedResource)
        messageBroker.Dispatch(this, new NewResourceDiscoveredMessage(identifiedResource))
        
        // if recursive option is enabled, analyze the directory just discovered
        if settings.BeRecursive && isStatusCodeOkToIterate(identifiedResource) then
            let discoverRequest = new DiscoverRequest(new HttpRequest(identifiedResource.Response.ResponseUri.Value))
            messageBroker.Dispatch(this, discoverRequest)   

    let filterResource(webResponse: WebResponse, resource: Resource) =
        let isResponseCodeAllowed = settings.BlackListedStatusCodes.Contains(int32 webResponse.HttpResponse.StatusCode) |> not
        let areAllWordsAllowed = settings.BlackListedWords |> Seq.exists (webResponse.HttpResponse.Html.Contains) |> not        
        webResponse.PageExists && isResponseCodeAllowed && areAllWordsAllowed
                
    let requestWorker(serviceStateController: ServiceStateController, discoverRequest: DiscoverRequest, resources: ConcurrentQueue<Resource>, total: Int32, counter: Int32 ref) =
        seq {
            //for resource in resources do
            let resource = ref (new Resource(String.Empty))
            while resources.TryDequeue(resource) do
                _serviceMetrics.AddMetric("Last requested resource", (!resource).Path)

                if not serviceStateController.IsStopped && not _stopRequested then   
                    serviceStateController.WaitIfPauseRequested()

                    // request the resource and verify if it is found
                    let resourceUri = new Uri(discoverRequest.Request.Uri, (!resource).Path)
                    let webRequest = new WebRequest(resourceUri)                       
                    let webResponse = webRequestor.RequestWebPage(webRequest)
                    
                    Interlocked.Increment(_numOfServicedRequests) |> ignore
                    Interlocked.Increment(counter) |> ignore
                    _logger.ScanProgress(discoverRequest.Request.Uri.AbsolutePath, total, !counter)

                    if filterResource(webResponse, !resource) then
                        let resourceDiscovered = new ResourceDiscovered(!resource, webResponse.HttpResponse.ResponseUri.Value, webRequest.HttpRequest, webResponse.HttpResponse)
                        resourceIdentified(resourceDiscovered)
                        yield resourceDiscovered

            serviceStateController.ReleaseStopIfNecessary()
            serviceStateController.UnlockPause()
        }                    

    do 
        logProvider.AddLogSourceToLoggers(_logger)

        webRequestor.HttpRequestor.Metrics <- _serviceMetrics.GetSubMetrics("DiscovererHttpRequestor_" + webRequestor.HttpRequestor.Id.ToString("N"))

        // set the page not found identifier to the heuristic base in order to have a great accurancy in the the resource discovery
        webRequestor.SetPageNotFoundIdentifier(new HeuristicPageNotFoundIdentifier(webRequestor.HttpRequestor))
        webRequestor.HttpRequestor.Settings.AllowAutoRedirect <- true
        webRequestor.HttpRequestor.Settings.UseJavascriptEngineForRequest <- false

        // disable authentication since it is not needed
        webRequestor.HttpRequestor.Settings.Authentication.Enabled <- false
        
        // message subscription
        messageBroker.Subscribe<String>(handleControlMessage)
        messageBroker.Subscribe<DiscoverRequest>(handleDiscoverRequestMessage)
        messageBroker.Subscribe<RequestMetricsMessage>(fun (sender, msg) -> msg.Item.AddResult(this, _serviceMetrics))

        // add forbidden directories loaded via repository
        settings.ForbiddenDirectories 
        |> Seq.append(resourceRepository.GetForbiddenDirectories())
        |> _forbiddenDirectories.AddRange

    static member ResourceDiscovererId = Guid.Parse("8DD36C46-8FEB-455F-A1BA-C14363339318")
    member val ServiceId = DefaultResourceDiscoverer.ResourceDiscovererId with get
    member this.NoMoreWebRequestsToProcess = _noMoreWebRequestsToProcess.Publish
    member this.ProcessCompleted = _processCompleted.Publish
    member this.InitializationCompleted = _initializationCompleted.Publish

    member this.Pause() = 
        // if there aren't requests that must be processed then not blocking call of Pause must be executed because the
        // main loop is waiting for requests and until this requirement old the WaitInInPauseState method
        // isn't called, so a deadlock may occour.
        let action =
            if Monitor.TryEnter(_statusMonitor) && _serviceDiagnostics.IsIdle then _stateController.NotBlockingPause
            else _stateController.Pause

        if action() then
            _logger.DiscovererPaused()
            _serviceMetrics.AddMetric("Status", "Paused")
                
    member this.Resume() = 
        if _stateController.ReleasePause() then
            _logger.DiscovererResumed()
            _serviceMetrics.AddMetric("Status", "Running")
            checkResourceDiscovererState()

    member this.Stop() =        
        _logger.StopRequested() 
        _stopRequested <- true             
        _requestsToProcess.CompleteAdding()
               
        if _stateController.Stop() then
            _logger.DiscovererStopped()
            _serviceMetrics.AddMetric("Status", "Stopped")

    member this.RunToCompletation() =
        _serviceMetrics.AddMetric("Status", "Run to completation")
        _logger.RunToCompletation()
        _requestsToProcess.CompleteAdding()  

        // unlock if locked by stop request
        _runToCompletationCalledLock.Set()

    member this.Activate() =
        // run the main loop
        Task.Factory.StartNew(fun _ -> discovererLoop(), TaskCreationOptions.LongRunning) |> ignore
     
    member this.Discover(inputDiscoverRequest: DiscoverRequest) : ResourceDiscovered list =
        let identifiedResources = new ConcurrentBag<ResourceDiscovered>()    
        let extensionMarker = "%EXT%"    

        // create the effective discover request, this is necessary if the request ask to discover a file
        let pathDirectory = HttpUtility.getAbsolutePathDirectory(inputDiscoverRequest.Request.Uri) + "/"
        let discoverRequest = new DiscoverRequest(new HttpRequest(new Uri(inputDiscoverRequest.Request.Uri, pathDirectory)))
        
        if isRequestAllowed(discoverRequest) then
            _logger.DiscoverRequest(discoverRequest)
            
            // this hash set is used in order to disallow to ask for duplicate resource from different dictionaries
            let requestedResources = new HashSet<String>()
            for dictionary in _dictionaries do
                _serviceMetrics.AddMetric("Current used dictionary", dictionary.Name)

                if not _stateController.IsStopped && not _stopRequested then
                    let counter = ref 0                
                    let resourcesQueue = new ConcurrentQueue<Resource>()

                    // create the full list of resource to identify
                    for resource in dictionary.Resources do
                        // manage extension
                        if resource.Path.Contains(extensionMarker) then
                            settings.Extensions
                            |> Seq.toList
                            |> List.iter(fun extension ->
                                let extension = if extension.StartsWith(".") then extension.Substring(1) else extension
                                let newPath = resource.Path.Replace(extensionMarker, extension)
                
                                // avoid to add the same extension twice
                                if not <| newPath.Equals(resource.Path, StringComparison.Ordinal) && not(String.IsNullOrWhiteSpace(resource.Path)) then
                                    let extensionResource = new Resource(newPath, Group = resource.Group)                                    
                                    if requestedResources.Add(extensionResource.Path.Trim([|'/'|])) then
                                        resourcesQueue.Enqueue(extensionResource)
                            )
                        else
                            let trimmedPath = resource.Path.Trim([|'/'|])
                            if not(String.IsNullOrWhiteSpace(trimmedPath)) && requestedResources.Add(trimmedPath) then
                                resourcesQueue.Enqueue(resource)

                    addExtensionsIfNeeded(resourcesQueue)

                    _logger.ResetCounter()
                    _logger.UseDictionary(dictionary.Name, resourcesQueue.Count)
                                                        
                    // run in parallels all the instantiated workers
                    let tasks = new List<Task>()
                    let numOfResources = resourcesQueue.Count
                    for _ in Enumerable.Range(0, _numOfParallelRequestWorkers) do
                        if not _stopRequested then
                            _taskManager.RunTask(fun serviceStateController -> 
                                requestWorker(serviceStateController,discoverRequest, resourcesQueue, numOfResources, counter)
                                |> Seq.toList
                                |> List.iter identifiedResources.Add
                            , true) |> tasks.Add

                    // wait for all task completed
                    let counter = ref 0
                    while not(Task.WaitAll(tasks |> Seq.toArray, 1000)) do
                        incr counter

                    // update list
                    identifiedResources 
                    |> Seq.toList
                    |> List.map(fun r -> r.Resource.Path)
                    |> List.map requestedResources.Add
                    |> ignore

        identifiedResources |> Seq.toList

    member val Diagnostics = _serviceDiagnostics with get

    interface IDisposable with
        member this.Dispose() =
            // dispose web requestor, this is importance, since if we use the Javascript
            // Engine the dispose will tear down the browser
            match webRequestor with
            | :? IDisposable as disposable -> disposable.Dispose()
            | _ -> ()
                    
    interface IResourceDiscoverer with       

        member this.ServiceId
            with get() = this.ServiceId

         member this.Diagnostics
            with get() = this.Diagnostics
            
        member this.Discover(discoverRequest: DiscoverRequest) =
            this.Discover(discoverRequest)

        member this.Pause() = 
            this.Pause()

        member this.Resume() = 
            this.Resume()
        
        member this.Stop() =    
            this.Stop()

        member this.RunToCompletation() =
            this.RunToCompletation()

        member this.Activate() =
            this.Activate()

        member this.ProcessCompleted
            with get() = this.ProcessCompleted

        member this.InitializationCompleted
            with get() = this.InitializationCompleted

        member this.NoMoreWebRequestsToProcess
            with get() = this.NoMoreWebRequestsToProcess