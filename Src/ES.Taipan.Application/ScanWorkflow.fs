namespace ES.Taipan.Application

open System
open System.Collections.Generic
open System.Threading
open ES.Taipan.Infrastructure.Service
open ES.Taipan.Crawler
open ES.Taipan.Inspector
open ES.Taipan.Fingerprinter
open ES.Taipan.Discoverer
open ES.Fslog
open ES.Taipan.Infrastructure.Messaging

type ScanWorkflow(messageBroker: IMessageBroker, runAssessmentPhaseCallback: unit -> unit, logProvider: ILogProvider) as this =  
    let _logger = new ScanWorkflowLogger()  
    let _serviceMetrics = new ServiceMetrics("Scan Workflow")
    let _statusQueue = new Queue<String>()
    let _serviceStatusChangeSyncRoot = new Object()
    let _producerServices = new List<IService>()
    let _completedServices = new Dictionary<IService, Boolean>()
    let _pendingServiceForCompletation = new List<Guid>()
    let _activatedServices = new List<Int32 * IService>()    
    let _initializedServices = ref 0
    let _currentRunToCompletationServiceLevel = ref Int32.MaxValue
    let _maxServiceLevelPriority = 4
    let mutable _scanCompleted = false  
    let mutable _scanInitializationCompleted = false

    do 
        logProvider.AddLogSourceToLoggers(_logger)
        messageBroker.Subscribe<RequestMetricsMessage>(fun (sender, msg) -> msg.Item.AddResult(this, _serviceMetrics))

    let (|Crawler|VulnerabilityScanner|WebAppFingerprinter|ResourceDiscoverer|Unknown|) (v: IService) =
        let typeOfService = v.GetType()
        if typeof<IVulnerabilityScanner>.IsAssignableFrom(typeOfService) then VulnerabilityScanner
        elif typeof<ICrawler>.IsAssignableFrom(typeOfService) then Crawler
        elif typeof<IWebAppFingerprinter>.IsAssignableFrom(typeOfService) then WebAppFingerprinter
        elif typeof<IResourceDiscoverer>.IsAssignableFrom(typeOfService) then ResourceDiscoverer
        else Unknown
                
    let getServiceLevel = function
        | Crawler -> 0
        | ResourceDiscoverer -> 1
        | WebAppFingerprinter -> 2
        | VulnerabilityScanner -> 3
        | Unknown -> failwith "Unkwnon service type"

    let verifyAllServiceCompletedTheInitialization() =
        while !_initializedServices <> _activatedServices.Count || not _scanInitializationCompleted do
            Thread.Sleep(1000)    
            
    let allServicesRunnedForCompletation() =
        _completedServices.Count = _activatedServices.Count && (_completedServices.Values |> Seq.forall (id))

    let haveToCallRunToCompletation() =
        let allProducerServicesInIdleState = _producerServices |> Seq.forall(fun srv -> srv.Diagnostics.IsIdle)
        let noPendingServiceForCompletation = _pendingServiceForCompletation |> Seq.isEmpty
        allProducerServicesInIdleState && noPendingServiceForCompletation
        
    let manageStatuschange() =
        verifyAllServiceCompletedTheInitialization()
        lock _statusQueue (fun () ->            
            while _statusQueue.Count > 0 do
                match _statusQueue.Dequeue() with
                | "STOP" ->
                    _activatedServices 
                    |> Seq.sortBy(fun (level, _) -> level)
                    |> Seq.map(snd)
                    |> Seq.iter(fun service -> service.Stop())

                | "PAUSE" ->
                    _activatedServices 
                    |> Seq.sortBy(fun (level, _) -> level)
                    |> Seq.map(snd)
                    |> Seq.iter(fun service -> service.Pause())

                | "RESUME" ->
                    _activatedServices 
                    |> Seq.sortBy(fun (level, _) -> level)
                    |> Seq.map(snd)
                    |> Seq.iter(fun service -> service.Resume())
                | _ -> ()
        )

    let runToCompletation(srv: IService) =
        _logger.RunServiceToCompletation(srv)  
        _serviceMetrics.AddMetric("Last run to completation service", srv.GetType().Name)
        _pendingServiceForCompletation.Add(srv.ServiceId)   
        _completedServices.[srv] <- false

        _currentRunToCompletationServiceLevel := getServiceLevel(srv) + 1

        // check if it is time to run the assessment phase. This is done if all service of level
        // strictly minor then 2 are completed
        if getServiceLevel(srv) >= 2 then
            runAssessmentPhaseCallback()

        srv.RunToCompletation()

    let tryIdentifyServiceAndRunToCompletation(inIdleState: Boolean) =
        if haveToCallRunToCompletation() then
            let mutable nextServiceIdentified = false
            let mutable tmpCurrentRunToCompletationServiceLevel = !_currentRunToCompletationServiceLevel
            let mutable loopCompleted = false

            while not loopCompleted do
                _activatedServices 
                |> Seq.toList
                |> List.sortBy(fun (level, _) -> level)
                |> List.filter(fun (serviceLevel, _) -> serviceLevel = tmpCurrentRunToCompletationServiceLevel)
                |> List.iter(fun (_, srv) -> 
                    nextServiceIdentified <- true

                    if not inIdleState then
                        // the next identified service must be in idle state,
                        // otherwise I'll wait for its idle state
                        if srv.Diagnostics.IsIdle 
                        then runToCompletation(srv)
                    else
                        runToCompletation(srv)
                )

                loopCompleted <- nextServiceIdentified || tmpCurrentRunToCompletationServiceLevel > _maxServiceLevelPriority
                tmpCurrentRunToCompletationServiceLevel <- tmpCurrentRunToCompletationServiceLevel + 1

    // This is the most important function. it is in charge for the process workflow.
    // All services need to go through an idle state and then run to completation.
    // All services have a priority level, the service with high priority (low number) need
    // to be finish first.
    member this.ServiceCompleted(service: IService, inIdleState: Boolean) =
        verifyAllServiceCompletedTheInitialization()
        lock _serviceStatusChangeSyncRoot (fun () ->            
            _pendingServiceForCompletation.Remove(service.ServiceId) |> ignore
            
            if inIdleState then
                // the service just went to an idle state, it can be resumed 
                // later, when new work is requested
                _logger.ServiceIdle(service) 

                tryIdentifyServiceAndRunToCompletation(inIdleState)
            else
                // the service really completed, not more work for it
                _completedServices.[service] <- true
                _logger.ServiceCompleted(service)
                _serviceMetrics.AddMetric("Last completed service", service.GetType().Name)
                                
                tryIdentifyServiceAndRunToCompletation(inIdleState)
            
                if allServicesRunnedForCompletation() then 
                    _logger.AllServiceCompleted()
                    _scanCompleted <- true
        )

    member this.GetServices() =
        _activatedServices

    member this.AddExecutedService(service: IService) =
        match service with
        | Crawler 
        | WebAppFingerprinter
        | ResourceDiscoverer -> _producerServices.Add(service)
        | _ -> ()        
        
        // set the service level to the minimum possible value among the activated services
        if !_currentRunToCompletationServiceLevel > getServiceLevel(service) then
            _currentRunToCompletationServiceLevel := getServiceLevel(service)

        service.InitializationCompleted.Add(fun srv -> 
            _logger.ServiceInitialized(srv)
            Interlocked.Increment(_initializedServices) |> ignore
        )

        _activatedServices.Add(getServiceLevel(service), service)
        service.Activate()
        
    member this.InitializationCompleted() =
        _scanInitializationCompleted <- true
                    
    member this.AllServicesCompleted() =
        _scanCompleted
        
    member this.Pause() =  
        _statusQueue.Enqueue("PAUSE")    
        _logger.ActionRequested("PAUSE")
        manageStatuschange()  
            
    member this.Stop() =
        _statusQueue.Enqueue("STOP")  
        _logger.ActionRequested("STOP")
        manageStatuschange()

    member this.Resume() =
        _statusQueue.Enqueue("RESUME")  
        _logger.ActionRequested("RESUME")
        manageStatuschange()

    interface IDisposable with
        member this.Dispose() =
            // dispose all addons
            for (_, service) in _activatedServices do
                if service :? IDisposable then
                    let disposable = service :?> IDisposable
                    disposable.Dispose()