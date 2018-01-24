namespace ES.Taipan.Application

open System
open System.Collections.Generic
open System.Threading
open System.Collections.Generic
open ES.Taipan.Infrastructure.Service
open ES.Taipan.Crawler
open ES.Taipan.Inspector
open ES.Taipan.Fingerprinter
open ES.Taipan.Discoverer
open ES.Taipan.Infrastructure.Service
open ES.Fslog

type ScanWorkflowLogger() =
    inherit LogSource("ScanWorkflow")
    
    [<Log(1, Message = "Requested: {0}", Level = LogLevel.Informational)>]
    member this.ActionRequested(action: String) =
        this.WriteLog(1, [|action|])

    [<Log(2, Message = "Service completed: {0}", Level = LogLevel.Informational)>]
    member this.ServiceCompleted(service: IService) =        
        this.WriteLog(2, [|service.GetType().Name|])

    [<Log(3, Message = "Run service to completation: {0}", Level = LogLevel.Informational)>]
    member this.RunServiceToCompletation(service: IService) =        
        this.WriteLog(3, [|service.GetType().Name|])

    [<Log(4, Message = "Service in Idle state: {0}", Level = LogLevel.Verbose)>]
    member this.ServiceIdle(service: IService) =        
        this.WriteLog(4, [|service.GetType().Name|])

    [<Log(5, Message = "All workflow services completed", Level = LogLevel.Informational)>]
    member this.AllServiceCompleted() =        
        this.WriteLog(5, [||])

    [<Log(6, Message = "All services in Idle state = {0}. No pending service for completation = {1}", Level = LogLevel.Verbose)>]
    member this.IdleAndCompletationServices(idle: Boolean, pending: Boolean) =        
        this.WriteLog(6, [|idle; pending|])

    [<Log(7, Message = "Service {0} initialized", Level = LogLevel.Informational)>]
    member this.ServiceInitialized(service: IService) =        
        this.WriteLog(7, [|service.GetType().FullName|])
        
type ScanWorkflowMetrics() =
    inherit ServiceMetrics("Scan Workflow")

    member this.LastCompletedProcess(service: IService) =
        this.AddMetric("Completed process " + service.GetType().Name, String.Empty)

    member this.LastRunToCompletationProcess(service: IService) =
        this.AddMetric("Last run to completation process " + service.GetType().Name, String.Empty)

type ScanWorkflow(logProvider: ILogProvider) =  
    let _logger = new ScanWorkflowLogger()  
    let _serviceMetrics = new ScanWorkflowMetrics()
    let _statusQueue = new Queue<String>()
    let _serviceStatusChangeSyncRoot = new Object()
    let _producerServices = new List<IService>()
    let _completedServices = new Dictionary<IService, Boolean>()
    let _pendingServiceForCompletation = new List<Guid>()
    let _activatedServices = new List<Int32 * IService>()    
    let _initializedServices = ref 0
    let _currentServiceLevel = ref 0
    let mutable _scanCompleted = false  
    let mutable _scanInitializationCompleted = false 
    do logProvider.AddLogSourceToLoggers(_logger)

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

    member this.GetServices() =
        _activatedServices

    member this.AddExecutedService(service: IService, scanProfile: TemplateProfile) =
        match service with
        | Crawler 
        | WebAppFingerprinter
        | ResourceDiscoverer -> _producerServices.Add(service)
        | _ -> ()        

        service.InitializationCompleted.Add(fun srv -> 
            _serviceMetrics.AddMetric(String.Format("Service {0} initialized", srv.GetType().FullName), "true")
            _logger.ServiceInitialized(srv)
            Interlocked.Increment(_initializedServices) |> ignore
        )

        _serviceMetrics.AddMetric(String.Format("Service {0} added", service.GetType().FullName), "true")
        _activatedServices.Add(getServiceLevel(service), service)
        service.Activate()

    member this.GetMetrics() =
        _serviceMetrics :> ServiceMetrics

    member this.InitializationCompleted() =
        _scanInitializationCompleted <- true
                    
    // this is the most important function. it is in charge for the process workflow
    member this.ServiceCompleted(service: IService, inIdleState: Boolean) =
        verifyAllServiceCompletedTheInitialization()
        lock _serviceStatusChangeSyncRoot (fun () ->
            _serviceMetrics.LastCompletedProcess(service)
            _pendingServiceForCompletation.Remove(service.ServiceId) |> ignore
            
            if inIdleState then
                // the service just went to an idle state, it can be resumed 
                // wether new work is requested
                _logger.ServiceIdle(service)                
            else
                // the service really completed, not more work for it
                _completedServices.[service] <- true
                _logger.ServiceCompleted(service)

            let allProducerServicesInIdleState = _producerServices |> Seq.forall(fun srv -> srv.Diagnostics.IsIdle)
            let noPendingServiceForCompletation = _pendingServiceForCompletation |> Seq.isEmpty
            _logger.IdleAndCompletationServices(allProducerServicesInIdleState, noPendingServiceForCompletation)

            if allProducerServicesInIdleState && noPendingServiceForCompletation then        
                // need to call run to completation for all idle services, but following the right priority level
                let mutable savedCurrentServiceLevel = !_currentServiceLevel
                incr _currentServiceLevel

                // the components with a low level need to run to completation            
                let mutable nextServiceIdentified = false
                while not nextServiceIdentified && savedCurrentServiceLevel <= 3 do
                    _activatedServices 
                    |> Seq.toList
                    |> List.sortBy(fun (level, _) -> level)
                    |> List.filter(fun (serviceLevel, _) -> serviceLevel = savedCurrentServiceLevel)
                    |> List.iter(fun (_, srv) -> 
                        _pendingServiceForCompletation.Add(srv.ServiceId)   
                        _logger.RunServiceToCompletation(srv)  
                        _serviceMetrics.LastRunToCompletationProcess(srv)                                   
                        _completedServices.[srv] <- false
                        nextServiceIdentified <- true
                        srv.RunToCompletation()
                    )

                    if not nextServiceIdentified then
                        savedCurrentServiceLevel <- !_currentServiceLevel
                        incr _currentServiceLevel

                // if no service needs to run to completation then the scan completed
                if allServicesRunnedForCompletation() then 
                    _logger.AllServiceCompleted()
                    _scanCompleted <- true
        )
                    
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