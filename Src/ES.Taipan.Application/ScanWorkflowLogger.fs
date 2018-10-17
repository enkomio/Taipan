namespace ES.Taipan.Application

open System
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

    [<Log(7, Message = "Service {0} initialized", Level = LogLevel.Informational)>]
    member this.ServiceInitialized(service: IService) =        
        this.WriteLog(7, [|service.GetType().FullName|])