namespace ES.Taipan.Infrastructure.Service

open System

type IService = 
    interface
        abstract ServiceId : Guid with get
        abstract Diagnostics : ServiceDiagnostics with get
        abstract Metrics : ServiceMetrics with get
        abstract ProcessCompleted : IEvent<IService> with get
        abstract InitializationCompleted : IEvent<IService> with get
        abstract Activate : unit -> unit
        abstract Pause : unit -> unit
        abstract Resume : unit -> unit
        abstract Stop : unit -> unit
        abstract RunToCompletation : unit -> unit        
    end