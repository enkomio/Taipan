namespace ES.Taipan.Infrastructure.Service

open System

type IService = 
    interface
        abstract ServiceId : Guid with get
        abstract Diagnostics : ServiceDiagnostics with get        
        abstract ProcessCompleted : IEvent<IService> with get
        abstract InitializationCompleted : IEvent<IService> with get
        abstract Activate : unit -> unit

        // this method pause the execution of the service. It will block until the service reach a Paused state
        abstract Pause : unit -> unit

        // this method restart a previously paused service. It will not stop
        abstract Resume : unit -> unit

        // this method stop the service. It will stop until the service has reached a Stopped state
        abstract Stop : unit -> unit

        // this method instruct the service to finish its current work and end the execution. It will not stop
        abstract RunToCompletation : unit -> unit        
    end