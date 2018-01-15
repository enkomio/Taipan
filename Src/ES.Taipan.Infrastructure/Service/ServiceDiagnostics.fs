namespace ES.Taipan.Infrastructure.Service

open System

type ServiceDiagnostics() =
    let mutable _idle = true

    member this.IsIdle 
        with get() = _idle

    member this.GoIdle() =
        _idle <- true

    member this.Activate() =
        _idle <- false

