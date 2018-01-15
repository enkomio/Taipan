namespace ES.Taipan.Infrastructure.Service

open System
open System.Threading

type ServiceStateController() = 
    let _syncRoot = new Object()
    let _syncRootForPause = new Object()
    let _stopResetEvent = new ManualResetEventSlim()

    let _methodCalled = new Event<ServiceAction>()
    let _statusChanged = new Event<ServiceStateController>()
    
    member val internal isPauseRequest = false with get, set
    member val internal isStopped = false with get, set
    member val Id = Guid.NewGuid() with get

    abstract StatusChanged: IEvent<ServiceStateController>
    default this.StatusChanged = _statusChanged.Publish
    
    abstract MethodCalled: IEvent<ServiceAction>
    default this.MethodCalled = _methodCalled.Publish
    
    abstract NotBlockingPause: unit -> Boolean
    default this.NotBlockingPause() =
        if this.IsRunning then
            this.isPauseRequest <- true
            _methodCalled.Trigger(ServiceAction.Paused)
            _statusChanged.Trigger(this)
            true
        else
            false

    abstract Pause : unit -> Boolean
    default this.Pause() =
        if this.IsRunning then
            this.isPauseRequest <- true
            _methodCalled.Trigger(ServiceAction.Paused)
            
            // wait until the method WaitIfPauseRequested is called. This ensure that the thread calling 
            // that method is blocked (in pause). After the methos call I can exit from the pause state, and be sure that
            // the service is effectively in Pause
            lock _syncRootForPause (fun () -> Monitor.Wait(_syncRootForPause) |> ignore)
            _statusChanged.Trigger(this)
            true
        else
            false

    member this.UnlockPause() =
        lock _syncRoot (fun () -> Monitor.Pulse(_syncRoot))
        
    abstract ReleasePause : unit -> Boolean
    default this.ReleasePause() =
        if this.IsPaused then
            this.isPauseRequest <- false
            _methodCalled.Trigger(ServiceAction.ReleasePause)
                        
            // this release paused threads in order to handle stop state
            this.UnlockPause()

            _statusChanged.Trigger(this)
            true
        else
            false

    abstract ReleaseStopIfNecessary : unit -> unit
    default this.ReleaseStopIfNecessary() =
        _stopResetEvent.Set()
        if this.isStopped then          
            _statusChanged.Trigger(this)
            
    abstract WaitIfPauseRequested: unit -> unit
    default this.WaitIfPauseRequested() =
        if this.isPauseRequest then
            lock _syncRootForPause (fun () -> Monitor.Pulse(_syncRootForPause))
            lock _syncRoot (fun () -> Monitor.Wait(_syncRoot) |> ignore)
            _statusChanged.Trigger(this)

    abstract NotBlockingStop: unit -> Boolean
    default this.NotBlockingStop() =
        if this.IsRunning then
            this.isStopped <- true
            _methodCalled.Trigger(ServiceAction.Stopped)

            _statusChanged.Trigger(this)
            true
        elif this.IsPaused then
            this.isStopped <- true

            // this release paused threads in order to handle stop state
            lock _syncRoot (fun () -> Monitor.Pulse(_syncRoot))

            _methodCalled.Trigger(ServiceAction.Stopped)
            _statusChanged.Trigger(this)
            true
        else
            false

    abstract Stop : unit -> Boolean
    default this.Stop() =
        if this.IsRunning then                        
            this.isStopped <- true

            _methodCalled.Trigger(ServiceAction.Stopped)

            // wait until the method ReleaseStopIfNecessary is called. This ensure that the thread calling 
            // that method is blocked. After the methos call I can exit from the stop state, and be sure that
            // the service is effectively Stopped
            _stopResetEvent.Wait()
            _statusChanged.Trigger(this)
            true
        elif this.IsPaused then
            this.isStopped <- true

            // this release paused threads in order to handle stop state
            lock _syncRoot (fun () -> Monitor.Pulse(_syncRoot))

            _methodCalled.Trigger(ServiceAction.Stopped)
                
            _stopResetEvent.Wait()
            _statusChanged.Trigger(this)
            true
        else
            false

    abstract IsRunning: Boolean
    default this.IsRunning
        with get() = not this.isPauseRequest && not this.isStopped

    abstract IsPaused: Boolean
    default this.IsPaused
        with get() = this.isPauseRequest && not this.isStopped

    abstract IsStopped: Boolean
    default this.IsStopped
        with get() = this.isStopped
        