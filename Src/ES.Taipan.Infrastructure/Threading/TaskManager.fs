namespace ES.Taipan.Infrastructure.Threading

open System
open System.Collections.Generic
open System.Collections.Concurrent
open System.Threading.Tasks
open System.Threading
open ES.Taipan.Infrastructure.Service

(*
This class is used in order to manage multiple Tasks in order to be Pause and/or Stopped 
in a coherent way. The task execyted through the manager, could be paused or stopped. 
*)

type TaskManager(statusToMonitor: ServiceStateController, releasePauseStatusMonitor: Boolean, releaseStopStatusMonitor: Boolean) as this =
    let _tasks = new ConcurrentDictionary<Guid, ServiceStateController>()
    let _taskObjects = new List<Task>()
    let _tasksSyncRoot = new Object()
    let _lockObj = new Object()
    let _stateControlAcquisitionLock = new Object()
    
    let methodCalled(sa: ServiceAction) =
        match sa with
        | ServiceAction.Paused -> lock _stateControlAcquisitionLock (fun () -> this.Pause())
        | ServiceAction.Stopped -> lock _stateControlAcquisitionLock (fun () -> this.Stop())
        | ServiceAction.ReleasePause -> lock _stateControlAcquisitionLock (fun () -> this.ReleasePause())

    let acquireState(dependantStateController: ServiceStateController) =        
        dependantStateController.isPauseRequest <- statusToMonitor.isPauseRequest || statusToMonitor.IsPaused        
        dependantStateController.isStopped <- statusToMonitor.IsStopped
        
    do
        statusToMonitor.MethodCalled.Add(methodCalled)
        if statusToMonitor.IsPaused then methodCalled(ServiceAction.Paused)
        elif statusToMonitor.IsStopped then methodCalled(ServiceAction.Stopped)

    member val ConcurrentLimit = 5 with get, set
    member val Id = Guid.NewGuid() with get

    member this.Count() =
        _taskObjects.Count
    
    member this.RunTask(taskMethod: ServiceStateController -> unit, removeTaskAfterCompletation: Boolean) =
        while(_tasks.Count > this.ConcurrentLimit) do
            lock _lockObj (fun () -> Monitor.Wait(_lockObj) |> ignore)
        
        let serviceStateController = new ServiceStateController()
        lock _stateControlAcquisitionLock (fun () -> 
            acquireState(serviceStateController)  
            _tasks.[serviceStateController.Id] <- serviceStateController
            
            let taskObject = Task.Factory.StartNew(fun () -> 
                taskMethod(serviceStateController)
                if removeTaskAfterCompletation then
                    lock _tasksSyncRoot (fun () ->
                        match _tasks.TryRemove(serviceStateController.Id) with
                        | (true, _) ->            
                            // release blocks if necessary
                            serviceStateController.UnlockPause()
                            serviceStateController.ReleaseStopIfNecessary()
                            lock _lockObj (fun () -> Monitor.Pulse(_lockObj))                      
                        | _ -> failwith "Unable to remove task"
                    )
            , TaskCreationOptions.LongRunning)
            _taskObjects.Add(taskObject)
            taskObject
        )
        
    member val StateController = statusToMonitor with get

    member this.AreAllTaskCompleted() =
        _taskObjects |> Seq.forall(fun task -> task.IsCompleted)

    member this.Pause() =
        let mutable allPaused = false
        while not allPaused do
            let tasksToWaitFor = new List<ServiceStateController>()
            lock _tasksSyncRoot (fun () ->
               tasksToWaitFor.AddRange(_tasks.Values)
            )

            let tmpTasks = new List<Task>()
            tasksToWaitFor
            |> Seq.toList
            |> List.filter(fun s -> not s.IsPaused)
            |> List.map(fun s -> Task.Factory.StartNew(fun () -> s.Pause() |> ignore))
            |> List.iter tmpTasks.Add
            allPaused <- Task.WaitAll(tmpTasks |> Seq.toArray, 10000)

        if releasePauseStatusMonitor then 
            // this allow to continue from the point where the Pause method was called on the statusMonitor
            Task.Factory.StartNew(fun () -> statusToMonitor.WaitIfPauseRequested()) |> ignore

    member this.Stop() =
        let mutable allStopped = false
        while not allStopped do
            let tasksToWaitFor = new List<ServiceStateController>()
            lock _tasksSyncRoot (fun () ->
               tasksToWaitFor.AddRange(_tasks.Values)
            )

            let tmpTasks = new List<Task>()
            tasksToWaitFor
            |> Seq.toList
            |> List.filter(fun s -> not s.IsStopped)
            |> List.map(fun s -> Task.Factory.StartNew(fun () -> s.Stop() |> ignore))
            |> List.iter tmpTasks.Add
            allStopped <- Task.WaitAll(tmpTasks |> Seq.toArray, 10000)
                        
        if releaseStopStatusMonitor then 
            // this allow to continue from the point where the Stop method was called
            Task.Factory.StartNew(fun () -> statusToMonitor.ReleaseStopIfNecessary()) |> ignore

    member this.ReleasePause() =
        _tasks.Keys
        |> Seq.toList
        |> List.iter(fun id -> _tasks.[id].ReleasePause() |> ignore)