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

type TaskManager(statusToMonitor: ServiceStateController, releasePauseStatusMonitor: Boolean, releaseStopStatusMonitor: Boolean, concurrentLimit: Int32) as this =
    let _tasks = new ConcurrentDictionary<Guid, ServiceStateController>()
    let _taskObjects = new List<Task>()
    let _tasksSyncRoot = new Object()
    let _semaphore = new Semaphore(concurrentLimit, concurrentLimit)
    let _stateControlAcquisitionLock = new Object()
    
    let methodCalled(sa: ServiceAction) =
        match sa with
        | ServiceAction.Paused -> lock _stateControlAcquisitionLock (fun () -> this.Pause())
        | ServiceAction.Stopped -> lock _stateControlAcquisitionLock (fun () -> this.Stop())
        | ServiceAction.ReleasePause -> lock _stateControlAcquisitionLock (fun () -> this.ReleasePause())

    let acquireState(dependantStateController: ServiceStateController) =        
        dependantStateController.isPauseRequest <- statusToMonitor.isPauseRequest || statusToMonitor.IsPaused        
        dependantStateController.isStopped <- statusToMonitor.IsStopped

    let checkConsistency(serviceStateController: ServiceStateController) =
        if statusToMonitor.IsPaused then 
            serviceStateController.Pause() |> ignore
        elif statusToMonitor.IsStopped then 
            serviceStateController.Stop() |> ignore
            
    do
        statusToMonitor.MethodCalled.Add(methodCalled)        

    //member val ConcurrentLimit = 5 with get, set
    member val Id = Guid.NewGuid() with get

    member this.Count() =
        _taskObjects.Count
    
    member this.RunTask(taskMethod: ServiceStateController -> unit, removeTaskAfterCompletation: Boolean) =
        let mutable taskObjectResult = Task.CompletedTask
        if not statusToMonitor.IsStopped then
            while not <| _semaphore.WaitOne(TimeSpan.FromSeconds(1.)) && not statusToMonitor.IsStopped do
                // do nothing, it is just a spin loop
                ()

            let serviceStateController = new ServiceStateController()
            lock _stateControlAcquisitionLock (fun () -> 
                acquireState(serviceStateController)  
                _tasks.[serviceStateController.Id] <- serviceStateController
            
                taskObjectResult <- Task.Factory.StartNew(fun () -> 
                    taskMethod(serviceStateController)
                    if removeTaskAfterCompletation then
                        lock _tasksSyncRoot (fun () ->
                            match _tasks.TryRemove(serviceStateController.Id) with
                            | (true, _) ->            
                                // release blocks if necessary
                                serviceStateController.UnlockPause()
                                serviceStateController.ReleaseStopIfNecessary()                                                      
                            | _ -> failwith "Unable to remove task"
                        )
                    _semaphore.Release() |> ignore
                , TaskCreationOptions.LongRunning)
                checkConsistency(serviceStateController) |> ignore
                _taskObjects.Add(taskObjectResult)                    
            )
        
        taskObjectResult
        
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