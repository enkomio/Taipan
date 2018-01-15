namespace ES.Taipan.Infrastructure.Threading

open System
open System.Threading

type RequestGate(numOfInstances: Int32) = 
    let _semaphore = new Semaphore(numOfInstances, numOfInstances)
    
    member this.AsyncAcquire(?millisecondsTimeout: Int32) =
        async {
            let! isAcquired = Async.AwaitWaitHandle(_semaphore, ?millisecondsTimeout=millisecondsTimeout)
            if isAcquired then
                return {
                     new IDisposable with
                        member this.Dispose() =
                            _semaphore.Release() |> ignore
                }
            else
                if millisecondsTimeout.IsSome then
                    return! raise <| new ApplicationException("Unable to acquire the lock after a period of " + millisecondsTimeout.Value.ToString() + " seconds" )
                else
                    return! raise <| new ApplicationException("Unable to acquire the lock" )
        }
