namespace ES.Taipan.Discoverer

open System
open System.Collections.Concurrent
open ES.Fslog

type internal ResourceDiscovererLogger() =
    inherit LogSource("DefaultResourceDiscoverer")

    let _syncLock = new Object()
    let _progress = new ConcurrentDictionary<String, Int32>()

    member this.ResetCounter() =
        _progress.Clear()
    
    [<Log(1, Message = "Start discover of: {0}", Level = LogLevel.Informational)>]
    member this.DiscoverRequest(discoverRequest: DiscoverRequest) = 
        this.WriteLog(1, [|discoverRequest.Request.Uri.ToString()|])
        
    [<Log(2, Message = "Resource Discoverer Stopped", Level = LogLevel.Informational)>]
    member this.DiscovererStopped() =
        this.WriteLog(2, [||])

    [<Log(3, Message = "Resource Discoverer Paused", Level = LogLevel.Informational)>]
    member this.DiscovererPaused() =
        this.WriteLog(3, [||])

    [<Log(4, Message = "Resource Discoverer Resumed", Level = LogLevel.Informational)>]
    member this.DiscovererResumed() =
        this.WriteLog(4, [||])

    [<Log(5, Message = "Identified resource at: {0} => {1} {2} #Bytes: {3}", Level = LogLevel.Informational)>]
    member this.ResourceFound(resourceDiscovered: ResourceDiscovered) = 
        this.WriteLog(5, [|resourceDiscovered.Request.Uri.ToString(); int resourceDiscovered.Response.StatusCode; resourceDiscovered.Response.ReasonPhrase; resourceDiscovered.Response.Html.Length|])

    [<Log(6, Message = "Use dictionary '{0}', len = {1}", Level = LogLevel.Informational)>]
    member this.UseDictionary(dictionaryName: String, count: Int32) = 
        this.WriteLog(6, [|dictionaryName; count|])

    [<Log(7, Message = "Discovery of {0} at {1}% [{2}/{3}]", Level = LogLevel.Informational)>]
    member this.ScanProgress(directory: String, totalReq: Int32, curReq: Int32) = 
        lock _syncLock (fun _ ->
            let percentage = (float curReq / float totalReq) * 100. |> int32
            if not <| _progress.ContainsKey(directory) then
                _progress.[directory] <- percentage

            let storedPercentage = ref 0
            if _progress.TryGetValue(directory, storedPercentage) && !storedPercentage < percentage && percentage % 5 = 0 then
                _progress.[directory] <- percentage
                this.WriteLog(7, [|directory; percentage; curReq; totalReq|])
        )   

    [<Log(8, Message = "Stop requested", Level = LogLevel.Verbose)>]
    member this.StopRequested() =
        this.WriteLog(8, [||])

    [<Log(9, Message = "Stop requested and wait for RunToCompletation message", Level = LogLevel.Verbose)>]
    member this.WaitRunToCompletation() =
        this.WriteLog(9, [||])

    [<Log(10, Message = "RunToCompletation message received", Level = LogLevel.Verbose)>]
    member this.RunToCompletation() =
        this.WriteLog(10, [||])

    [<Log(11, Message = "Go in Idle state", Level = LogLevel.Verbose)>]
    member this.GoIdle() =
        this.WriteLog(11, [||])