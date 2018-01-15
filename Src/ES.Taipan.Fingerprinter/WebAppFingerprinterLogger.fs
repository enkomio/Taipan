namespace ES.Taipan.Fingerprinter

open System
open System.Collections.Generic
open System.Text
open System.Net
open ES.Fslog

type WebAppFingerprinterLogger() =
    inherit LogSource("DefaultWebAppFingerprinter")
    
    [<Log(1, Message = "Start discover directory: {0}", Level = LogLevel.Informational)>]
    member this.StartDiscover(fingerprintRequest: FingerprintRequest) = 
        this.WriteLog(1, [|fingerprintRequest.Request.Uri.AbsolutePath|])
        
    [<Log(2, Message = "WebAppFingerprinter Stopped", Level = LogLevel.Informational)>]
    member this.WebAppFingerprinterStopped() =
        this.WriteLog(2, [||])

    [<Log(3, Message = "WebAppFingerprinter Paused", Level = LogLevel.Informational)>]
    member this.WebAppFingerprinterPaused() =
        this.WriteLog(3, [||])

    [<Log(4, Message = "WebAppFingerprinter Resumed", Level = LogLevel.Informational)>]
    member this.WebAppFingerprinterResumed() =
        this.WriteLog(4, [||])

    [<Log(5, Message = "Stop requested", Level = LogLevel.Informational)>]
    member this.StopRequested() =
        this.WriteLog(5, [||])

    [<Log(6, Message = "Stop requested and wait for RunToCompletation message", Level = LogLevel.Verbose)>]
    member this.WaitRunToCompletation() =
        this.WriteLog(6, [||])

    [<Log(7, Message = "RunToCompletation message received", Level = LogLevel.Verbose)>]
    member this.RunToCompletation() =
        this.WriteLog(7, [||])

    [<Log(8, Message = "Go in Idle state", Level = LogLevel.Verbose)>]
    member this.GoIdle() =
        this.WriteLog(8, [||])