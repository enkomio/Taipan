namespace ES.Taipan.Application

open System
open System.Text
open System.Diagnostics
open System.Reflection
open ES.Fslog

type internal ScanLogger() =
    inherit LogSource("Scan")
                
    [<Log(1, Message = "All services stopped", Level = LogLevel.Informational)>]
    member this.ScanStopped() =
        this.WriteLog(1, [||])

    [<Log(2, Message = "All services paused", Level = LogLevel.Informational)>]
    member this.ScanPaused() =
        this.WriteLog(2, [||])

    [<Log(3, Message = "All services resumed", Level = LogLevel.Informational)>]
    member this.ScanResumed() =
        this.WriteLog(3, [||])

    [<Log(4, Message = "Start scan of: {0} [{1}]", Level = LogLevel.Informational)>]
    member this.ScanStarted(ip: String, scanContext: ScanContext) =
        this.WriteLog(4, [|scanContext.StartRequest.HttpRequest.Uri; ip|])

    [<Log(5, Message = "Scan engine version: {0}", Level = LogLevel.Informational)>]
    member this.ScanEngineUsed() =
        let scanEngineVersion = FileVersionInfo.GetVersionInfo(Assembly.GetCallingAssembly().Location).ProductVersion
        this.WriteLog(5, [|scanEngineVersion|])

    [<Log(6, Message = "Completed scan of: {0} in {1} seconds", Level = LogLevel.Informational)>]
    member this.ScanCompleted(scanContext: ScanContext, seconds: Int32) =
        this.WriteLog(6, [|scanContext.StartRequest.HttpRequest.Uri; seconds|])

    [<Log(7, Message = "Using template: {0} [{1}]", Level = LogLevel.Informational)>]
    member this.UsedTemplate(template: TemplateProfile) =
        this.WriteLog(7, [|template.Name; template.Id|])
                
    [<Log(8, Message = "{0}", Level = LogLevel.Critical)>]
    member this.FatalScanError(e: Exception) =
        let exceptionError = new StringBuilder()
        let populateField(ex: Exception) =
            ignore(
                exceptionError.AppendLine(),
                exceptionError.AppendLine("Exception Message=" + ex.Message),
                exceptionError.AppendLine("Exception Source=" + ex.Source),
                exceptionError.AppendLine("*** Exception Stack trace follow:"),
                exceptionError.AppendLine(),
                exceptionError.AppendLine(ex.StackTrace),
                exceptionError.AppendLine()
            )
        populateField(e)

        if e.InnerException <> null then
            ignore(
                exceptionError.AppendLine(),
                exceptionError.AppendLine("*** Inner Exception Details"),
                exceptionError.AppendLine()
            )
            populateField(e.InnerException)

        this.WriteLog(8, [|exceptionError.ToString()|])

    [<Log(9, Message = "All services started", Level = LogLevel.Informational)>]
    member this.AllServicesStarted() =        
        this.WriteLog(9, Array.empty)

    [<Log(10, Message = "Unable to connect to host '{0}' port {1}. {2}", Level = LogLevel.Error)>]
    member this.HostPortNotReachable(host: String, port: Int32, errorMessage: String) =
        this.WriteLog(10, [|host; port; errorMessage|])

    [<Log(11, Message = "Start assessment step for web site: {0}", Level = LogLevel.Informational)>]
    member this.StartAssessment(uri: String) =
        this.WriteLog(11, [|uri|])