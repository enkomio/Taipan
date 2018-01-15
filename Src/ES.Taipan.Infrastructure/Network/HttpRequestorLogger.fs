namespace ES.Taipan.Infrastructure.Network

open System
open System.Linq
open ES.Fslog

type HttpRequestorLogger() =
    inherit LogSource("HttpRequestor  logger")
    
    [<Log(1, Message = "Unable to authenticate for url: {0}. Login pattern: {1}", Level = LogLevel.Warning)>]
    member this.UnableToAuthenticate(url: String, webFormAuth: WebFormAuthenticationDescriptor) =
        this.WriteLog(1, [|url; webFormAuth.LoginMatchingPattern|])

    [<Log(2, Message = "Error on request: {0}. Message: {1}", Level = LogLevel.Verbose)>]
    member this.RequestError(url: String, message: String) =
        this.WriteLog(2, [|url; message|])

    [<Log(3, Message = "{0}", Level = LogLevel.Informational)>]
    member this.JavascriptLog(message: String) =
        this.WriteLog(3, [|message|])