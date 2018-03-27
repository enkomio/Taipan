namespace ES.Taipan.Infrastructure.Network

open System
open System.Linq
open ES.Fslog

type HttpRequestorLogger() =
    inherit LogSource("HttpRequestor  logger")
    
    [<Log(1, Message = "SessionState is null, it is not possible to authenticate via web form in this configuration", Level = LogLevel.Error)>]
    member this.SessionStateNullOnWebAuth() =
        this.WriteLog(1, [||])

    [<Log(2, Message = "Error on request: {0}. Message: {1}", Level = LogLevel.Verbose)>]
    member this.RequestError(url: String, message: String) =
        this.WriteLog(2, [|url; message|])

    [<Log(3, Message = "{0}", Level = LogLevel.Informational)>]
    member this.JavascriptLog(message: String) =
        this.WriteLog(3, [|message|])

    [<Log(4, Message = "The authentication process has failed", Level = LogLevel.Error)>]
    member this.AuthenticationFailed() =
        this.WriteLog(4, [||])