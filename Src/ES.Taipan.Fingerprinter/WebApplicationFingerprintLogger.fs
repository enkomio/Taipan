namespace ES.Taipan.Fingerprinter

open System
open System.Text
open System.Net
open ES.Fslog

type WebApplicationFingerprintLogger() =
    inherit LogSource("WebApplicationFingerprintLogger")
    
    [<Log(1, Message = "Web app '{0}' seems to exists [{1}%], files: {2}", Level = LogLevel.Verbose)>]
    member this.WebApplicationSeemsToExists(webAppName: String, fingerprintResult: FingerprintResult) =
        let signatures = 
            fingerprintResult.MatchedSignatures             
            |> Seq.map(fun s -> s.Signature)
            |> Seq.filter(Option.isSome)
            |> Seq.map(fun s -> s.Value.ToString())
            |> Seq.toList
            |> fun s -> String.Join(",", s)
        let rate = fingerprintResult.Rate * 100.
        this.WriteLog(1, [|webAppName; rate; signatures|])

    [<Log(2, Message = "Web application '{0}'{1} version '{2}' [Score {3}%] found at: {4}", Level = LogLevel.Informational)>]
    member this.WebApplicationVersionFound(webAppName: String, dependsOn: String, webAppVersionName: String, rate: Double, url: String) =
        this.WriteLog(2, [|webAppName; dependsOn; webAppVersionName; (rate * 100.0); url|])

    [<Log(3, Message = "Test for '{0}' version '{1}' at: {2}", Level = LogLevel.Verbose)>]
    member this.TestForWebApplicationVersion(webAppName: String, webAppVersionName: String, url: String) =
        this.WriteLog(3, [|webAppName; webAppVersionName; url|])
        
    [<Log(4, Message = "Web application '{0}' not found. Rate: {1}", Level = LogLevel.Verbose)>]
    member this.WebApplicationNotFound(webAppName: String, rate: float) =
        this.WriteLog(4, [|webAppName; rate|])

    [<Log(5, Message = "Web application version '{0}' [Score {1}%] found at: {2} (via custom checker)", Level = LogLevel.Informational)>]
    member this.WebApplicationVersionFoundThroughCustomChecker(webAppVersionName: String, rate: Double, url: String) =
        this.WriteLog(5, [|webAppVersionName; (rate * 100.0); url|])

    [<Log(6, Message = "Test for web application '{0}' at: {1}", Level = LogLevel.Verbose)>]
    member this.TestForWebApplication(webAppVersionName: String, url: String) =
        this.WriteLog(6, [|webAppVersionName; url|])