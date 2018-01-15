namespace ES.Taipan.Fingerprinter

open System
open ES.Taipan.Infrastructure.Service

type FingerprinterMetrics() =
    inherit ServiceMetrics("Fingerprinter")
    
    member this.CurrentState(status: String) =
        this.AddMetric("Current status", status)     
        
    member this.RequestPerSeconds(numReq: Int32) =
        this.AddMetric("Applications processed per minute", numReq.ToString())

    member this.LastTestedApplication(appName: String) =
        this.AddMetric("Last tested web application", appName)

    member this.LastExecutedScript(script: String) =
        this.AddMetric("Last executed script", script)

    member this.LastFingerprintedDirectory(directory: String) =
        this.AddMetric("Last fingerprinted directory", directory)

    member this.WaitForTasksFingerprintCompletation(counter: Int32) =
        this.AddMetric("Wait for tasks completation. Seconds passed", counter.ToString())

    member this.InitializationCompleted() =
        this.AddMetric("Initialization completed", "true")