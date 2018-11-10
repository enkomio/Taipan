namespace ES.Taipan.Fingerprinter

open System
open System.Collections.Generic
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Infrastructure.Service
open ES.Taipan.Infrastructure.Messaging
open ES.Fslog

type FingerprintWithScripts
    (
        webPageRequestor: IWebPageRequestor,
        messageBroker: IMessageBroker,
        webServerFingerprint: WebServerFingerprint,
        webApplicationFingerprintRepository: IWebApplicationFingerprintRepository, 
        stateController: ServiceStateController,
        stopRequested: unit -> Boolean,
        logProvider: ILogProvider
    ) as this =
    
    let _serviceMetrics = new ServiceMetrics("FingerprintWithScripts")
    let _logger =
        log "FingerprintWithScripts"
        |> info "WebApplicationVersionFoundViaScript" "Web application '{0}' version '{1}' found at: {2} (via: {3})"
        |> build

    let requestMetricsMessageHandler(sender: Object, msg: Envelope<RequestMetricsMessage>) =
        msg.Item.AddResult(this, _serviceMetrics)

    let isScriptOkToRun(luaSignature: LuaScriptSignature, webApplicationFound: List<WebApplicationIdentified>) =
        // avoid to analyze applications that were already found or that was already analyzed by the script
        webApplicationFound 
        |> Seq.exists(fun webApp -> webApp.WebApplicationFingerprint.Name.Equals(luaSignature.ApplicationName, StringComparison.OrdinalIgnoreCase))
        |> not

    let getApplicationAndVersionFromScriptResult(luaSignRes: LuaSignatureVerificationResult) =
        match webApplicationFingerprintRepository.GetAllWebApplications()|> Seq.tryFind(fun webApp -> webApp.Name.Equals(luaSignRes.AppName, StringComparison.OrdinalIgnoreCase)) with
        | Some webAppFing ->
            match webAppFing.Versions |> Seq.tryFind(fun v -> v.Version.Equals(luaSignRes.AppVersion, StringComparison.OrdinalIgnoreCase)) with
            | Some webAppVerFing ->
                (webAppFing, webAppVerFing)
            | None -> 
                // need to create a version from scratch
                let webAppVerFing = new WebApplicationVersionFingerprint(Version = luaSignRes.AppVersion)
                webAppVerFing.Signatures.Add(downcast luaSignRes.Signature.Value)
                (webAppFing, webAppVerFing)

        | None ->
            // need to create an application and version from scratch
            let webAppFing = new WebApplicationFingerprint(Name = luaSignRes.AppName, AcceptanceRate = 1.0)                                
            webAppFing.ScriptSignatures.Add(downcast luaSignRes.Signature.Value)
                                    
            let webAppVerFing = new WebApplicationVersionFingerprint(Version = luaSignRes.AppVersion)
            webAppVerFing.Signatures.Add(downcast luaSignRes.Signature.Value)
            (webAppFing, webAppVerFing)

    do 
        logProvider.AddLogSourceToLoggers(_logger)
        messageBroker.Subscribe<RequestMetricsMessage>(requestMetricsMessageHandler)
        
    member this.Fingerprint(fingerprintRequest: FingerprintRequest, webApplicationFound: List<WebApplicationIdentified>) =
        let cacheableWebPageRequestor = new CacheableWebPageRequestor(webPageRequestor) 
                                                                
        for customScript in webApplicationFingerprintRepository.GetCustomScriptCheckers() do
            if not(stopRequested()) && not stateController.IsStopped then
                match customScript with
                | :? LuaScriptSignature as luaSignature when isScriptOkToRun(luaSignature, webApplicationFound) ->
                    _serviceMetrics.AddMetric("Last executed script", luaSignature.FilePath)                    
                    let luaSignRes = luaSignature.Verify(fingerprintRequest.Request.Uri.AbsoluteUri, cacheableWebPageRequestor) :?> LuaSignatureVerificationResult

                    // if the app was found signal it with a message
                    if luaSignRes.Found then
                        let (webAppFing, webAppVerFing) = getApplicationAndVersionFromScriptResult(luaSignRes)

                        // fill the web app identified object
                        let webAppIdentified = new WebApplicationIdentified(webAppFing, fingerprintRequest)
                        let fingerprintResult = new FingerprintResult(Rate = 1.0)
                        fingerprintResult.MatchedSignatures.Add(luaSignRes)
                        webAppIdentified.IdentifiedVersions.Add(webAppVerFing, fingerprintResult)
                        webAppIdentified.Server <- Some webServerFingerprint
                    
                        webApplicationFound.Add(webAppIdentified)
                        _logger?WebApplicationVersionFoundViaScript(luaSignRes.AppName, luaSignRes.AppVersion, luaSignRes.Signature.Value.ToString(), fingerprintRequest.Request.Uri.AbsoluteUri)

                        // dispatch the event
                        messageBroker.Dispatch(this, new NewWebApplicationIdentifiedMessage(webAppIdentified))
                | _ -> ()

    member this.Dispose() =
        messageBroker.Unsubscribe(this)

    interface IDisposable with
        member this.Dispose() =
            this.Dispose()