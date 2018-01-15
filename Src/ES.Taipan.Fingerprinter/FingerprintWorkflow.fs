namespace ES.Taipan.Fingerprinter

open System
open System.Collections.Generic
open Microsoft.FSharp.Reflection
open ES.Taipan.Infrastructure.Service
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Infrastructure.Messaging
open ES.Taipan.Infrastructure.Threading
open ES.Fslog

type FingerprintWorkflow
    (
        settings: WebAppFingerprinterSettings,
        serviceMetrics: FingerprinterMetrics,
        messageBroker: IMessageBroker,
        webServerFingerprinter: IWebServerFingerprinter, 
        webApplicationFingerprintRepository: IWebApplicationFingerprintRepository,   
        webPageRequestor: IWebPageRequestor,
        taskManager: TaskManager,
        numOfParallelRequestWorkers: Int32,
        stateController: ServiceStateController,
        stopRequested: unit -> Boolean,        
        logProvider: ILogProvider
    ) =

    let _supportedLanguages = new List<String>()
    let mutable _webServerFingerprint: WebServerFingerprint option = None

    let _logger =
        log "FingerprintWorkflow"
        |> info "LoadAllProgrammingLanguages" "Unable to fingerprint the server, load all signatures of supported languages (may cause false positive): {0}"
        |> build
    do logProvider.AddLogSourceToLoggers(_logger)

    let identifySupportedServerLanguages(fingerprintRequest: FingerprintRequest) =
        _webServerFingerprint <- Some <| webServerFingerprinter.Fingerprint(fingerprintRequest.Request.Uri)               
        if _webServerFingerprint.Value.Languages |> Seq.isEmpty then                
            // unable to identify the language, by deafult add all supported languages
            FSharpType.GetUnionCases typeof<ProgrammingLanguage>
            |> Seq.map(fun l -> l.Name)
            |> _supportedLanguages.AddRange
            _logger?LoadAllProgrammingLanguages(String.Join(",", _supportedLanguages))
        else
            _supportedLanguages.AddRange(_webServerFingerprint.Value.Languages |> Seq.map(fun l -> l.ToString())) 
                
    member this.Fingerprint(fingerprintRequest: FingerprintRequest, webApplicationFound: List<WebApplicationIdentified>) = 
        identifySupportedServerLanguages(fingerprintRequest)

        let fingerprintWithSignature = 
            new FingerprintWithSignatures(
                settings,
                serviceMetrics,
                messageBroker,
                _webServerFingerprint.Value, 
                webApplicationFingerprintRepository,   
                webPageRequestor,
                taskManager,
                numOfParallelRequestWorkers,
                stateController,
                stopRequested
            )

        let fingerprintWithScripts =
            new FingerprintWithScripts(
                serviceMetrics,
                webPageRequestor,
                messageBroker,
                _webServerFingerprint.Value, 
                webApplicationFingerprintRepository, 
                stateController,
                stopRequested,
                logProvider
            )

        // this action must be done also if only scripts are enabled since it uses the list of loaded applications
        webApplicationFingerprintRepository.LoadSignatures(_supportedLanguages, stopRequested)

        webApplicationFingerprintRepository.LoadScripts(_supportedLanguages, stopRequested)
        fingerprintWithScripts.Fingerprint(fingerprintRequest, webApplicationFound)

        if (not settings.StopAtTheFirstApplicationIdentified || Seq.isEmpty webApplicationFound) && not settings.UseOnlyScripts then            
            fingerprintWithSignature.Fingerprint(fingerprintRequest, webApplicationFound)
        