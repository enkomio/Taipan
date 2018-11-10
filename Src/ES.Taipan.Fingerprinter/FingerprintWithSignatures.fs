namespace ES.Taipan.Fingerprinter

open System
open System.Linq
open System.Collections.Generic
open System.Collections.Concurrent
open System.Threading.Tasks
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Infrastructure.Threading
open ES.Taipan.Infrastructure.Service
open ES.Taipan.Infrastructure.Messaging
open ES.Fslog
open MoonSharp.Interpreter.CoreLib

type FingerprintWithSignatures
    (
        settings: WebAppFingerprinterSettings,
        messageBroker: IMessageBroker,
        webServerFingerprint: WebServerFingerprint,
        webApplicationFingerprintRepository: IWebApplicationFingerprintRepository,   
        webPageRequestor: IWebPageRequestor,
        taskManager: TaskManager,
        numOfParallelRequestWorkers: Int32,
        stateController: ServiceStateController,
        stopRequested: unit -> Boolean
    ) as this =

    let _serviceMetrics = new ServiceMetrics("FingerprintWithSignatures")
    let serviceMetricHandler(sender: Object, msg: Envelope<RequestMetricsMessage>) =
        msg.Item.AddResult(this, _serviceMetrics)

    do messageBroker.Subscribe<RequestMetricsMessage>(serviceMetricHandler)
    
    let getWebApplicationsToAnalyze(webApplicationFound: List<WebApplicationIdentified>, webApplicationAnalyzed: List<String>) =
        let webApplicationFoundNames = webApplicationFound |> Seq.map(fun webApp -> webApp.WebApplicationFingerprint.Name)
        webApplicationFingerprintRepository.GetAllWebApplications()
        |> Seq.filter (fun webApp -> 
            // analyze web applications that doesn't have dependencies or which the dependecies were all already found
            webApp.DependantWebApplications.TrueForAll(fun dependantWebApp -> webApplicationFoundNames |> Seq.contains(dependantWebApp.ApplicationName)) &&
            not <| webApplicationAnalyzed.Contains(webApp.Name)
        )
        |> Seq.toList

    let fingeprinterWorker
        (
            serviceStateController: ServiceStateController, 
            webAppFingerprints: ConcurrentQueue<WebApplicationFingerprint>, 
            webAppsIdentified: ConcurrentBag<WebApplicationIdentified>,
            fingerprintRequest: FingerprintRequest
        ) =     

        let webApplicationFingerprint = ref (new WebApplicationFingerprint())
        let partialIdentifiedWebApps = new List<WebApplicationVersionFingerprint * FingerprintResult>()

        let iterate() =
            not <| stopRequested() &&
            not stateController.IsStopped &&
            if settings.StopAtTheFirstApplicationIdentified then webAppsIdentified.IsEmpty && Seq.isEmpty partialIdentifiedWebApps 
            else true

        while webAppFingerprints.TryDequeue(webApplicationFingerprint) do
            if iterate() then
                serviceStateController.WaitIfPauseRequested()
                partialIdentifiedWebApps.Clear()
                _serviceMetrics.AddMetric("Last tested application", (!webApplicationFingerprint).Name)

                // identify the current web application                
                (!webApplicationFingerprint).Fingeprint(webPageRequestor, fingerprintRequest, serviceStateController)
                |> Seq.takeWhile(fun(webAppVersion, fingerprintResult) -> 
                    serviceStateController.WaitIfPauseRequested()
                    _serviceMetrics.AddMetric("Last tested web application version", webAppVersion.Version)
                    if settings.RaiseAnEventForEachVersionIdentified then
                        let webAppIdentified = new WebApplicationIdentified(!webApplicationFingerprint, fingerprintRequest)
                        webAppIdentified.IdentifiedVersions.Add(webAppVersion, fingerprintResult)
                        webAppIdentified.Server <- Some webServerFingerprint 
                        webAppsIdentified.Add(webAppIdentified)

                        // raise the event  
                        messageBroker.Dispatch(this, new NewWebApplicationIdentifiedMessage(webAppIdentified))
                    else
                        partialIdentifiedWebApps.Add(webAppVersion, fingerprintResult)
                    iterate()
                ) 
                |> Seq.toList 
                |> ignore

                // if necessary raise a cumulative event for each identified versions of the current web app
                if not settings.RaiseAnEventForEachVersionIdentified && partialIdentifiedWebApps.Any() then 
                    let webAppIdentified = new WebApplicationIdentified(!webApplicationFingerprint, fingerprintRequest)
                    webAppIdentified.Server <- Some webServerFingerprint
                    webAppsIdentified.Add(webAppIdentified)

                    partialIdentifiedWebApps
                    |> Seq.iter(webAppIdentified.IdentifiedVersions.Add)

                    // finally raise the cumulative event  
                    messageBroker.Dispatch(this, new NewWebApplicationIdentifiedMessage(webAppIdentified))
        
        serviceStateController.ReleaseStopIfNecessary()
        serviceStateController.UnlockPause()

    let runFingerprint(webApplicationToAnalyze: WebApplicationFingerprint list, webApplicationFound: List<WebApplicationIdentified>, fingerprintRequest: FingerprintRequest) =
        let webApplicationsQueue = new ConcurrentQueue<WebApplicationFingerprint>(webApplicationToAnalyze)
        let identifiedWebApplications = new ConcurrentBag<WebApplicationIdentified>(webApplicationFound)

        // run in parallels all the instantiated workers
        let tasks = new List<Task>()
        let effectiveNumOfWorkers = min numOfParallelRequestWorkers webApplicationToAnalyze.Length
        for _ in Enumerable.Range(0, effectiveNumOfWorkers) do
            taskManager.RunTask(fun serviceStateController -> 
                fingeprinterWorker(serviceStateController, webApplicationsQueue, identifiedWebApplications, fingerprintRequest)
            , true) |> tasks.Add

        // wait for all task to complete
        Task.WaitAll(tasks |> Seq.toArray)

        // add back the new web applications
        webApplicationFound.Clear()
        webApplicationFound.AddRange(identifiedWebApplications)
    
    member this.Fingerprint(fingerprintRequest: FingerprintRequest, webApplicationFound: List<WebApplicationIdentified>) =
        // list used to take count of which applications was found and which still need to be identified        
        let webApplicationAnalyzed = new List<String>()
        
        // start fingerprint main loop process
        let mutable iterate = true
        while iterate do
            let webApplicationToAnalyze = getWebApplicationsToAnalyze(webApplicationFound, webApplicationAnalyzed)
            iterate <- not webApplicationToAnalyze.IsEmpty && not stateController.IsStopped
            webApplicationToAnalyze |> List.iter(fun wa -> webApplicationAnalyzed.Add(wa.Name))
            
            if iterate then
                runFingerprint(webApplicationToAnalyze, webApplicationFound, fingerprintRequest)

        messageBroker.Unsubscribe(serviceMetricHandler)

    member this.Dispose() =
        messageBroker.Unsubscribe(this)

    interface IDisposable with
        member this.Dispose() =
            this.Dispose()