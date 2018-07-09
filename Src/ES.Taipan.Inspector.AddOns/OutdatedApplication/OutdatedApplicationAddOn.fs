namespace ES.Taipan.Inspector.AddOns.OutdatedApplication

open System
open System.Threading
open System.Collections.Generic
open System.Collections.Concurrent
open System.Text.RegularExpressions
open ES.Taipan.Inspector
open ES.Taipan.Inspector.AddOns
open ES.Taipan.Infrastructure.Service
open ES.Taipan.Infrastructure.Messaging
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Fingerprinter
open ES.Fslog

type private ApplicationVersionCheck = {
    IdentifiedVersions : String list
    Uri : Uri
}

type OutdatedApplicationAddOn() as this =
    inherit BaseStatelessAddOn("Outdated Application AddOn", "C1B47585-5961-42B8-945E-1367B9CD251C", 1)       
    let _availableVersionsMessages = new BlockingCollection<AvailableApplicationVersionMessage>()
    let _waitLocker = new ManualResetEventSlim()
    let _pendingChecks = new ConcurrentDictionary<Guid, ApplicationVersionCheck>()
    let _signaledApplications = new HashSet<String>()
    
    let reportSecurityIssue(uri: Uri, applicationName: String, outdateVersion: Version, currentVersion: Version) =        
        let securityIssue = 
            new SecurityIssue(
                this.Id, 
                Name = "Outdated Application", 
                Uri = uri, 
                EntryPoint = EntryPoint.UriSegment
            )
        securityIssue.Details.Properties.Add("ApplicationName", applicationName)
        securityIssue.Details.Properties.Add("OutdatedVersion", outdateVersion.ToString())
        securityIssue.Details.Properties.Add("CurrentVersion", currentVersion.ToString())
        this.Context.Value.AddSecurityIssue(securityIssue)

    let cleanVersion(version: String) =
        Regex.Replace(version, "[^0-9.]", String.Empty)

    let isStandardVersionFormat(version: String) =
        let v = ref(new Version())
        Version.TryParse(version, v)

    let versionFormat(versions: String list) =
        versions
        |> List.map cleanVersion
        |> List.filter isStandardVersionFormat
        |> List.map Version.Parse

    let isApplicationNotYetSignaled(appName: String) =
        lock _signaledApplications (fun () ->
            _signaledApplications.Add(appName)
        )

    let checkForOutdatedApplication(check: ApplicationVersionCheck, availableVersionsString: String list, applicationName: String) =
        if isApplicationNotYetSignaled(applicationName) then
            let availableVersions = versionFormat availableVersionsString
            let identifiedVersions = versionFormat check.IdentifiedVersions
          
            if not availableVersions.IsEmpty && not identifiedVersions.IsEmpty then
                let mostRecentAvailableVersion = availableVersions |> List.max
                let mostRecentIDentifiedVersion = identifiedVersions |> List.max
            
                if mostRecentIDentifiedVersion < mostRecentAvailableVersion then
                    reportSecurityIssue(check.Uri, applicationName, mostRecentIDentifiedVersion, mostRecentAvailableVersion)

    let messageHandlingLoop() =
        async {
            try
                for availableVersionsMessage in _availableVersionsMessages.GetConsumingEnumerable() do
                    if _pendingChecks.ContainsKey(availableVersionsMessage.RequestId) then
                        checkForOutdatedApplication(
                            _pendingChecks.[availableVersionsMessage.RequestId], 
                            availableVersionsMessage.Versions, 
                            availableVersionsMessage.Application
                        )

                        // clean-up
                        let tmp = ref {IdentifiedVersions = []; Uri = new Uri("http://www.example.com")}
                        _pendingChecks.TryRemove(availableVersionsMessage.RequestId, tmp) |> ignore
                        if _pendingChecks.IsEmpty then
                            _waitLocker.Set()
            with
            | :? OperationCanceledException -> ()

            // unlock the final wait in the RunToCompletation metohd
            _waitLocker.Set()
            
        } |> Async.Start
    
    do messageHandlingLoop()
        
    let handleAvailableApplicationVersionMessage(sender: Object, availableApplicationVersionMessage: Envelope<AvailableApplicationVersionMessage>) =
        _availableVersionsMessages.Add(availableApplicationVersionMessage.Item)

    let handleNewWebApplicationIdentifiedMessage(sender: Object, newWebApplicationIdentifiedMessage: Envelope<NewWebApplicationIdentifiedMessage>) =        
        let appName = newWebApplicationIdentifiedMessage.Item.WebApplication.WebApplicationFingerprint.Name
        let getVersionsMessage = new GetAvailableVersionsMessage(Guid.NewGuid(), appName)  

        let check = {
            Uri = newWebApplicationIdentifiedMessage.Item.WebApplication.Request.Request.Uri
            IdentifiedVersions = newWebApplicationIdentifiedMessage.Item.WebApplication.IdentifiedVersions |> Seq.map(fun kv -> kv.Key.Version) |> Seq.toList
        }
        _pendingChecks.[getVersionsMessage.Id] <- check
        
        this.MessageBroker.Value.Dispatch(this, getVersionsMessage)

    override this.Initialize(context: Context, webRequestor: IWebPageRequestor, messageBroker: IMessageBroker, logProvider: ILogProvider) =
        base.Initialize(context, webRequestor, messageBroker, logProvider) |> ignore
        this.MessageBroker.Value.Subscribe<NewWebApplicationIdentifiedMessage>(handleNewWebApplicationIdentifiedMessage)
        this.MessageBroker.Value.Subscribe<AvailableApplicationVersionMessage>(handleAvailableApplicationVersionMessage)
        true

    override this.RunToCompletation(stateController: ServiceStateController) =        
        // complete only when all requests are evaded
        while not(_pendingChecks.IsEmpty) do
            _waitLocker.Wait(5000) |> ignore
            _waitLocker.Reset()

        _availableVersionsMessages.CompleteAdding()
        _waitLocker.Wait()
        
    default this.Scan(testRequest: TestRequest, stateController: ServiceStateController) =
        ()