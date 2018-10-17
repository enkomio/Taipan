namespace ES.Taipan.Inspector.AddOns.OutdatedApplication

open System
open System.Threading
open System.Collections.Generic
open System.Text.RegularExpressions
open ES.Taipan.Inspector
open ES.Taipan.Infrastructure.Service
open ES.Taipan.Infrastructure.Messaging
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Fingerprinter
open ES.Fslog

type OutdatedApplicationAddOn() as this =
    inherit BaseStatelessAddOn("Outdated Application AddOn", string OutdatedApplicationAddOn.Id, 1)
    let _waitLocker = new ManualResetEventSlim(true)
    let _signaledApplications = new HashSet<String>()
    
    let reportSecurityIssue(uri: Uri, applicationName: String, outdateVersion: Version, currentVersion: Version) =        
        let securityIssue = 
            new SecurityIssue(
                OutdatedApplicationAddOn.Id, 
                Name = "Outdated Application", 
                Uri = uri, 
                EntryPoint = EntryPoint.UriSegment,
                Note = String.Format("{0} v{1}, current version: {2}", applicationName, outdateVersion, currentVersion)
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

    let checkForOutdatedApplication(uri: Uri, identifiedVersionsString: String list, availableVersionsString: String list, applicationName: String) =
        if isApplicationNotYetSignaled(applicationName) then
            let availableVersions = versionFormat availableVersionsString
            let identifiedVersions = versionFormat identifiedVersionsString
          
            if not availableVersions.IsEmpty && not identifiedVersions.IsEmpty then
                let mostRecentAvailableVersion = availableVersions |> List.max
                let mostRecentIDentifiedVersion = identifiedVersions |> List.max
            
                if mostRecentIDentifiedVersion < mostRecentAvailableVersion then
                    reportSecurityIssue(uri, applicationName, mostRecentIDentifiedVersion, mostRecentAvailableVersion)
                    
    let handleNewWebApplicationIdentifiedMessage(sender: Object, newWebApplicationIdentifiedMessage: Envelope<NewWebApplicationIdentifiedMessage>) = 
        _waitLocker.Reset()
        let appName = newWebApplicationIdentifiedMessage.Item.WebApplication.WebApplicationFingerprint.Name
        let getVersionsMessage = new GetAvailableVersionsMessage(Guid.NewGuid(), appName) 
        
        // send the message in order to add tothe message the list of versions (if any)
        this.MessageBroker.Value.Dispatch(this, getVersionsMessage)

        // verify if the versions are old
        let identifiedVersions = 
            newWebApplicationIdentifiedMessage.Item.WebApplication.IdentifiedVersions 
            |> Seq.map(fun kv -> kv.Key.Version) 
            |> Seq.toList

        let uri = newWebApplicationIdentifiedMessage.Item.WebApplication.Request.Request.Uri
        checkForOutdatedApplication(uri, identifiedVersions, getVersionsMessage.Versions, appName)
        _waitLocker.Set()

    static member Id = Guid.Parse("C1B47585-5961-42B8-945E-1367B9CD251C")
    override this.IsBackgroundService with get() = true

    override this.Initialize(context: Context, webRequestor: IWebPageRequestor, messageBroker: IMessageBroker, logProvider: ILogProvider) =
        base.Initialize(context, webRequestor, messageBroker, logProvider) |> ignore
        this.MessageBroker.Value.Subscribe<NewWebApplicationIdentifiedMessage>(handleNewWebApplicationIdentifiedMessage)
        true

    override this.RunToCompletation(stateController: ServiceStateController) =
        _waitLocker.Wait()
        
    default this.Scan(testRequest: TestRequest, stateController: ServiceStateController) =
        // do nothing, It just wait for web application found messages
        ()