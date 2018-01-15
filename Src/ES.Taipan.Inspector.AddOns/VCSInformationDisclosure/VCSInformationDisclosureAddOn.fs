namespace ES.Taipan.Inspector.AddOns.InformationLeakage

open System
open System.Text
open System.IO
open System.Threading
open System.Collections.Generic
open System.Collections.Concurrent
open System.Text.RegularExpressions
open ES.Taipan.Inspector
open ES.Taipan.Inspector.AddOns
open ES.Taipan.Infrastructure.Service
open ES.Taipan.Infrastructure.Messaging
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Infrastructure.Text
open ES.Taipan.Fingerprinter
open ES.Taipan.Crawler
open ES.Fslog

type VCSInformationDisclosureAddOn() as this =
    inherit BaseStatelessAddOn("Version Control System Information Disclosure AddOn", "46DAC261-3B13-4123-9AAF-22DFAF9B5E19", 1)       
    let _analyzedPages = new HashSet<String>()

    let _log =
        log "GitDownloader"
        |> info "DownloadedGitResource" "Git file '{0}': {1}"
        |> build
                    
    let createSecurityIssue(url: String, vulName: String) =
        new SecurityIssue(
            this.Id, 
            Name = vulName, 
            Uri = new Uri(url), 
            EntryPoint = EntryPoint.UriSegment
        )

    let getUniquePropertyName(propertyName: String, dict: Dictionary<String, String>) =
        let mutable effectivePropName = propertyName
        let index = ref 1
        while dict.ContainsKey(effectivePropName) do
            effectivePropName <- propertyName + (!index).ToString()
            incr index
        effectivePropName

    let addProperty(propName: String, propValue: String, securityIssue: SecurityIssue) =
        securityIssue.Details.Properties.Add(getUniquePropertyName(propName, securityIssue.Details.Properties), propValue)

    let isNew(key: String) =
        let mutable isNew = false
        lock _analyzedPages (fun () ->
            isNew <- _analyzedPages.Add(key)
        )  
        isNew
        
    let extractGitInfo(testRequest: TestRequest) =
        if testRequest.WebRequest.HttpRequest.Uri.Segments |> Seq.map(fun r -> r.TrimEnd('/')) |> Seq.contains(".git") then
            let gitPath =
                (testRequest.WebRequest.HttpRequest.Uri.Segments
                |> Seq.takeWhile(fun r -> not <| r.TrimEnd('/').Equals(".git", StringComparison.Ordinal))
                |> fun segments -> String.Join(String.Empty, segments)) + ".git/"

            if isNew(gitPath + "_PATH") then
                let ub = new UriBuilder(testRequest.WebRequest.HttpRequest.Uri.AbsoluteUri)
                ub.Path <- gitPath
                let url = ub.Uri.AbsoluteUri
                let securityIssue = createSecurityIssue(url, "GIT Information and Source Code Disclosure")
                let files = new Dictionary<String, GitObject * String>()
                let tree = new Dictionary<String, String>()

                let gitDownloader = new GitDownloader(this.WebRequestor.Value.HttpRequestor)
                gitDownloader.AnalyzeUrl(url)
                |> List.iter(fun (id, gitObject) ->
                    match gitObject with
                    | Commit commit -> addProperty("Commit", commit, securityIssue)
                    | Tree tl -> tl |> List.iter(fun (fileName, id) -> tree.Add(getUniquePropertyName(id, tree), fileName))
                    | Tag v -> ()
                    | Blob blob -> files.[id] <- (gitObject, blob)
                    | Description desc -> addProperty("Description", desc, securityIssue)
                    | Config config -> addProperty("Config", config, securityIssue)
                    | Index il -> 
                        let indexData = String.Join(Environment.NewLine, il |> List.map(fun (f,s) -> f + " size: " + s.ToString()))
                        addProperty("Index", indexData, securityIssue)
                )

                // for each blob file get the filename
                files
                |> Seq.iter(fun kv ->
                    let id = kv.Key
                    let (gitObj, objContent) = kv.Value
                    if tree.ContainsKey(id) then
                        let filename = tree.[id]
                        _log?DownloadedGitResource(filename, gitObj)
                        securityIssue.Details.Properties.Add(getUniquePropertyName(filename, securityIssue.Details.Properties), objContent)
                )

                if securityIssue.Details.Properties.Count > 0 then
                    this.Context.Value.AddSecurityIssue(securityIssue)

    default this.Initialize(context: Context, webRequestor: IWebPageRequestor, messageBroker: IMessageBroker, logProvider: ILogProvider) =
        logProvider.AddLogSourceToLoggers(_log)
        base.Initialize(context, webRequestor, messageBroker, logProvider)        
                
    default this.Scan(testRequest: TestRequest, stateController: ServiceStateController) =        
        if isNew(testRequest.WebRequest.HttpRequest.Uri.PathAndQuery) then
            extractGitInfo(testRequest)