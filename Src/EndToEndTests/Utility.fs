[<AutoOpen>]
module Utility

open System
open System.Threading.Tasks
open System.Threading
open Suave
open ES.Groviera
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Application
open ES.Taipan.Fingerprinter
open ES.Taipan.Discoverer
open ES.Taipan.Crawler
open ES.Taipan.Infrastructure.Service
open ES.Fslog
open ES.Fslog.Loggers

type TestResult = {
    Crawled: (String * String) list
    Discoverer: String list
    Fingerprinter: (String * String list) list
    Vulnerabilities: (String * String) list
} with
    static member Create(crawled: (String * String) list, discoverer: String list, fingerprinter: (String * String list) list, vulnerabilities: (String * String) list) =
        {Crawled = crawled; Discoverer = discoverer; Fingerprinter = fingerprinter; Vulnerabilities = vulnerabilities}

let activatePlugin(scanContext: ScanContext, plugin: String) =
    scanContext.Template.VulnerabilityScannerSettings.ActivateAllAddOns <- false
    scanContext.Template.VulnerabilityScannerSettings.AddOnIdsToActivate.Clear()
    scanContext.Template.VulnerabilityScannerSettings.AddOnIdsToActivate.Add(Guid.Parse(plugin))

let activatePlugins(scanContext: ScanContext, plugins: String list) =
    scanContext.Template.VulnerabilityScannerSettings.ActivateAllAddOns <- false
    scanContext.Template.VulnerabilityScannerSettings.AddOnIdsToActivate.Clear()
    
    plugins
    |> List.map(Guid.Parse)
    |> scanContext.Template.VulnerabilityScannerSettings.AddOnIdsToActivate.AddRange
    
let verifyInspector(securityIssuesToCheck: (String * String) list) (scanResult: ScanResult) =
    let securityIssues = scanResult.GetSecurityIssues()
    if securityIssues.Count <> securityIssuesToCheck.Length then failwith "Unexpected number of security issues"

    securityIssuesToCheck
    |> List.iter(fun (vulnerabilityName, path) ->
        if 
            securityIssues
            |> Seq.exists(fun secIssue ->
                secIssue.Name.Equals(vulnerabilityName, StringComparison.Ordinal) && secIssue.Uri.AbsolutePath.Equals(path, StringComparison.Ordinal)
            )
            |> not
        then
            failwith(String.Format("Security issue: {0}, path {1} not found", vulnerabilityName, path))
    )

let verifyFingerprint(resToCheck: (String * String list) list) (scanResult: ScanResult) =
    let applicationsFound = scanResult.GetWebApplicationsIdentified()
    if applicationsFound.Count <> resToCheck.Length then failwith "Unexpected number of applications"

    resToCheck
    |> List.iter(fun webAppToCheck ->
        let appNameToCheck = fst webAppToCheck
        let versionsToCheck = snd webAppToCheck

        // check if app name found
        let foundAppName = 
            applicationsFound
            |> Seq.tryFind(fun identifiedApp -> identifiedApp.WebApplicationFingerprint.Name.Equals(appNameToCheck, StringComparison.Ordinal))

        if foundAppName.IsNone then
            failwith ("Expected application: " +  appNameToCheck)
                
        // check if version found
        if foundAppName.Value.IdentifiedVersions.Count <> versionsToCheck.Length then 
            failwith "Unexpected number of versions"

        for version in foundAppName.Value.IdentifiedVersions.Keys |> Seq.map(fun v -> v.Version) do
            if not(versionsToCheck |> List.contains version) then
                failwith("Application version: " +  version + " not found")
    )

let verifyDiscoverer(resToCheck: String list) (scanResult: ScanResult) =
    let resourcesFound = scanResult.GetHiddenResourceDiscovered()
    if resourcesFound.Count <> resToCheck.Length then failwith "Unexpected number of resources"        
    if
        resourcesFound
        |> Seq.map(fun r -> r.Resource.Path)
        |> Seq.forall(fun path -> resToCheck |> List.contains path)
        |> not
    then failwith "Some resource wasn't found"

let verifyCrawlerWithCallback(pagesToCheck: (String * String) list) (callback: WebLink * WebResponse -> Boolean) (scanResult: ScanResult) =
    let pagesFound = scanResult.GetWebPages()
    if pagesFound.Count < pagesToCheck.Length then failwith "Unexpected number of pages"   
    
    let isAllowedResponseCode(webResponse: WebResponse) =
        [System.Net.HttpStatusCode.OK; System.Net.HttpStatusCode.Redirect] 
        |> List.contains webResponse.HttpResponse.StatusCode
    
    if
        pagesToCheck 
        |> List.forall(fun (url, data) ->
            pagesFound
            |> Seq.exists(fun (webLink, webResponse) -> 
                let result = 
                    if String.IsNullOrEmpty(data) then
                        isAllowedResponseCode(webResponse) && 
                        webLink.Request.HttpRequest.Uri.PathAndQuery.Equals(url, StringComparison.Ordinal)
                    else
                        let dataCheck = 
                            webLink.Request.HttpRequest.Data.Contains(data) || 
                            (data + "=").Equals(webLink.Request.HttpRequest.Data) ||
                            webResponse.HttpResponse.Html.Contains(data)

                        isAllowedResponseCode(webResponse) && 
                        webLink.Request.HttpRequest.Uri.PathAndQuery.Equals(url, StringComparison.Ordinal) && 
                        dataCheck

                if result then
                    callback(webLink, webResponse)
                else false
                    
            )
        )
        |> not
    then failwith "Some page wasn't found"

let verifyCrawler(pagesToCheck: (String * String) list) (scanResult: ScanResult) =
    verifyCrawlerWithCallback pagesToCheck (fun _ -> true) scanResult

let verify(testResult: TestResult) (scanResult: ScanResult) =
    verifyDiscoverer testResult.Discoverer scanResult
    verifyFingerprint testResult.Fingerprinter scanResult
    verifyCrawler testResult.Crawled scanResult
    verifyInspector testResult.Vulnerabilities scanResult

let shutDownServer() =
    ES.Groviera.Program.shutDownServer()

let simulatePhp() =
    ES.Groviera.Program.simulatePhpEnabledWebServer()

let stopSimulatePhp() =
    ES.Groviera.Program.stopSimulatePhpEnabledWebServer()

let runGrovieraServerOnPort(port: Int32) =
    let host = "127.0.0.1"
                
    // run the server    
    Task.Factory.StartNew(fun () -> 
        ES.Groviera.Program.main([|host; string port|])
    ) |> ignore
    Thread.Sleep(6000)
    new Uri("http://" + host + ":" + string port)

let runGrovieraServer() = 
    let port = (new Random()).Next(2000, 65535)
    runGrovieraServerOnPort(port)

let prettyPrintMetrics(metrics: ServiceMetrics) =
    Console.WriteLine("{0}Service: {1}", Environment.NewLine, metrics.ServiceName)
    match metrics.GetAll() with
    | [] -> Console.WriteLine("N/A")
    | metrics ->
        metrics
        |> List.iter(fun metric ->
            Console.WriteLine("[{0}] {1} = {2}", metric.TimeStamp, metric.Name, metric.Value)
        )

let mutable scanService : ScanService option = None
do
    Task.Factory.StartNew(fun () ->
        while true do
            if scanService.IsSome then
                let key = Console.ReadKey(true).KeyChar
                if key = 'k' || key = 'K' then
                    scanService.Value.AbortCurrentScan()
                elif key = 'd' || key = 'D' then                    
                    Console.WriteLine("{0}*********************************************", Environment.NewLine)
                    Console.WriteLine("**************** DEBUG INFO *****************")
                    Console.WriteLine("*********************************************")
                    scanService.Value.GetCurrenScanMetrics()
                    |> Seq.iter prettyPrintMetrics
                    Console.WriteLine()
                else
                    match scanService.Value.GetCurrenScanStatus() with
                    | Some scanResult -> 
                        let scan = scanResult.Scan
                        if key = 'p' || key = 'P' then
                            scan.Pause()
                        elif key = 'r' || key = 'R' then
                            scan.Resume()
                        elif key = 's' || key = 'S' then
                            scan.Stop()
                    | None -> ()
    , TaskCreationOptions.LongRunning) |> ignore

let runScan(scanContext: ScanContext) =
    let service = new ScanService(LogProvider.GetDefault())    
    let scanLogProvider = new LogProvider()
    scanLogProvider.AddLogger(new ConsoleLogger(LogLevel.Informational))    
    scanService <- Some service
    service.GetScanResult(scanContext, Guid.NewGuid(), scanLogProvider)
    
    
