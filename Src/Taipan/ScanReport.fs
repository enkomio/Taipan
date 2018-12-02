namespace Taipan

open System
open System.Reflection
open System.Linq
open System.IO
open System.Collections.Generic
open System.Text
open Newtonsoft.Json
open ES.Taipan.Application

type ReportFormat =
    | Json
    | Txt

    override this.ToString() =
        match this with
        | Txt -> ".txt"
        | Json -> ".json"

type ScanReport(scanResult: ScanResult) =
    let getOrDefault(key: String, defaultValue: String, items: Dictionary<String, String>) =
        items
        |> Seq.tryFind(fun kv -> kv.Key.Equals(key, StringComparison.OrdinalIgnoreCase))
        |> function
            | Some v -> v.Value
            | None -> defaultValue

    member val Vulnerabilities = scanResult.GetSecurityIssues() with get
    member val WebApplications = scanResult.GetWebApplicationsIdentified() with get
    member val WebServer = scanResult.GetWebServerFingerprint() with get
    member val HiddenResources = scanResult.GetHiddenResourceDiscovered() with get
    member val Type = Txt with get, set

    member this.FormatToTxt() =
        let reportContent = new StringBuilder()
        let print x = reportContent.AppendLine(x) |> ignore
        
        // print server fingerprint
        let webServerFingerprint = scanResult.GetWebServerFingerprint()

        print("-= Web Server =-")
        print("\t" + webServerFingerprint.Server.ToString())
        print(String.Empty)
        
        let frameworks = webServerFingerprint.Frameworks
        if frameworks.Any() then
            print("-= Web Frameworks =-")
            frameworks
            |> Seq.iter(fun framework ->
                print("\t" + framework)
            )
            print(String.Empty)

        let languages = webServerFingerprint.Languages
        if languages.Any() then
            print("-= Web Programming Language =-")
            languages
            |> Seq.iter(fun lang ->
                print("\t" + lang.ToString())
            )
            print(String.Empty)
        
        // print hidden resources
        let hiddenResources = scanResult.GetHiddenResourceDiscovered()
        if hiddenResources.Any() then
            print("-= Hidden Resources =-")
            hiddenResources
            |> Seq.iter(fun hiddenRes ->
                String.Format("\t{0} {1} ({2})", hiddenRes.Resource.Path.PadRight(40), hiddenRes.Response.StatusCode, int32 hiddenRes.Response.StatusCode)
                |> print
            )
            print(String.Empty)

        // print fingerprint        
        let webApplicationIdentified = scanResult.GetWebApplicationsIdentified()
        if webApplicationIdentified.Any() then
            print("-= Identified Web Applications =-")
            webApplicationIdentified
            |> Seq.iter(fun webApp ->
                let versions = String.Join(",", webApp.IdentifiedVersions |> Seq.map(fun kv -> kv.Key.Version))
                String.Format("\t{0} v{1} {2}", webApp.WebApplicationFingerprint.Name, versions, webApp.Request.Request.Uri.AbsolutePath)
                |> print
            )
            print(String.Empty)
        
        // print security issues
        let issues = scanResult.GetSecurityIssues()
        if issues.Any() then
            print("-= Security Issues =-")
            issues
            |> Seq.iter(string >> print)

        reportContent.ToString()

    member this.Save(reportFilename: String option) =
        let baseName = String.Format("{0}_{1}{2}", scanResult.Scan.Context.StartRequest.HttpRequest.Uri.Host, Guid.NewGuid().ToString("N"), this.Type.ToString())
        let reportDirectory = Path.Combine(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location), "Report")
        Directory.CreateDirectory(reportDirectory) |> ignore
        let defaultName = Path.Combine(reportDirectory, baseName)

        let filename = defaultArg reportFilename defaultName

        let reportContent =
            match this.Type with
            | Json -> JsonConvert.SerializeObject(this, Formatting.Indented)        
            | Txt -> this.FormatToTxt()

        File.WriteAllText(filename, reportContent)
        filename