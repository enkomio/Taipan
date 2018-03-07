namespace Taipan

open ES.Taipan.Application
open System
open System.IO
open Newtonsoft.Json

type ScanReport(scan: ScanResult) =
    member val Vulnerabilities = scan.GetSecurityIssues() with get
    member val WebApplications = scan.GetWebApplicationsIdentified() with get
    member val WebServer = scan.GetWebServerFingerprint() with get
    member val HiddenResources = scan.GetHiddenResourceDiscovered() with get

    member this.Save(reportFilename: String option) =
        let defaultName = String.Format("{0}_{1}.json", scan.Scan.Context.StartRequest.HttpRequest.Uri.Host, Guid.NewGuid().ToString("N"))        
        let filename = defaultArg reportFilename defaultName
        let jsonReport = JsonConvert.SerializeObject(this, Formatting.Indented)        
        File.WriteAllText(filename, jsonReport)
        filename