namespace ES.Taipan.Application

open System
open System.Linq
open System.Collections.Concurrent
open ES.Taipan.Fingerprinter
open ES.Taipan.Discoverer
open ES.Taipan.Crawler
open ES.Taipan.Inspector
open ES.Taipan.Infrastructure.Network

type ScanResult(scan: Scan) =
    let _identifiedWebApplications = new ConcurrentBag<WebApplicationIdentified>()
    let _resourceDiscovered = new ConcurrentBag<ResourceDiscovered>()
    let _webPages = new ConcurrentBag<WebLink * WebResponse>()
    let _securityIssues = new ConcurrentBag<SecurityIssue>()
    let mutable _webServerFingerprint = new WebServerFingerprint()

    do
        scan.NewApplicationIdentified.Add(fun msg -> _identifiedWebApplications.Add(msg.WebApplication))
        scan.NewResourceDiscovered.Add(fun msg -> _resourceDiscovered.Add(msg.Resource))
        scan.PageProcessed.Add(fun msg -> _webPages.Add(msg.Link, msg.WebResponse))
        scan.NewSecurityIssueFound.Add(fun msg -> _securityIssues.Add(msg.Issue))
        scan.WebServerFingerprinted.Add(fun fingerprint -> _webServerFingerprint <- fingerprint)
        
    member this.Scan = scan

    member this.GetWebApplicationsIdentified() =
        _identifiedWebApplications.ToList()

    member this.GetHiddenResourceDiscovered() =
        _resourceDiscovered.ToList()

    member this.GetWebPages() =
        _webPages.ToList()

    member this.GetSecurityIssues() =
        _securityIssues.ToList()

    member this.GetWebServerFingerprint() =
        _webServerFingerprint