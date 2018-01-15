namespace ES.Taipan.Inspector.AddOns.WebApplicationVulnerability

open System
open System.IO
open ES.Taipan.Inspector
open ES.Taipan.Inspector.AddOns
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Infrastructure.Service
open ES.Taipan.Infrastructure.Messaging
open ES.Fslog
open TestSSLServerLib

type SSLTestAddOn() as this =
    inherit BaseStatelessAddOn("SSL Test AddOn", "70786DC5-0831-463B-B8FE-A3FCED2F1AD2", 1)
    let mutable _serverTested = false
    let mutable _webProxy : String option = None
        
    let createIssue(testRequest: TestRequest, reportData: ReportDataDto, testResult: String) =
        let securityIssue = 
            new SecurityIssue(
                this.Id, 
                Name = "SSL Test", 
                Uri = testRequest.WebRequest.HttpRequest.Uri, 
                EntryPoint = EntryPoint.Other "Server",
                Note = String.Empty
            )
            
        // add properties
        securityIssue.Details.Properties.Add("Output", testResult)
        securityIssue.Details.Properties.Add("NameMismatch", reportData.NameMismatch.ToString())
        securityIssue.Details.Properties.Add("WeakCipher", reportData.WeakCipher.ToString())
        reportData.Issues |> Seq.iteri(fun i issue -> securityIssue.Details.Properties.Add("Issue" + i.ToString(), issue))

        if reportData.NameMismatch || reportData.WeakCipher || reportData.Issues.Count > 0 then
            securityIssue.Details.Properties.Add("Impact", "Low")
        else
            securityIssue.Details.Properties.Add("Impact", "Informational")

        this.Context.Value.AddSecurityIssue(securityIssue)

    default this.Initialize(context: Context, webRequestor: IWebPageRequestor, messageBroker: IMessageBroker, logProvider: ILogProvider) =
        base.Initialize(context, webRequestor, messageBroker, logProvider) |> ignore
        _webProxy <- webRequestor.HttpRequestor.Settings.ProxyUrl
        true
                                                
    default this.Scan(testRequest: TestRequest, stateController: ServiceStateController) =
        if testRequest.RequestType = TestRequestType.CrawledPage && not _serverTested then            
            if testRequest.WebRequest.HttpRequest.Uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase) then
                _serverTested <- true

                // start test
                let ft = new FullTest()
                ft.AllSuites <- true
                ft.ServerName <- testRequest.WebRequest.HttpRequest.Uri.Host
                ft.ServerPort <- testRequest.WebRequest.HttpRequest.Uri.Port

                match _webProxy with
                | Some proxy when not(String.IsNullOrWhiteSpace(proxy)) -> 
                    let proxyUri = new Uri(proxy)
                    ft.ProxName <- proxyUri.Host
                    ft.ProxPort <- proxyUri.Port
                | _ -> ()

                let report = ft.Run()

                // get result
                report.ShowCertPEM <- true
                let stringtWriter = new StringWriter()    
                let reportData = report.Print(stringtWriter)
                createIssue(testRequest, reportData, stringtWriter.ToString())