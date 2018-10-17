namespace ES.Taipan.Inspector.AddOns.SSLTest

open System
open System.Text
open ES.Taipan.Inspector
open ES.Taipan.Inspector.AddOns
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Infrastructure.Service
open ES.Taipan.Infrastructure.Messaging
open ES.Fslog
open TestSSLServerLib
open Newtonsoft.Json.Linq

type SSLTestAddOn() as this =
    inherit BaseStatelessAddOn("SSL Test AddOn", string SSLTestAddOn.Id, 1)
    let mutable _serverTested = false
    let mutable _webProxy : String option = None

    let parseJsonReport(json: String) =
        let jsonObj = JObject.Parse(json)
        let jTokenRef: JToken ref = ref(null)
        let mutable globalImpact = 3
        let outputAnalysis = new StringBuilder()

        if jsonObj.TryGetValue("SSLv2", jTokenRef) then
            outputAnalysis.AppendLine("SSLV2 Enabled").AppendLine() |> ignore
            globalImpact <- 0

        ["SSLv3"; "TLSv1.0"; "TLSv1.1"; "TLSv1.2"]
        |> List.iter(fun suite ->        
            if jsonObj.TryGetValue(suite, jTokenRef) then
                outputAnalysis.AppendLine(suite) |> ignore

                let jToken = !jTokenRef
                jToken.["suites"]
                |> Seq.iter(fun suite ->
                    let name = suite.["name"].ToString()
            
                    // compute global impact
                    let strength = ref 3
                    if Int32.TryParse(suite.["strength"].ToString(), strength) then
                        if !strength < globalImpact then
                            globalImpact <- !strength
            
                    let forwardSecrecy = ref true
                    if Boolean.TryParse(suite.["forwardSecrecy"].ToString(), forwardSecrecy) then
                        if not !forwardSecrecy && globalImpact > 2 then
                            globalImpact <- 2

                    let anonymous = ref false
                    if Boolean.TryParse(suite.["anonymous"].ToString(), anonymous) then
                        if !anonymous && globalImpact > 2 then
                            globalImpact <- 2

                    let strengthString =
                        match !strength with
                        | 0 -> "unencrypted"
                        | 1 -> "very weak"
                        | 2 -> "less weak"
                        | 3 -> "strong"
                        | _ -> "n/a"

                    outputAnalysis.AppendFormat("\tStrenght: {0}, Name: {1}", strengthString, name).AppendLine() |> ignore
                )

                outputAnalysis.AppendLine() |> ignore
        )

        // parse ssl3 chains
        if jsonObj.TryGetValue("ssl3Chains", jTokenRef) then
            !jTokenRef
            |> Seq.iteri(fun i jTokenChain ->
                outputAnalysis.AppendFormat("SSLv3/TLS, chain: {0}", i+1).AppendLine() |> ignore
                jTokenChain.["certificates"]
                |> Seq.iteri(fun j jToken ->
                    outputAnalysis.AppendLine().AppendFormat("Certificate: {0}", j+1).AppendLine() |> ignore
                    let decodable = ref false

                    if Boolean.TryParse(jToken.["decodable"].ToString(), decodable) && !decodable then
                        let validFrom = DateTime.Parse(jToken.["validFrom"].ToString().Replace(" UTC", String.Empty))
                        let validTo = DateTime.Parse(jToken.["validTo"].ToString().Replace(" UTC", String.Empty))
                        let now = DateTime.UtcNow

                        if (now < validFrom || now > validTo) && globalImpact > 1 then
                            globalImpact <- 1

                        let selfIssued = ref false
                        if Boolean.TryParse(jToken.["selfIssued"].ToString(), selfIssued) then
                            if !selfIssued then
                                globalImpact <- 0

                        // compose output
                        outputAnalysis.AppendFormat("\tValid From: {0}", validFrom).AppendLine() |> ignore
                        outputAnalysis.AppendFormat("\tValid To: {0}", validTo).AppendLine() |> ignore
                        outputAnalysis.AppendFormat("\tSelf Issued: {0}", !selfIssued).AppendLine() |> ignore
                        outputAnalysis.AppendFormat("\tSerial: {0}", jToken.["serial"]).AppendLine() |> ignore
                        outputAnalysis.AppendFormat("\tSubject: {0}", jToken.["subject"]).AppendLine() |> ignore
                        outputAnalysis.AppendFormat("\tIssuer: {0}", jToken.["issuer"]).AppendLine() |> ignore
                    
                        let serverNames = jToken.["serverNames"]
                        if serverNames <> null then
                            outputAnalysis.AppendLine("\tServer Names:") |> ignore
                            serverNames
                            |> Seq.iter(fun jServerName ->
                                outputAnalysis.AppendFormat("\t\t{0}", jServerName).AppendLine() |> ignore
                            )
                )                

            )

            // check for warnings
            if jsonObj.TryGetValue("warnings", jTokenRef) then
                outputAnalysis.AppendLine().AppendLine("Warnings:") |> ignore
                !jTokenRef
                |> Seq.iter(fun jTokenWarning ->
                    outputAnalysis.AppendFormat("\t{0}: {1}", jTokenWarning.["id"], jTokenWarning.["text"]).AppendLine() |> ignore

                    if globalImpact > 1 then
                        globalImpact <- 1
                )


        (globalImpact, outputAnalysis.ToString())
        
    let createIssue(testRequest: TestRequest, jsonReport: String) =
        let securityIssue = 
            new SecurityIssue(
                SSLTestAddOn.Id, 
                Name = "SSL Test", 
                Uri = testRequest.WebRequest.HttpRequest.Uri, 
                EntryPoint = EntryPoint.Other "Server"
            )
          
        let (impact, output) = parseJsonReport(jsonReport)

        // add properties
        securityIssue.Details.Properties.Add("Output", output)
        securityIssue.Details.Properties.Add("Json", jsonReport)
        securityIssue.Note <- output

        // set impact
        let impactString =
            match impact with
            | 0 -> "High"
            | 1 -> "Medium"
            | 2 -> "Low"
            | _ -> "Informational"
        securityIssue.Details.Properties.Add("Impact", impactString)

        this.Context.Value.AddSecurityIssue(securityIssue)

    static member Id = Guid.Parse("70786DC5-0831-463B-B8FE-A3FCED2F1AD2")

    default this.Initialize(context: Context, webRequestor: IWebPageRequestor, messageBroker: IMessageBroker, logProvider: ILogProvider) =
        base.Initialize(context, webRequestor, messageBroker, logProvider) |> ignore
        _webProxy <- webRequestor.HttpRequestor.Settings.ProxyUrl
        true
                                                
    default this.Scan(testRequest: TestRequest, stateController: ServiceStateController) =
        if testRequest.RequestType = TestRequestType.CrawledPage && not _serverTested then            
            if testRequest.WebRequest.HttpRequest.Uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase) then
                _serverTested <- true
                try
                    // start test
                    let ft = new FullTestWrapper()
                    ft.AllSuites <- true
                    ft.ServerName <- testRequest.WebRequest.HttpRequest.Uri.Host
                    ft.ServerPort <- testRequest.WebRequest.HttpRequest.Uri.Port

                    match _webProxy with
                    | Some proxy when not(String.IsNullOrWhiteSpace(proxy)) -> 
                        let proxyUri = new Uri(proxy)
                        ft.ProxName <- proxyUri.Host
                        ft.ProxPort <- proxyUri.Port
                    | _ -> ()
                
                    let jsonReport = ft.Run()
                    createIssue(testRequest, jsonReport)
                with _ -> ()