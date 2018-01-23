namespace ES.Taipan.Inspector.AddOns.StoredCrossSiteScripting

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
open ES.Taipan.Crawler
open ES.Fslog

type StoredCrossSiteScriptingAddOn() as this =
    inherit BaseStatelessAddOn("Stored Cross Site Scripting AddOn", "5B9F1F2F-4A91-48A9-8615-2EA25E73E5B3", 1)
    let _analyzedParameters = new Dictionary<String, HashSet<String>>()
    let _forbiddenContentTypes = ["video/"; "audio/"; "image/"]

    // this parameter contains a list of: attack vector | list of string to search in HTML for success
    let mutable _payloads: (String * String list) list = []

    let _log = 
        log "StoredCrossSiteScriptingAddOn"
        |> verbose "MaybeXss" "Precondition for XSS verified on path '{0}' parameter: {1}"
        |> verbose "FoundXss" "Identified XSS on path '{0}' parameter: {1}"
        |> build
    
    let reportSecurityIssue(uri: Uri, parameterName: String, attackString: String, entryPoint: EntryPoint, webRequest: WebRequest, webResponse: WebResponse, html: String) =
        let securityIssue = 
            new SecurityIssue(
                this.Id, 
                Name = "Stored Cross Site Scripting", 
                Uri = uri,
                EntryPoint = entryPoint,
                Note = String.Format("Parameter = {0}", parameterName)
            )
        securityIssue.Transactions.Add(webRequest, webResponse)
        securityIssue.Details.Properties.Add("Html", html)
        securityIssue.Details.Properties.Add("Parameter", parameterName)
        securityIssue.Details.Properties.Add("Attack", attackString)
        this.Context.Value.AddSecurityIssue(securityIssue)

    let hasForbiddenContentType(header: HttpHeader) =
        _forbiddenContentTypes
        |> List.exists(header.Value.Contains)

    let testProbeRequest(parameter: ProbeParameter, inProbeRequest: ProbeRequest, rebuild: Boolean) =
        let mutable probeRequest = inProbeRequest

        if rebuild then
            let rebuildedTestRequest = this.RebuildTestRequestFromReferer(probeRequest.TestRequest)
            probeRequest <- new ProbeRequest(rebuildedTestRequest)
            probeRequest.AddParameter(parameter)

        let webRequest = new WebRequest(probeRequest.BuildHttpRequest(true))
        let webResponse = this.WebRequestor.Value.RequestWebPage(webRequest)        
        if box(webResponse.HttpResponse) <> null then
            inProbeRequest.WebResponse <- Some webResponse
            match HttpUtility.tryGetHeader("Content-Type", webResponse.HttpResponse.Headers) with
            | Some header when not(hasForbiddenContentType(header)) -> 
                // if one of the expected value is found, than the website is vulnerable
                let html = webResponse.HttpResponse.Html
                match parameter.ExpectedValues |> List.tryFind(fun expectedValue -> html.ToLower().Contains(expectedValue.ToLower())) with
                | Some check -> 
                    parameter.State <- Some(upcast(check, html))
                    true
                | None -> false
            | _ -> false
        else false

    let verifyWithBogusParamValue(parameter: ProbeParameter, probeRequest: ProbeRequest, rebuild: Boolean) =
        let newProbeRequest = new ProbeRequest(probeRequest.TestRequest)
        let newParameter = getParameter(parameter, newProbeRequest)
        newParameter.AlterValue(parameter.Value)

        // for each parameter with empty value insert a bogus value
        let bogusValue = Guid.NewGuid().ToString("N").Substring(0,6)
        newProbeRequest.GetParameters()
        |> Seq.filter(fun parameter -> String.IsNullOrEmpty(parameter.Value))
        |> Seq.iter(fun parameter -> parameter.Value <- bogusValue)

        testProbeRequest(newParameter, newProbeRequest, rebuild)    
        
    let verifyWithOriginalParamValue(parameter: ProbeParameter, probeRequest: ProbeRequest, rebuild: Boolean) =
        testProbeRequest(parameter, probeRequest, rebuild)      
    
    let verify(parameter: ProbeParameter, probeRequest: ProbeRequest, rebuild: Boolean) =
        [verifyWithOriginalParamValue; verifyWithBogusParamValue]
        |> List.exists(fun f -> f(parameter, probeRequest, rebuild))
        
    let isParameterSafeToTest(parameter: ProbeParameter) =
        if parameter.Type = HEADER then
            ["User"; "X-"] |> List.exists (fun headerPrefix -> parameter.Name.StartsWith(headerPrefix))
        else
            true

    let specificTest(parameter: ProbeParameter, probeRequest: ProbeRequest, attackVector: String, checks: String list, rebuild: Boolean) =
        // configure probe
        parameter.AlterValue(attackVector)
        parameter.ExpectedValues <- checks

        // verify the vulnerability
        if verify(parameter, probeRequest, rebuild) then
            let (successCheck, html) = parameter.State.Value :?> (String * String)
            Some(attackVector, successCheck, html)
        else None

    let verifyPrecondition(parameter: ProbeParameter, probeRequest: ProbeRequest, rebuild: Boolean) =
        let preconditionValue = String.Join(String.Empty, (Guid.NewGuid().ToString("N")).ToCharArray().[0..5])
        parameter.AlterValue(preconditionValue)
        parameter.ExpectedValues <- [preconditionValue]
        verify(parameter, probeRequest, rebuild)

    let test(parameter: ProbeParameter, probeRequest: ProbeRequest, rebuild: Boolean) =
        let mutable isVulnerable = false
        if isParameterSafeToTest(parameter) && verifyPrecondition(parameter, probeRequest, rebuild) then
            _log?MaybeXss(probeRequest.TestRequest.WebRequest.HttpRequest.Uri.AbsolutePath, parameter)
            // do a more deepth test to avoid FP and to identify a payload
            for (vector, checks) in _payloads do
                if not isVulnerable then
                    match specificTest(parameter, probeRequest, vector, checks, rebuild) with
                    | Some (foundVector, foundPaload, html) -> 
                        _log?FoundXss(probeRequest.TestRequest.WebRequest.HttpRequest.Uri.AbsolutePath, parameter)

                        let path = probeRequest.TestRequest.WebRequest.HttpRequest.Uri.AbsolutePath                        
                        isVulnerable <- true

                        let entryPoint =
                            match parameter.Type with
                            | QUERY -> EntryPoint.QueryString
                            | DATA -> EntryPoint.DataString
                            | HEADER -> EntryPoint.Header

                        reportSecurityIssue(
                            probeRequest.TestRequest.WebRequest.HttpRequest.Uri, 
                            parameter.Name, 
                            parameter.Value,
                            entryPoint,
                            new WebRequest(probeRequest.BuildHttpRequest()),
                            probeRequest.WebResponse.Value,
                            html
                        )
                    | None -> ()
        isVulnerable
        
    let isRequestOkToAnalyze(parameter: ProbeParameter, probeRequest: ProbeRequest, rebuild: Boolean) =
        let path = probeRequest.TestRequest.WebRequest.HttpRequest.Uri.AbsolutePath
        let hasSource = probeRequest.TestRequest.WebRequest.HttpRequest.Source.IsSome
        if not <| _analyzedParameters.ContainsKey(path) then
            _analyzedParameters.Add(path, new HashSet<String>())
        _analyzedParameters.[path].Add(String.Format("{0}_{1}_{2}_{3}", parameter.Type, parameter.Name, rebuild, hasSource))

    let scan(testRequest: TestRequest, stateController: ServiceStateController, rebuild: Boolean) =
        let mutable testWithRebuild = false
        let mutable probeRequest = new ProbeRequest(testRequest)     
        let parameters = new List<ProbeParameter>()
        
        // thread safe check on parameters
        lock _analyzedParameters (fun _ -> 
            for parameter in probeRequest.GetParameters() do
                if isRequestOkToAnalyze(parameter, probeRequest, rebuild) then
                    parameters.Add(parameter)
        )
           
        // analyze all new parameters
        for parameter in parameters do
            let originalValue = parameter.Value
            let mutable isTestVulnerable = test(parameter, probeRequest, rebuild)
            parameter.Value <- originalValue

            // check for file parameter
            match parameter.Filename with
            | Some filename -> 
                let originalValue = parameter.AlterValue
                parameter.AlterValue <- (fun x -> parameter.Filename <- Some x)
                isTestVulnerable <- test(parameter, probeRequest, rebuild)
                parameter.AlterValue <- originalValue
                parameter.Filename <- Some filename
            | _ -> ()

            if isTestVulnerable then
                // this code is necessary in order to update the list of analyzed parameters
                lock _analyzedParameters (fun _ ->                     
                    isRequestOkToAnalyze(parameter, probeRequest, not rebuild) |> ignore
                )

            testWithRebuild <- testWithRebuild || (not isTestVulnerable && testRequest.WebRequest.HttpRequest.Method = HttpMethods.Post)
        
        testWithRebuild

    default this.Initialize(context: Context, webRequestor: IWebPageRequestor, messageBroker: IMessageBroker, logProvider: ILogProvider) =
        base.Initialize(context, webRequestor, messageBroker, logProvider) |> ignore
        logProvider.AddLogSourceToLoggers(_log)

        match this.Context.Value.AddOnStorage.ReadProperty<(String * String list) list>("Payloads") with
        | Some payloads -> _payloads <- payloads
        | None -> ()


        // test if re-crawling is active, otherwise is useless to send test

        true

    default this.Scan(testRequest: TestRequest, stateController: ServiceStateController) =
        

        if testRequest.RequestType = TestRequestType.CrawledPage then
            if not <| scan(testRequest, stateController, false) then
                // test with rebuild, since there are POST parameters that are not vulnerable, maybe they are not due to CSRF token?
                scan(testRequest, stateController, true) |> ignore   