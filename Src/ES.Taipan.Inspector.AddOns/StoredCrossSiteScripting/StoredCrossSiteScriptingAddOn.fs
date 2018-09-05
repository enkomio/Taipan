namespace ES.Taipan.Inspector.AddOns.StoredCrossSiteScripting

open System
open System.Collections.Generic
open ES.Taipan.Inspector
open ES.Taipan.Inspector.AddOns
open ES.Taipan.Infrastructure.Service
open ES.Taipan.Infrastructure.Messaging
open ES.Taipan.Infrastructure.Network
open ES.Fslog

type StoredCrossSiteScriptingAddOn() as this =
    inherit BaseStatelessAddOn("Stored Cross Site Scripting AddOn", string StoredCrossSiteScriptingAddOn.Id, 1)    
    let _analyzedParameters = new Dictionary<String, HashSet<String>>()
    let _testRequests = new List<TestRequest>()
    let _probes = new Dictionary<String, ProbeRequest * ProbeParameter>()
    let _forbiddenContentTypes = ["video/"; "audio/"; "image/"]

    // this parameter contains a list of: attack vector | list of string to search in HTML for success
    let mutable _payloads = new Dictionary<String, List<String>>()
    let mutable _messageBroker: IMessageBroker option = None

    let _log = 
        log "StoredCrossSiteScriptingAddOn"
        |> verbose "MaybeXss" "Precondition for Sotred XSS verified on path '{0}' parameter: {1}, out page: {2}"
        |> verbose "FoundXss" "Identified Stored XSS on path '{0}' parameter: {1}, input page: {2}"
        |> build
    
    let reportSecurityIssue
        (
            uri: Uri, 
            parameterName: String, 
            attackString: String, 
            entryPoint: EntryPoint, 
            inWebRequest: WebRequest,             
            inWebResponse: WebResponse, 
            outWebRequest: WebRequest, 
            outWebResponse: WebResponse
        ) =

        let securityIssue = 
            new SecurityIssue(
                StoredCrossSiteScriptingAddOn.Id, 
                Name = "Stored Cross Site Scripting", 
                Uri = uri,
                EntryPoint = entryPoint,
                Note = String.Format("Parameter = {0}", parameterName)
            )
        securityIssue.Transactions.Add(inWebRequest, inWebResponse)
        securityIssue.Details.Properties.Add("InUrl", inWebRequest.HttpRequest.Uri.ToString())
        securityIssue.Transactions.Add(outWebRequest, outWebResponse)
        securityIssue.Details.Properties.Add("OutUrl", outWebRequest.HttpRequest.Uri.ToString())
        securityIssue.Details.Properties.Add("Parameter", parameterName)
        securityIssue.Details.Properties.Add("Attack", attackString)
        securityIssue.Details.Properties.Add("Html", outWebResponse.HttpResponse.Html)
        this.Context.Value.AddSecurityIssue(securityIssue)

    let hasForbiddenContentType(header: HttpHeader) =
        _forbiddenContentTypes
        |> List.exists(header.Value.Contains)

    let sendProbeRequest(parameter: ProbeParameter, inProbeRequest: ProbeRequest) =
        let mutable probeRequest = inProbeRequest        
        let webRequest = new WebRequest(probeRequest.BuildHttpRequest(true))
        this.WebRequestor.Value.RequestWebPage(webRequest)
                        
    let isParameterSafeToTest(parameter: ProbeParameter) =
        if parameter.Type = HEADER then
            ["User"; "X-"] |> List.exists (fun headerPrefix -> parameter.Name.StartsWith(headerPrefix))
        else
            true

    let sendProbe(parameter: ProbeParameter, probeRequest: ProbeRequest, probeValue: String) =
        probeRequest.SaveState()

        // send probe request
        parameter.AlterValue(probeValue)
        let webResponse = sendProbeRequest(parameter, probeRequest)
        probeRequest.RestoreState()

        webResponse
        
    let isRequestOkToAnalyze(parameter: ProbeParameter, probeRequest: ProbeRequest) =
        let path = probeRequest.TestRequest.WebRequest.HttpRequest.Uri.AbsolutePath
        let hasSource = probeRequest.TestRequest.WebRequest.HttpRequest.Source.IsSome
        if not <| _analyzedParameters.ContainsKey(path) then
            _analyzedParameters.Add(path, new HashSet<String>())
        _analyzedParameters.[path].Add(String.Format("{0}_{1}_{2}", parameter.Type, parameter.Name, hasSource))

    let probePage(testRequest: TestRequest, stateController: ServiceStateController) =        
        let mutable probeRequest = new ProbeRequest(testRequest)     
        let parameters = new List<ProbeParameter>()
        
        // thread safe check on parameters
        lock _analyzedParameters (fun _ -> 
            for parameter in probeRequest.GetParameters() do
                if isRequestOkToAnalyze(parameter, probeRequest) then
                    parameters.Add(parameter)
        )
                   
        // analyze all new parameters
        parameters
        |> Seq.filter(isParameterSafeToTest)
        |> Seq.iter(fun parameter ->
            let probeId = (new String(Guid.NewGuid().ToString("N").ToCharArray().[0..5])).ToLower()
            sendProbe(parameter, probeRequest, probeId) |> ignore           
            _probes.Add(probeId, (probeRequest, parameter))

            // check for file parameter
            match parameter.Filename with
            | Some filename -> 
                let probeId = (new String(Guid.NewGuid().ToString("N").ToCharArray().[0..5])).ToLower()
                let originalValue = parameter.AlterValue
                parameter.AlterValue <- (fun x -> parameter.Filename <- Some x)
                sendProbe(parameter, probeRequest, filename) |> ignore
                _probes.Add(probeId, (probeRequest, parameter))
                parameter.AlterValue <- originalValue
                parameter.Filename <- Some filename
            | _ -> ()
        )

    let verifyProbePresence(testRequest: TestRequest) =
        // re-send the request
        let httpResponse = this.WebRequestor.Value.RequestWebPage(testRequest.WebRequest).HttpResponse

        // do verification
        if box(httpResponse) <> null then
            match HttpUtility.tryGetHeader("Content-Type", httpResponse.Headers) with
            | Some header when not(hasForbiddenContentType(header)) -> 
                // if one of the expected value is found, than the website could be vulnerable
                let html = httpResponse.Html.ToLower()
                _probes.Keys |> Seq.tryFind(fun expectedValue -> html.Contains(expectedValue))
            | _ -> None
        else None

    let sendAttack(probeId: String, testRequest: TestRequest) =        
        let probeRequest, parameter = _probes.[probeId]
        let outRequest = testRequest.WebRequest
        let mutable isVulnerable = false

        _log?MaybeXss(probeRequest.TestRequest.WebRequest.HttpRequest.Uri.AbsolutePath, parameter.Name, outRequest.HttpRequest.Uri.AbsolutePath)
        // do a more deepth test to avoid FP and to identify a payload
        for kv in _payloads do
            let (attackVector, checks) = (kv.Key, kv.Value |> Seq.toList)
            if not isVulnerable then
                // send input probe
                parameter.AlterValue(attackVector)
                let inWebRequest = new WebRequest(probeRequest.BuildHttpRequest())
                let inWebResponse = sendProbe(parameter, probeRequest, attackVector)

                // verify output probe
                let outWebResponse = this.WebRequestor.Value.RequestWebPage(outRequest)
                if box(outWebResponse.HttpResponse) <> null then
                    let html = outWebResponse.HttpResponse.Html.ToLower()
                    match checks |> List.tryFind(fun expectedValue -> html.Contains(expectedValue.ToLower())) with
                    | Some check -> 
                        _log?FoundXss(outRequest.HttpRequest.Uri.AbsolutePath, parameter, probeRequest.TestRequest.WebRequest.HttpRequest.Uri.AbsolutePath)
                        parameter.State <- Some(upcast(check, outWebResponse.HttpResponse.Html))
                        isVulnerable <- true

                        // signal vulnerability
                        let entryPoint =
                            match parameter.Type with
                            | QUERY -> EntryPoint.QueryString
                            | DATA -> EntryPoint.DataString
                            | HEADER -> EntryPoint.Header

                        reportSecurityIssue(
                            outRequest.HttpRequest.Uri,
                            parameter.Name, 
                            attackVector,
                            entryPoint,
                            inWebRequest, // in web request
                            inWebResponse, // in web response
                            outRequest, // out web request
                            outWebResponse // out web response
                        )
                    | None -> ()

    static member Id = Guid.Parse("5B9F1F2F-4A91-48A9-8615-2EA25E73E5B3")

    default this.Initialize(context: Context, webRequestor: IWebPageRequestor, messageBroker: IMessageBroker, logProvider: ILogProvider) =
        base.Initialize(context, webRequestor, messageBroker, logProvider) |> ignore
        logProvider.AddLogSourceToLoggers(_log)
        
        _messageBroker <- Some messageBroker

        match this.Context.Value.AddOnStorage.ReadProperty<Dictionary<String, List<String>>>("Payloads") with
        | Some payloads -> _payloads <- payloads
        | None -> ()
        
        true

    override this.RunToCompletation(stateController: ServiceStateController) =
        _testRequests
        |> Seq.iter(fun testRequest ->
            if not stateController.IsStopped then
                match verifyProbePresence(testRequest) with
                | Some probeId -> sendAttack(probeId, testRequest)
                | None -> ()
        )

    default this.Scan(testRequest: TestRequest, stateController: ServiceStateController) =
        if testRequest.RequestType = TestRequestType.CrawledPage then
            probePage(testRequest, stateController)
            _testRequests.Add(testRequest)