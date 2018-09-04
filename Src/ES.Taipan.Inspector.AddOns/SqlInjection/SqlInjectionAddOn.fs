namespace ES.Taipan.Inspector.AddOns.SqlInjection

open System
open System.Collections.Generic
open ES.Taipan.Inspector
open ES.Taipan.Inspector.AddOns
open ES.Taipan.Infrastructure.Service
open ES.Taipan.Infrastructure.Messaging
open ES.Taipan.Infrastructure.Network
open ES.Fslog

type SqlInjectionAddOn() as this =
    inherit BaseStatelessAddOn("SQL Injection (Blind and Error based) AddOn Wrapper", Guid.Empty.ToString(), 1)       
    let _analyzedParameters = new Dictionary<String, HashSet<String>>()    
    let _vulnerableParameters = new Dictionary<String, List<String>>()
    let _forbiddenContentTypes = ["video/"; "audio/"; "image/"]    
    let mutable _checkers : ISqliChecker list = List.empty

    let isRequestOkToAnalyze(parameter: ProbeParameter, probeRequest: ProbeRequest, rebuild: Boolean) =
        let path = probeRequest.TestRequest.WebRequest.HttpRequest.Uri.AbsolutePath
        if _vulnerableParameters.ContainsKey(path) && _vulnerableParameters.[path].Contains(parameter.Name)
        then false
        else
            let hasSource = probeRequest.TestRequest.WebRequest.HttpRequest.Source.IsSome
            if not <| _analyzedParameters.ContainsKey(path) then
                _analyzedParameters.Add(path, new HashSet<String>())
            _analyzedParameters.[path].Add(String.Format("{0}_{1}_{2}_{3}", parameter.Type, parameter.Name, rebuild, hasSource))

    let isParameterSafeToTest(parameter: ProbeParameter) =
        if parameter.Type = HEADER then
            ["User"; "X-"] |> List.exists (fun headerPrefix -> parameter.Name.StartsWith(headerPrefix))
        else
            true

    let reportSecurityIssue(uri: Uri, entryPoint: EntryPoint, checker: ISqliChecker, attackDetails: AttackDetails) =
        let attackString = 
            attackDetails.Details.Keys 
            |> Seq.tryFind(fun keyName -> keyName.Equals("Attack", StringComparison.OrdinalIgnoreCase))
            |> fun arg -> defaultArg arg String.Empty

        let securityIssue = 
            new SecurityIssue(
                checker.VulnId, 
                Name = checker.VulnName, 
                Uri = uri,
                EntryPoint = entryPoint,
                Note = String.Format("Parameter = {0} - {1}", attackDetails.ParameterName, attackString)
            )

        Seq.zip attackDetails.Requests attackDetails.Responses
        |> Seq.iter(securityIssue.Transactions.Add)

        securityIssue.Details.Properties.Add("Parameter", attackDetails.ParameterName)
        securityIssue.Details.Properties.Add("Synopsis", String.Format("{0} - Parameter: {1}", uri.AbsolutePath, attackDetails.ParameterName))

        // add details
        attackDetails.Details
        |> Seq.iter(fun kv -> securityIssue.Details.Properties.Add(kv.Key, kv.Value))

        this.Context.Value.AddSecurityIssue(securityIssue)
            
    let test(parameter: ProbeParameter, probeRequest: ProbeRequest) =
        let mutable isVulnerable = false
        if isParameterSafeToTest(parameter) then
            for checker in _checkers do
                if not isVulnerable then
                    let result = checker.Test(parameter, probeRequest)
                    if result.Success then
                        isVulnerable <- true

                        // set this parameter as vulnerable to avoid further tests
                        lock _analyzedParameters (fun _ ->
                            let path = probeRequest.TestRequest.WebRequest.HttpRequest.Uri.AbsolutePath
                            if not <| _vulnerableParameters.ContainsKey(path) then
                                _vulnerableParameters.Add(path, new List<String>())
                            _vulnerableParameters.[path].Add(parameter.Name)
                        )

                        let entryPoint =
                            match parameter.Type with
                            | QUERY -> EntryPoint.QueryString
                            | DATA -> EntryPoint.DataString
                            | HEADER -> EntryPoint.Header
                        reportSecurityIssue(probeRequest.TestRequest.WebRequest.HttpRequest.Uri, entryPoint, checker, result.Details.Value)
        isVulnerable

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
        for tmpParameter in parameters do            
            let mutable parameter = tmpParameter
            if rebuild then
                // re-try by rebuilding the request from the referer, this can be useful if there are anti-CSRF token
                probeRequest <- new ProbeRequest(this.RebuildTestRequestFromReferer(testRequest))
                match probeRequest.GetParameters() |> Seq.tryFind(fun p -> p.Name.Equals(parameter.Name, StringComparison.Ordinal)) with
                | Some newParam -> parameter <- newParam
                | _ -> ()

            probeRequest.SaveState()
            let mutable isTestVulnerable = test(parameter, probeRequest)            
            probeRequest.RestoreState()

            // check for file parameter
            match parameter.Filename with
            | Some filename -> 
                probeRequest.SaveState()
                parameter.AlterValue <- (fun x -> parameter.Filename <- Some x)
                isTestVulnerable <- test(parameter, probeRequest)
                probeRequest.RestoreState()
            | _ -> ()

            if isTestVulnerable then
                // this code is necessary in order to update the list of analyzed parameters
                lock _analyzedParameters (fun _ ->                     
                    isRequestOkToAnalyze(tmpParameter, probeRequest, not rebuild) |> ignore
                )

            testWithRebuild <- testWithRebuild || (not isTestVulnerable && testRequest.WebRequest.HttpRequest.Method = HttpMethods.Post)
        
        testWithRebuild
        
    default this.Initialize(context: Context, webRequestor: IWebPageRequestor, messageBroker: IMessageBroker, logProvider: ILogProvider) =
        base.Initialize(context, webRequestor, messageBroker, logProvider) |> ignore
        
        let errors =
            match this.Context.Value.AddOnStorage.ReadProperty<Dictionary<String, List<String>>>("Errors") with
            | Some errors -> errors
            | None -> new Dictionary<String, List<String>>()

        // verify if some of these addOn should be deactivated
        let settingsMsg = new InspectorSettingsMessage()
        messageBroker.Dispatch(this, settingsMsg)
        
        // create checkers
        _checkers <-
            [new ErrorBasedSqliChecker(webRequestor, errors, logProvider) :> ISqliChecker; new BlindSqliChecker(webRequestor, logProvider) :> ISqliChecker]
            |> List.filter(fun checker ->
                settingsMsg.Settings.Value.ActivateAllAddOns || settingsMsg.Settings.Value.AddOnIdsToActivate.Contains(checker.VulnId)
            )

        _checkers.Length > 0
                        
    default this.Scan(testRequest: TestRequest, stateController: ServiceStateController) =        
        if not <| scan(testRequest, stateController, false) then
            // test with rebuild, since there are POST parameters that are not vulnerable, maybe they are not due to CSRF token?
            scan(testRequest, stateController, true) |> ignore