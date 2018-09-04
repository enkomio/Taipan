namespace ES.Taipan.Inspector.AddOns.SqlInjection

open System
open System.Collections.Generic
open System.Text.RegularExpressions
open ES.Fslog
open ES.Taipan.Inspector
open ES.Taipan.Infrastructure.Network

type ErrorBasedSqliChecker(webRequestor: IWebPageRequestor, errors: Dictionary<String, List<String>>, logProvider: ILogProvider) =
    let _log = 
        log "ErrorBasedSqliChecker"        
        |> verbose "FoundSqlInjection" "Identified Error Based SQL Injection on path '{0}', parameter: {1}, attack string: {2}, db: {3}, error: {4}"
        |> build
    do logProvider.AddLogSourceToLoggers(_log)

    let _triggeringPayloads = [
        "'"
        "\""
        "--"
        ";"
        "`"
        ")"
    ]

    let testProbeRequest(parameter: ProbeParameter, payload: String, probeRequest: ProbeRequest) =
        let mutable result: AttackDetails option = None
        
        // send attack vetor
        let originalValue = parameter.Value
        parameter.AlterValue(parameter.Value + payload)
        
        probeRequest.EnsureConsistencyOnPasswordTypeParameter(parameter)

        let webRequest = new WebRequest(probeRequest.BuildHttpRequest(true))
        let webResponse = webRequestor.RequestWebPage(webRequest)        
                
        // verify result
        if box(webResponse.HttpResponse) <> null then
            probeRequest.WebResponse <- Some webResponse
            let html = webResponse.HttpResponse.Html
            for kv in errors do
                let (dbName, dbErrors) = (kv.Key, kv.Value |> Seq.toList)
                for dbError in dbErrors do
                    if result.IsNone then
                        let m = Regex.Match(html, dbError, RegexOptions.Singleline)
                        if m.Success then
                            result <- Some {
                                ParameterName = parameter.Name
                                Requests = [webRequest]
                                Responses = [webResponse]
                                Details = new Dictionary<String, String>()
                            }

                            // add details related to error sql injection
                            result.Value.Details.Add("Attack", parameter.Value)
                            result.Value.Details.Add("Database", dbName)
                            result.Value.Details.Add("Payload", payload)
                            result.Value.Details.Add("Error", m.Groups.[0].Value)

                            _log?FoundSqlInjection(probeRequest.TestRequest.WebRequest.HttpRequest.Uri.AbsolutePath, parameter.Name, payload, dbName, dbError)
                            
        parameter.AlterValue(originalValue)
        result
        
    member this.VulnName 
        with get() = "SQL Injection Error Based"

    static member Id = Guid.Parse("7B55A85D-3CA6-492D-8D07-7B35A12CCEF3")

    member this.VulnId 
        with get() = ErrorBasedSqliChecker.Id
                
    member this.Test(parameter: ProbeParameter, probeRequest: ProbeRequest) =
        let mutable result = CheckResult.NotVulnerable
        for payload in _triggeringPayloads do
            if not result.Success then
                match testProbeRequest(parameter, payload, probeRequest) with
                | Some attackDetails ->
                    result <- {
                        Success = true
                        Details = Some attackDetails
                    }
                | None -> ()
        result

    interface ISqliChecker with
        member this.Test(parameter: ProbeParameter, probeRequest: ProbeRequest) =
            this.Test(parameter, probeRequest)

        member this.VulnName 
            with get() = this.VulnName

        member this.VulnId 
            with get() = this.VulnId
