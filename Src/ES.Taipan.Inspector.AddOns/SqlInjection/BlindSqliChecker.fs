namespace ES.Taipan.Inspector.AddOns.SqlInjection

open System
open System.Collections.Generic
open ES.Fslog
open ES.Taipan.Inspector
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Infrastructure.Text

type BlindSqliChecker(webRequestor: IWebPageRequestor, logProvider: ILogProvider) =
    
    [<Literal>]
    static let RatioThreshold = 0.85

    let _rnd = new Random()
    let _log = 
        log "BlindSqliChecker"        
        |> verbose "FoundSqlInjection" "Identified Blind SQL Injection on path '{0}', parameter: {1}"
        |> verbose "TestFor" "Blind test '{0}' on request: {1}"
        |> warning "TooDynamic" "Parameter '{0}' in page '{1}' is too dynamic to test for blind sql injection"
        |> warning "PageChangeAccordingToValue" "The web page '{0}' change content according to the parameter '{1}' value, unable to test"
        |> build    
    do logProvider.AddLogSourceToLoggers(_log)
    
    let _queries = [
        ("' OR '{0}", "' AND '0")
        ("' OR '{0}' = '{0}", "' AND '{0}' = '{1}")
        (" OR {0} = {0}", " AND {0} = {1}")
    ]
    
    let getQueries() = [        
        for (trueQueryTemplate, falseQueryTemplate) in _queries do
            let trueRandomNum = _rnd.Next(2, 50)
            let falseRandomNum = _rnd.Next(100, 150)

            let trueQuery = String.Format(trueQueryTemplate, trueRandomNum)
            let falseQuery = String.Format(falseQueryTemplate, trueRandomNum, falseRandomNum)
            yield (trueQuery, falseQuery)
    ]

    let testForQuery(parameter: ProbeParameter, query: String, probeRequest: ProbeRequest) =        
        let originalValue = parameter.Value
        parameter.AlterValue(query)

        probeRequest.EnsureConsistencyOnPasswordTypeParameter(parameter)

        let webRequest = new WebRequest(probeRequest.BuildHttpRequest(true))
        let webResponse = webRequestor.RequestWebPage(webRequest)
        parameter.AlterValue(originalValue)  
        (webRequest, webResponse)  

    let testProbeRequest(parameter: ProbeParameter, trueQuery: String, falseQuery: String, probeRequest: ProbeRequest, ratio: Double) =
        let mutable result: AttackDetails option = None

        let (trueWebRequest, trueWebResponse) = testForQuery(parameter, trueQuery, probeRequest)
        let (falseWebRequest, falseWebResponse) = testForQuery(parameter, falseQuery, probeRequest)
                        
        // verify result
        if box(trueWebResponse.HttpResponse) <> null && box(falseWebResponse.HttpResponse) <> null then
            probeRequest.WebResponse <- Some trueWebResponse
            let attackRatio = TextUtility.computeDifferenceRatio(trueWebResponse.HttpResponse.Html, falseWebResponse.HttpResponse.Html)

            if attackRatio < ratio then
                result <- Some {
                    ParameterName = parameter.Name
                    Requests = [trueWebRequest; falseWebRequest]
                    Responses = [trueWebResponse; falseWebResponse]
                    Details = new Dictionary<String, String>()
                }
                                
                // add details related to blind sql injection
                result.Value.Details.Add("TrueQuery", trueQuery)
                result.Value.Details.Add("FalseQuery", falseQuery)
                result.Value.Details.Add("TrueHtml", trueWebResponse.HttpResponse.Html)
                result.Value.Details.Add("FalseHtml", falseWebResponse.HttpResponse.Html)

                _log?FoundSqlInjection(probeRequest.TestRequest.WebRequest.HttpRequest.Uri.AbsolutePath, parameter.Name)                            
                            
        result

    let isPageContentIndependentFromParameterValue(parameter: ProbeParameter, probeRequest: ProbeRequest) =
        let originalHtml = probeRequest.TestRequest.WebResponse.HttpResponse.Html

        // send a request with a random value
        let originalValue = parameter.Value
        parameter.AlterValue(Guid.NewGuid().ToString("N"))
        let webRequest = new WebRequest(probeRequest.BuildHttpRequest(true))
        let webResponse = webRequestor.RequestWebPage(webRequest)
        parameter.AlterValue(originalValue)  
        let alteredHtml = webResponse.HttpResponse.Html

        let ratio = TextUtility.computeDifferenceRatio(originalHtml, alteredHtml)
        ratio >= RatioThreshold
                
    member this.VulnName 
        with get() = "Blind SQL Injection"

    static member Id = Guid.Parse("1DF114E2-FE1E-44CF-8CB2-612B7CFF62B1")

    member this.VulnId 
        with get() = BlindSqliChecker.Id
        
    member this.Test(parameter: ProbeParameter, probeRequest: ProbeRequest) =
        let mutable result = CheckResult.NotVulnerable
        _log?TestFor(parameter, probeRequest.TestRequest.WebRequest)

        let newResponse = webRequestor.RequestWebPage(probeRequest.TestRequest.WebRequest)
        if box(newResponse.HttpResponse) <> null && not(String.IsNullOrEmpty(newResponse.HttpResponse.Html)) then            
            // verify that the page is stable
            let ratio = TextUtility.computeDifferenceRatio(probeRequest.TestRequest.WebResponse.HttpResponse.Html, newResponse.HttpResponse.Html)

            if ratio < RatioThreshold then
                if parameter.Type = ProbeParameterType.DATA || parameter.Type = ProbeParameterType.QUERY
                then _log?TooDynamic(parameter, probeRequest)
            elif isPageContentIndependentFromParameterValue(parameter, probeRequest) then
                // execute single test
                getQueries()
                |> Seq.iter(fun (trueQuery, falseQuery) ->
                    if not result.Success then
                        match testProbeRequest(parameter, trueQuery, falseQuery, probeRequest, ratio) with
                        | Some attackDetails ->
                            result <- {
                                Success = true
                                Details = Some attackDetails
                            }
                        | None -> ()
                )
            else
                _log?PageChangeAccordingToValue(probeRequest.TestRequest.WebRequest.HttpRequest.Uri.AbsoluteUri, parameter.Name)

        result

    interface ISqliChecker with
        member this.Test(parameter: ProbeParameter, probeRequest: ProbeRequest) =
            this.Test(parameter, probeRequest)

        member this.VulnName 
            with get() = this.VulnName

        member this.VulnId 
            with get() = this.VulnId
