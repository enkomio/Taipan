namespace ES.Taipan.Inspector.AddOns.WebFormBruteforcer

open System 
open ES.Taipan.Inspector
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Crawler
open ES.Taipan.Infrastructure.Text

module internal BruteforceHelper =
    let private sendRequest(webRequest: WebRequest, webRequestor: IWebPageRequestor) =
        webRequest.HttpRequest.AllowAutoRedirect <- Some false
        webRequestor.RequestWebPage(webRequest)

    let sendProbe(testRequest: TestRequest, usernameInputs: String list, passwordInputs: String list, username: String, password: String, webRequestor: IWebPageRequestor)=
        // create the probe request and set each input password and username            
        let probeRequest = new ProbeRequest(testRequest)
        probeRequest.GetParameters()
        |> Seq.filter(fun parameter -> parameter.Type = ProbeParameterType.DATA || parameter.Type = ProbeParameterType.QUERY)
        |> Seq.iter(fun parameter ->
            if usernameInputs |> List.contains(parameter.Name) then
                parameter.AlterValue(username)
                parameter.IsUnderTest <- true
            elif passwordInputs |> List.contains(parameter.Name) then
                parameter.AlterValue(password)
                parameter.IsUnderTest <- true
        )

        // send the probe
        let webRequest = new WebRequest(probeRequest.BuildHttpRequest(true))
        probeRequest.WebResponse <- Some <| sendRequest(webRequest, webRequestor)
        (webRequest, probeRequest.WebResponse.Value)

    let getUsernameandPasswordInputs(testRequest: TestRequest) =
        // get all inputs that are password and (possible) username types
        let webLink = testRequest.GetData<WebLink>()
        let inputs = RegexUtility.getAllHtmlTagsWithName(webLink.ParsedHtmlCode, "input")
        let passwordInputs = 
            inputs 
            |> Seq.filter(fun input -> 
                RegexUtility
                    .getHtmlInputValue(input, "type")
                    .Equals("password", StringComparison.OrdinalIgnoreCase)
            )
            |> Seq.map(fun html -> RegexUtility.getHtmlInputValue(html, "name"))
            |> Seq.toList

        let usernameInputs = 
            inputs 
            |> Seq.filter(fun input -> 
                let name = RegexUtility.getHtmlInputValue(input, "name").ToLower()
                [
                    "username"; "usrn"; "user"; "login"; "email"
                ] |> List.exists(name.Contains)
            )
            |> Seq.map(fun html -> RegexUtility.getHtmlInputValue(html, "name"))
            |> Seq.toList

        (usernameInputs, passwordInputs)