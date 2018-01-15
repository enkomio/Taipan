namespace ES.Taipan.Crawler.WebScrapers

open System
open System.Text
open System.Collections.Generic
open System.Text.RegularExpressions
open System.ComponentModel.Composition
open System.ComponentModel.Composition.Hosting
open ES.Taipan.Crawler
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Infrastructure.Text
open ES.Taipan.Infrastructure.Messaging
open ES.Fslog

module FormLinkScraperUtility =    
    let createMultipartDataString(parameters: (String option * String option * String) seq) =
        let dataString = new StringBuilder()
        let boundary = "---------------------------" + Guid.NewGuid().ToString("N")
        let encType = "multipart/form-data; boundary=" + boundary

        parameters
        |> Seq.iter(fun (encTypeOpt, fileNameParameter, rawParameter) ->
            let (paramName, paramValue) =
                let indexOfEqual = rawParameter.IndexOf('=')
                if indexOfEqual >= 0 then
                    (System.Net.WebUtility.HtmlDecode(rawParameter.Substring(0, indexOfEqual)), System.Net.WebUtility.HtmlDecode(rawParameter.Substring(indexOfEqual + 1)))
                else
                    (System.Net.WebUtility.HtmlDecode(rawParameter), String.Empty)

            dataString.Append(boundary).Append("\r\n") |> ignore

            match encTypeOpt with
            | Some encType when encType.Trim().Equals("file", StringComparison.OrdinalIgnoreCase) ->                
                dataString.Append(String.Format("Content-Disposition: form-data; name=\"{0}\"; filename=\"{1}\"", paramName, defaultArg fileNameParameter String.Empty)).Append("\r\n") |> ignore
                dataString.Append("Content-Type: text/plain").Append("\r\n\r\n") |> ignore
                    
                // add some bogus content
                dataString.Append(Guid.NewGuid().ToString()).Append("\r\n") |> ignore
            | _ ->
                dataString.Append(String.Format("Content-Disposition: form-data; name=\"{0}\"", paramName)).Append("\r\n\r\n") |> ignore
                dataString.Append(paramValue).Append("\r\n") |> ignore
        )

        if dataString.Length > 0 then (encType, dataString.ToString() + boundary + "--")
        else (encType, String.Empty)

[<InheritedExport(typeof<ICrawlerAddOn>)>]
type FormLinkScraper() = 

    let combineValues (listOfList: _ list list) =
        let indexArray = Array.zeroCreate(listOfList.Length)

        let rec combineValuesImpl (listOfList: _ list list) (listIndex: Int32 list) (currentScannedListIndex: Int32) = 
            seq {
                let currentScannedListOverflow =
                    let currentList = listOfList.[currentScannedListIndex]
                    if listIndex.[currentScannedListIndex] >= currentList.Length  then true
                    else false
                
                if currentScannedListOverflow then
                    // update the indexs           
                    let newListIndex = Array.copy(listIndex |> Array.ofList)     
                    newListIndex.[currentScannedListIndex] <- newListIndex.[currentScannedListIndex] + 1

                    // zeroes the previous index
                    for i in [0 .. currentScannedListIndex] do                        
                        newListIndex.[i] <- 0

                    // update the next list index
                    let updateNextIndex = ref true
                    for i in [currentScannedListIndex+1 .. listIndex.Length-1] do
                        if !updateNextIndex then
                            let li = listIndex.[i] + 1
                            if li >= listOfList.[i].Length then
                                newListIndex.[i] <- 0
                            else 
                                newListIndex.[i] <- li
                                updateNextIndex := false

                    if not(!updateNextIndex) then
                        yield! combineValuesImpl listOfList (newListIndex |> List.ofSeq) 0
                else
                    // calculate value
                    let newCombination = Array.zeroCreate<_>(listOfList.Length)
                    for i in [0..listOfList.Length-1] do
                        let listValIndex = listIndex.[i]
                        let listVal = listOfList.[i].[listValIndex]
                        newCombination.[i] <- listVal
                    yield newCombination
                    
                    // update the indexs           
                    let newListIndex = Array.copy(listIndex |> Array.ofList)     
                    newListIndex.[currentScannedListIndex] <- newListIndex.[currentScannedListIndex] + 1

                    // iterate
                    yield! combineValuesImpl listOfList (newListIndex |> List.ofSeq) currentScannedListIndex
            }

        combineValuesImpl listOfList (indexArray |> List.ofArray) 0

    let retrieveAllCheckBoxValuesInput(formBody: String) =
        [
            let inputs = new Dictionary<String, List<String>>()

            let inputRegex = new Regex(@"<input(.*?)(>|/>)", RegexOptions.Singleline ||| RegexOptions.Multiline ||| RegexOptions.IgnoreCase)
            let inputRegexMatch = ref <| inputRegex.Match(formBody)

            // for each radiobox input return a formatted string "name=value"
            while (!inputRegexMatch).Success do
                let inputTagHead = (!inputRegexMatch).Groups.[1].Value
                let name = RegexUtility.getHtmlAttributeValueFromChunk(inputTagHead, @"name")
                let value = RegexUtility.getHtmlAttributeValueFromChunk(inputTagHead, @"value")
                let inputType = RegexUtility.getHtmlAttributeValueFromChunk(inputTagHead, @"type")
                inputRegexMatch := (!inputRegexMatch).NextMatch()

                let isCheckboxInput =
                    if inputType.IsSome then inputType.Value.Trim().Equals("checkbox", StringComparison.OrdinalIgnoreCase)
                    else false

                if isCheckboxInput && name.IsSome then                
                    // return a request with empty string meaning that the checkvalue isn't setted
                    yield String.Empty    
                    // return a request with the checkbox value setted
                    if value.IsSome then
                        yield String.Format("{0}={1}", name.Value, value.Value)
        ]

    let retrieveAllRadioBoxValuesInput(formBody: String) =
        let inputs = new Dictionary<String, List<String>>()

        let inputRegex = new Regex(@"<input(.*?)(>|/>)", RegexOptions.Singleline ||| RegexOptions.Multiline ||| RegexOptions.IgnoreCase)
        let inputRegexMatch = ref <| inputRegex.Match(formBody)

        // for each radiobox input return a formatted string "name=value"
        while (!inputRegexMatch).Success do
            let inputTagHead = (!inputRegexMatch).Groups.[1].Value
            let name = RegexUtility.getHtmlAttributeValueFromChunk(inputTagHead, @"name")
            let value = RegexUtility.getHtmlAttributeValueFromChunk(inputTagHead, @"value")
            let inputType = RegexUtility.getHtmlAttributeValueFromChunk(inputTagHead, @"type")
            inputRegexMatch := (!inputRegexMatch).NextMatch()

            let isRadioInput =
                if inputType.IsSome then inputType.Value.Trim().Equals("radio", StringComparison.OrdinalIgnoreCase)
                else false

            if isRadioInput && name.IsSome then
                if not <| inputs.ContainsKey(name.Value) then 
                    inputs.Add(name.Value, new List<String>())
                inputs.[name.Value].Add(if value.IsSome then value.Value else String.Empty)
        [
            for kv in inputs do
                let name = kv.Key
                let values = kv.Value

                for value in values do
                    if not <| String.IsNullOrWhiteSpace(value) then
                        yield String.Format("{0}={1}", name.Trim(), value)
                    else
                        yield name
        ]

    let retrieveAllSelectValuesInput(formBody: String) =
        let inputs = new Dictionary<String, List<String>>()

        let selectRegex = new Regex(@"<select(.*?)>(.*?)</select>", RegexOptions.Singleline ||| RegexOptions.Multiline ||| RegexOptions.IgnoreCase)
        let selectRegexMatch = ref <| selectRegex.Match(formBody)

        // for each input return a formatted parameter/value
        while (!selectRegexMatch).Success do
            let selectTagHead = (!selectRegexMatch).Groups.[1].Value
            let selectTagBody = (!selectRegexMatch).Groups.[2].Value
            selectRegexMatch := (!selectRegexMatch).NextMatch()
            let paramName = RegexUtility.getHtmlAttributeValueFromChunk(selectTagHead, @"name")

            if paramName.IsSome then
                if not <| inputs.ContainsKey(paramName.Value) then inputs.Add(paramName.Value.Trim(), new List<String>())

                // retrieve all option values
                let optionRegex = new Regex(@"<option(.*?)(>|/>)", RegexOptions.Singleline ||| RegexOptions.Multiline ||| RegexOptions.IgnoreCase)
                let optionRegexMatch = ref <| optionRegex.Match(selectTagBody)

                while (!optionRegexMatch).Success do
                    let optionTagHead = (!optionRegexMatch).Groups.[1].Value
                    optionRegexMatch := (!optionRegexMatch).NextMatch()
                    let optionValue = RegexUtility.getHtmlAttributeValueFromChunk(optionTagHead, @"value")

                    if optionValue.IsSome then 
                        inputs.[paramName.Value].Add(optionValue.Value)
        
        // return the found values as a formatted string "name=value"
        [
            for kv in inputs do
                let name = kv.Key
                let values = kv.Value

                for value in values do
                    if not <| String.IsNullOrWhiteSpace(value) then
                        yield String.Format("{0}={1}", name.Trim(), value)
                    else
                        yield name
        ]

    let retrieveAllSingleValuelInput(formBody: String) =
        [
            let inputRegex = new Regex(@"<(input|textarea|button)(.*?)(>|/>)", RegexOptions.Singleline ||| RegexOptions.Multiline ||| RegexOptions.IgnoreCase)
            let inputRegexMatch = ref <| inputRegex.Match(formBody)

            // for each input return a formatted string "name=value"
            while (!inputRegexMatch).Success do
                let inputTagHead = (!inputRegexMatch).Groups.[2].Value
                let name = RegexUtility.getHtmlAttributeValueFromChunk(inputTagHead, @"name")
                let value = RegexUtility.getHtmlAttributeValueFromChunk(inputTagHead, @"value")
                let inputType = RegexUtility.getHtmlAttributeValueFromChunk(inputTagHead, @"type")
                inputRegexMatch := (!inputRegexMatch).NextMatch()
                
                let isRadioInput =
                    if inputType.IsSome then inputType.Value.Trim().Equals("radio", StringComparison.OrdinalIgnoreCase)
                    else false

                let isCheckboxInput =
                    if inputType.IsSome then inputType.Value.Trim().Equals("checkbox", StringComparison.OrdinalIgnoreCase)
                    else false
                                        
                if name.IsSome && not isRadioInput && not isCheckboxInput then
                    if value.IsSome then
                        yield (inputType, None, String.Format("{0}={1}", name.Value.Trim(), value.Value))
                    else
                        yield (inputType, None, name.Value.Trim())
        ]

    let createDataString(parameters: HashSet<String option * String option * String>, encType: String) =
        let dataString = new StringBuilder()
        let mutable effectiveEncType = encType
        
        if encType.Equals("multipart/form-data", StringComparison.OrdinalIgnoreCase) then
            FormLinkScraperUtility.createMultipartDataString(parameters)
        else
            parameters
            |> Seq.iter(fun (_, _, rawParameter) ->
                let parameter = System.Net.WebUtility.HtmlDecode(rawParameter)
                let items = parameter.Split('=')
                let (parameterName, parameterValue) = (items.[0], String.Join("=", items.[1..]))
                
                let encodeContent(content: String) =
                    match encType.ToLower() with                    
                    | "application/x-www-form-urlencoded" -> System.Net.WebUtility.UrlEncode(content)
                    | "text/plain" -> content.Replace(' ', '+')
                    | _ -> content

                let encodedValue = String.Format("{0}={1}", encodeContent(parameterName), encodeContent(parameterValue))
                dataString.Append('&').Append(encodedValue) |> ignore
            )

            if dataString.Length > 0 then (effectiveEncType, dataString.ToString().Substring(1))
            else (effectiveEncType, String.Empty)

    member this.Name = "Form scraper AddOn"
    static member AddOnId = Guid.Parse("E3EDF40E-BB96-4E99-B53B-8FC3D5DAA136")
    member this.Id = FormLinkScraper.AddOnId
    member this.Priority = 3

    member this.DiscoverNewLinks(sourceWebLink: WebLink, webResponse: WebResponse, logProvider: ILogProvider) =
        let identifiedLinks = new List<WebLink>()

        if isValidContentType(webResponse) then
            let cleanHtml = 
                RegexUtility.removeHtmlComments(webResponse.HttpResponse.Html)
                |> fun (html, _) -> RegexUtility.removeScriptContent(html)
                |> fun (html, _) -> html

            let formRegex = new Regex(@"<form(.*?)>(.*?)</form>", RegexOptions.Singleline ||| RegexOptions.Multiline ||| RegexOptions.IgnoreCase)
            let mutable formRegexMatch = formRegex.Match(cleanHtml)

            // for each form found create a new link
            while formRegexMatch.Success do
                let matchText = formRegexMatch.Groups.[0].Value
                let formTagHead = formRegexMatch.Groups.[1].Value
                let formTagBody = formRegexMatch.Groups.[2].Value
                formRegexMatch <- formRegexMatch.NextMatch()

                // retrieve form uri and method
                let formMethod = RegexUtility.getHtmlAttributeValueFromChunk(formTagHead, @"method")
                let formAction = RegexUtility.getHtmlAttributeValueFromChunk(formTagHead, @"action")
                let mutable encodingType = 
                    match RegexUtility.getHtmlAttributeValueFromChunk(formTagHead, @"enctype") with
                    | Some v -> v
                    | None -> "application/x-www-form-urlencoded"

                // retrieve all input
                let singleValueInputList = retrieveAllSingleValuelInput(formTagBody)

                // check if some of the input is of type file, if so change the encoding-type
                if 
                    (singleValueInputList 
                    |> List.exists(fun (encTypeOpt, _, _) -> encTypeOpt.IsSome && encTypeOpt.Value.Trim().Equals("file", StringComparison.OrdinalIgnoreCase)))
                then                    
                    encodingType <- "multipart/form-data"
                
                // create the template http request
                let linkFound = 
                    if formAction.IsSome then formAction.Value 
                    else sourceWebLink.Request.HttpRequest.Uri.AbsoluteUri

                let linkMethod =
                    if formMethod.IsSome then
                        match formMethod.Value.ToUpper().Trim() with
                        | "POST" -> HttpMethods.Post
                        | "GET" -> HttpMethods.Get
                        | c -> HttpMethods.Custom c
                    else
                        HttpMethods.Get
                
                let sourceAbsoluteUri = sourceWebLink.Request.HttpRequest.Uri.AbsoluteUri
                let absoluteUriStringOpt = WebUtility.getAbsoluteUriStringValueSameHost(sourceAbsoluteUri, linkFound)

                if absoluteUriStringOpt.IsSome then                    
                    // create the links of the multivalue input like select and radiobox
                    let selectInputs = retrieveAllSelectValuesInput(formTagBody)
                    let radioBoxInputs = retrieveAllRadioBoxValuesInput(formTagBody)
                    let checkBoxInputs = retrieveAllCheckBoxValuesInput(formTagBody)
                                       
                    // create all the combined data strings possible
                    let parameters = new HashSet<String option * String option * String>()

                    // add input parameters
                    singleValueInputList |> List.iter(fun v -> parameters.Add(v) |> ignore)

                    let notEmptyLists = 
                        [selectInputs; radioBoxInputs; checkBoxInputs]
                        |> List.filter (List.isEmpty >> not)

                    let allCombinedInputs =
                        if notEmptyLists.IsEmpty then Seq.empty
                        else combineValues notEmptyLists

                    let requestDatas = new List<String * String>()

                    // all items in the combined input is a different request
                    if allCombinedInputs |> Seq.length > 0 then      
                        for dataArray in allCombinedInputs do
                            let tmpParameters = new HashSet<String option * String option * String>(parameters)

                            for dataArrayVal in dataArray do
                                if not <| String.IsNullOrWhiteSpace(dataArrayVal) then
                                    tmpParameters.Add((None, None, dataArrayVal)) |> ignore

                            let (effectiveContentType, dataString) = createDataString(tmpParameters, encodingType)
                            requestDatas.Add(effectiveContentType, dataString)
                    else
                        let (effectiveContentType, dataString) = createDataString(parameters, encodingType)
                        requestDatas.Add(effectiveContentType, dataString)
                    
                    // create the effective requests
                    for (effectiveContentType, dataString) in requestDatas do
                        let newWebRequest = new WebRequest(new Uri(absoluteUriStringOpt.Value))
                        newWebRequest.HttpRequest.Headers.Add(new HttpHeader(Name = "Referer", Value = sourceWebLink.Request.HttpRequest.Uri.AbsoluteUri))
                        newWebRequest.HttpRequest.Method <- linkMethod

                        match linkMethod with
                        | HttpMethods.Get -> 
                            let uriBuilder = new UriBuilder(newWebRequest.HttpRequest.Uri)
                            uriBuilder.Query <- dataString
                            newWebRequest.HttpRequest.Uri <- uriBuilder.Uri
                        | HttpMethods.Post -> 
                            newWebRequest.HttpRequest.Data <- dataString
                            newWebRequest.HttpRequest.Headers.Add(new HttpHeader(Name="Content-Type", Value=effectiveContentType))
                        | _ -> ()

                        let newWebLink = new WebLink(newWebRequest, matchText, sourceWebLink.SessionId)
                        identifiedLinks.Add(newWebLink)
                    
        identifiedLinks

    interface ICrawlerAddOn with
        member this.Name 
            with get() = this.Name

        member this.Id
            with get() = this.Id
            
        member this.Priority
            with get() = this.Priority

        member this.DiscoverNewLinks(sourceWebLink: WebLink, webResponse: WebResponse, messageBroker: IMessageBroker, logProvider: ILogProvider) =
            upcast this.DiscoverNewLinks(sourceWebLink, webResponse, logProvider)



