namespace ES.Taipan.Infrastructure.Network

open System
open System.Text.RegularExpressions
open System.IO
open System.Linq
open System.Collections.Generic
open System.Net

module HeuristicHelpers =
    let tokenize(txt: String) =
        let toLower = txt.ToLower()
        let cleanString = Regex.Replace(toLower, "([^a-z])+", " ", RegexOptions.Singleline)
        let uniqueWords = new HashSet<String>()
        cleanString.Split([|" "|], StringSplitOptions.RemoveEmptyEntries) 
        |> Seq.filter(fun w -> w.Length > 5)
        |> Seq.iter(fun w -> uniqueWords.Add(w) |> ignore)
        uniqueWords |> Seq.toList

    let matchWordsLength(htmls: List<String list>, htmlToCheckTokens: String list, percentageOfHtmlSimilarity: Double) =
        htmls
        |> Seq.exists(fun htmlTokens -> 
            let lenDifference = Math.Abs(htmlTokens.Length - htmlToCheckTokens.Length)
            
            // if the number of words is too different between the two strings, then 
            // they are considered NOT equals. In order to be considered equals the len 
            // percentage should be near zero.
            let differencePercentage = 1. - float(lenDifference) / float(htmlTokens.Length)
            differencePercentage > percentageOfHtmlSimilarity
        )

    // return true if the page match a not existent page
    let htmlMatch(htmls: List<String list>, htmlToCheckTokens: String list, percentageOfHtmlSimilarity: Double) =        
        let htmlToCheckTokensSet = htmlToCheckTokens |> Set.ofList
        htmls
        |> Seq.exists(fun htmlTokens ->
            // This check is based on the fact that if the text has in common many words with that of
            // an un-existent page, than the page is considered not found.
            // Leviathan was too inefficient.
            let intersectNotExistingWords = Set.intersect (htmlTokens |> Set.ofSeq) htmlToCheckTokensSet
            let percentageOfWordsFound = float(intersectNotExistingWords.Count) / float(htmlTokens.Length)
            percentageOfWordsFound > percentageOfHtmlSimilarity
        )

type HeuristicPageNotFoundIdentifier(httpRequestor: IHttpRequestor, percentageOfHtmlSimilarity: Double) =
    let _syncRoot = new Object()
    let _storedHeuristics = new Dictionary<String, HttpRequest * HttpResponse -> Boolean>()

    let cleanUri(uri: Uri, location: String) =
        let page = HttpUtility.getPage(uri)
        if not <| String.IsNullOrWhiteSpace(page) then
            location.Replace(page, String.Empty)
        else
            // maybe is a directory
            if location.EndsWith("/") then
                let lastDir = HttpUtility.getPage(new Uri(uri.AbsoluteUri.Substring(0, uri.AbsoluteUri.Length - 1))) + "/"
                location.Replace(lastDir, String.Empty)
            else
                location

    let verifyIfRedirectDueToNotExistance(httpRequest: HttpRequest, httpResponse: HttpResponse, redirects: IEnumerable<String>) =
        let statusCode = httpResponse.StatusCode
        let mutable result = false
        
        if HttpUtility.isRedirect(statusCode) then
            let locationHeader = httpResponse.Headers.FirstOrDefault(fun hdr -> hdr.Name.Equals("Location", StringComparison.OrdinalIgnoreCase))
            if box(locationHeader) <> null then        
                // remove the page because sometimes is copied in the redirection url
                let redirectionUrl = cleanUri(httpRequest.Uri, locationHeader.Value)
                result <- redirects.Contains(redirectionUrl)
        
        result

    let matchUnexistendContentLength(lenghts: HashSet<Int32>, lenToCheck: Int32) =
        lenghts
        |> Seq.contains(lenToCheck)

    let matchNotExistentContentType(headers: HttpHeader seq, contentTypes: HashSet<String>) =
        match HttpUtility.tryGetHeader("Content-Type", headers) with
        | Some header -> contentTypes.Contains(header.Value)
        | _ -> false

    // return true if the status code match that of an un-existent page
    let statusCodeIsEqualsForAll(statusCodeNotExistingPages: List<HttpStatusCode>, responseStatusCode: HttpStatusCode) =
        if int32 responseStatusCode >= 400 && statusCodeNotExistingPages.Any() then
            statusCodeNotExistingPages |> Seq.forall((=) responseStatusCode)
        else false

    let getInexistentPageTemplates(uri: Uri) = [
        let mutable extension = Path.GetExtension(uri.AbsolutePath)        
        if String.IsNullOrWhiteSpace(extension) || not([".php"; ".jsp"; ".do"; ".asp"; ".aspx"].Contains(extension)) then
            extension <- ".fakeextension"
            
        for i=0 to 3 do
            yield! [
                extension
                Guid.NewGuid().ToString("N")
                Guid.NewGuid().ToString("N") + ".ini"
                Guid.NewGuid().ToString("N") + ".txt"                
                Guid.NewGuid().ToString("N") + extension
                Guid.NewGuid().ToString("N") + "/"
                "%" + Guid.NewGuid().ToString("N") + "%"                
            ]
    ]

    let generateHeuristic(uri: Uri, httpResponse: HttpResponse) =
        let htmls = new List<String list>()
        let statusCodes = new List<HttpStatusCode>()
        let contentTypes = new HashSet<String>()
        let htmlLengths = new HashSet<Int32>()
        let redirects = new HashSet<String>()

        for page in getInexistentPageTemplates(uri) do
            let newUri = new Uri(uri, page)
            let response = httpRequestor.SendRequest(new HttpRequest(newUri))
            if response.IsSome then
                htmls.Add(HeuristicHelpers.tokenize(response.Value.Html))
                htmlLengths.Add(response.Value.Html.Length) |> ignore
                match HttpUtility.tryGetHeader("Content-Type", response.Value.Headers) with
                | Some header -> contentTypes.Add(header.Value) |> ignore
                | _ -> ()

                if response.Value.StatusCode <> HttpStatusCode.NotFound then
                    // it is a custom not found status code
                    statusCodes.Add(response.Value.StatusCode)
                
                // if redirect get the redirect url
                if HttpUtility.isRedirect(response.Value.StatusCode) then
                    let locationHeader = response.Value.Headers.FirstOrDefault(fun hdr -> hdr.Name.Equals("Location", StringComparison.OrdinalIgnoreCase))
                    if box(locationHeader) <> null then
                        // remove the page because sometimes is copied in the redirection url
                        let redirectionUrl = locationHeader.Value.Replace(page, String.Empty)
                        redirects.Add(redirectionUrl) |> ignore

        // finally create the matching function, return true if the page exists
        fun (req: HttpRequest, resp: HttpResponse) ->            
            let mutable pageNotExist = true

            // create decision logic properties            
            let statusCodeMatchNotExistentPage = statusCodes.Contains(resp.StatusCode)
            let contentTypeMatchNotExistentPage = matchNotExistentContentType(resp.Headers, contentTypes)
            let isRedirectToNotExistent = verifyIfRedirectDueToNotExistance(req, resp, redirects)
                        
            // if the status code is not in the list of the page not existing, then page exists
            if resp.StatusCode <>  HttpStatusCode.NotFound && not statusCodeMatchNotExistentPage then
                pageNotExist <- false
            else
                pageNotExist <-
                    match resp.Headers |> Seq.tryFind(fun hdr -> hdr.Name.Equals("Content-Type")) with
                    | Some contentType when not(contentType.Value.ToLower().Contains("image")) -> 
                        let currentHtml = resp.Html
                        let htmlToCheckTokens = HeuristicHelpers.tokenize(currentHtml)
                
                        let htmlMatchNotExistentPage = HeuristicHelpers.htmlMatch(htmls, htmlToCheckTokens, percentageOfHtmlSimilarity)
                        let wordsLengthMatchNotExistentPage = HeuristicHelpers.matchWordsLength(htmls, htmlToCheckTokens, percentageOfHtmlSimilarity)
                        let matchLengthsOfUnexistenPages = matchUnexistendContentLength(htmlLengths, currentHtml.Length)
                        let matchStatusCodeNotExistenPagesIsEqualsForAll = statusCodeIsEqualsForAll(statusCodes, resp.StatusCode)

                        matchStatusCodeNotExistenPagesIsEqualsForAll ||
                        (contentTypeMatchNotExistentPage && wordsLengthMatchNotExistentPage && htmlMatchNotExistentPage) || 
                        matchLengthsOfUnexistenPages ||                    
                        isRedirectToNotExistent

                    | _ -> 
                        isRedirectToNotExistent

            not pageNotExist

    // set a default confidence of 5%
    new(httpRequestor: IHttpRequestor) = new HeuristicPageNotFoundIdentifier(httpRequestor, 0.05)

    member this.PageExists(httpRequest: HttpRequest, httpResponse: HttpResponse option) =
        if httpResponse.IsNone || httpResponse.Value.StatusCode = HttpStatusCode.NotFound then 
            false
        else
            let uriToTest = 
                if httpRequest.Uri.AbsolutePath.EndsWith("/") then
                    // need to get the path
                    let uriBuilder = new UriBuilder(httpRequest.Uri)
                    uriBuilder.Query <- String.Empty
                    // delete the final /
                    uriBuilder.Path <- httpRequest.Uri.AbsolutePath.Substring(0, httpRequest.Uri.AbsolutePath.Length - 1)
                    uriBuilder.Uri
                else
                    httpRequest.Uri

            let path = HttpUtility.getAbsolutePathDirectory(uriToTest)
            lock _syncRoot (fun _ ->
                if not <| _storedHeuristics.ContainsKey(path) then
                    _storedHeuristics.Add(path, generateHeuristic(uriToTest, httpResponse.Value))
            )
            
            _storedHeuristics.[path](httpRequest, httpResponse.Value)

    interface IPageNotFoundIdentifier with
        member this.PageExists(httpRequest: HttpRequest, httpResponse: HttpResponse option) =
            this.PageExists(httpRequest, httpResponse)
