namespace ES.Taipan.Crawler

open System
open System.Net
open System.Text.RegularExpressions
open System.Linq
open System.Threading
open System.Collections.Generic
open System.Collections.Concurrent
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Infrastructure.Text
open ES.Fslog

type CrawlerState(settings: CrawlerSettings, httpRequestorSettings: HttpRequestorSettings, logProvider: ILogProvider) =        
    let _syncRoot = new Object()
    let _pagesToProcess = new BlockingCollection<WebLink>()
    let _pagesInProcess = new List<WebLink>()
    let _pagesProcessed = new List<WebLink>()
    let _requestsPerPage = new ConcurrentDictionary<String, Int32>()
    let mutable _pathRoot = "/"
    let mutable _stopRequested = false

    let _log = 
        log "CrawlerState"
        |> build    
    do logProvider.AddLogSourceToLoggers(_log)
        
    
    let createFingerprint(html: String) =
        let mutable cleanContent = html
        ["<link.*?>"; "<img.*?>"; "<style.*?>"; "<body.*?>"; "<head.*?>"; "<html.*?>"; "</body>"; "</head>"; "</html>"; "'"; "\""]
        |> List.iter(fun regex -> cleanContent <- Regex.Replace(cleanContent, regex, String.Empty, RegexOptions.Singleline ||| RegexOptions.IgnoreCase))
        cleanContent.GetHashCode()
                
    let isStaticOrNotParameters(req: HttpRequest) =
        let emptyParameters = String.IsNullOrWhiteSpace(req.Uri.Query) && String.IsNullOrEmpty(req.Data)

        let isStatic = 
            httpRequestorSettings.StaticExtensions
            |> Seq.exists(fun ext -> req.Uri.AbsolutePath.EndsWith(ext, StringComparison.OrdinalIgnoreCase))

        isStatic || emptyParameters
    
    let areReferersEqualForDynamicPage(reqToCheck: HttpRequest, req2: HttpRequest) =
        let referer1 =
            match HttpUtility.tryGetHeader("Referer", reqToCheck.Headers) with
            | Some hdr -> WebUtility.getAbsoluteUriStringValueSameHost(reqToCheck.Uri.AbsoluteUri, hdr.Value)
            | None -> None

        let referer2 =
            match HttpUtility.tryGetHeader("Referer", req2.Headers) with
            | Some hdr -> WebUtility.getAbsoluteUriStringValueSameHost(req2.Uri.AbsoluteUri, hdr.Value)
            | None -> None

        if referer1.IsSome && referer2.IsSome then
            let path1 = (new Uri(referer1.Value)).AbsolutePath
            let path2 = (new Uri(referer2.Value)).AbsolutePath
            path1.Equals(path2, StringComparison.Ordinal)
        else false

    let linkExists(requests: seq<WebLink>, webLink: WebLink) =
        let haveSource = webLink.Request.HttpRequest.Source.IsSome

        requests
        |> Seq.map (fun link -> link.Request.HttpRequest)
        |> Seq.tryFind (fun httpRequest ->
            let isSameLink =
                webLink.Request.HttpRequest.Method = httpRequest.Method &&
                WebUtility.areUriEquals(httpRequest.Uri, webLink.Request.HttpRequest.Uri) &&
                WebUtility.hasSameParametersAndData(httpRequest.Data, webLink.Request.HttpRequest.Data)

            if isSameLink then                
                if webLink.IsMutated() then 
                    // found via mutation, don't go further
                    true 
                elif isStaticOrNotParameters(webLink.Request.HttpRequest) then 
                    // links are equals and are static or without parameters, so it exists
                    true
                elif haveSource && httpRequest.Source.IsNone then
                    // the inspected request has Source, better to add to give change to the
                    // Javascript engine to use the source
                    false
                elif webLink.Request.HttpRequest.Method = HttpMethods.Get then
                    // links are equals and sent via GET
                    true
                else
                    // check referer for dynamic page (sent via POST)
                    areReferersEqualForDynamicPage(webLink.Request.HttpRequest, httpRequest)
            else
                false
        )
        |> Option.isSome

    // define filter methods
    let isMaxNumOfPageToCrawlReached() =
        if settings.HasLinkNavigationLimit then
            // I'll consider only not mutated pages
            let numOfProcessedPages =
                _pagesProcessed 
                |> Seq.map(fun webLink -> webLink.IsMutated() |> not)
                |> Seq.length
            numOfProcessedPages > settings.MaxNumberOfPagesToCrawl
        else false

    let isBlacklisted(webRequest: WebRequest) =
        let path = webRequest.HttpRequest.Uri.AbsolutePath
        settings.BlacklistedPattern
        |> Seq.exists(fun pattern -> Regex.IsMatch(path, pattern, RegexOptions.IgnoreCase))

    let isHostAllowed(webRequest: WebRequest) =
        let hostToCheck = webRequest.HttpRequest.Uri.Host
        settings.AllowedHosts.Contains(hostToCheck)

    let isContentTypeAllowed(webResponse: WebResponse) =
        let contentTypeHeader = 
            webResponse.HttpResponse.Headers
            |> Seq.tryFind (fun header -> header.Name.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))

        if contentTypeHeader.IsSome then
            not <| settings.ContentTypeToFilter.Contains(contentTypeHeader.Value.Value)
        else
            true

    let isExtensionAllowed(webRequest: WebRequest) =
        let extensionOpt = WebUtility.getPageExtension(webRequest.HttpRequest.Uri)
        if extensionOpt.IsSome then 
            let hasExtension = 
                settings.WebPageExtensions
                |> Seq.map(fun ext -> ext.ToLower())
                |> Seq.contains(extensionOpt.Value.ToLower())

            if settings.CrawlOnlyPageWithTheSpecifiedExtensions then hasExtension
            else not hasExtension
        else
            settings.CrawlPageWithoutExtension

    let isBasePathAllowed(webRequest: WebRequest) =
        match settings.Scope with
        | EnteredPath -> webRequest.HttpRequest.Uri.ToString().Equals(_pathRoot, StringComparison.Ordinal)
        | _ -> webRequest.HttpRequest.Uri.AbsolutePath.StartsWith(_pathRoot)

    let isHttpPostMethodAllowed(webRequest: WebRequest) =
        if webRequest.HttpRequest.Method = HttpMethods.Post then settings.SubmitPost
        else true

    let extractWebRequestKey(webRequest: WebRequest) =
        let path = webRequest.HttpRequest.Uri.AbsolutePath

        // extrac parameters from request
        let parametersName =
            WebUtility.getParametersFromData(webRequest.HttpRequest.Uri.Query) @ WebUtility.getParametersFromData(webRequest.HttpRequest.Data)
            |> List.map(fun (pName, _) -> pName)
            |> List.sort
            |> (fun pList -> String.Join(String.Empty, pList))

        path + parametersName

    let updateMaximumNumberOrRequestsPerPage(webRequest: WebRequest) =
        let key = extractWebRequestKey(webRequest)
        if not <| _requestsPerPage.ContainsKey(key) then
            _requestsPerPage.[key] <- 0
        _requestsPerPage.[key] <- _requestsPerPage.[key] + 1

    let isMaximumNumberOrRequestsPerPageAllowed(webRequest: WebRequest) =
        let key = extractWebRequestKey(webRequest)
        if not <| _requestsPerPage.ContainsKey(key) then
            _requestsPerPage.[key] <- 0
        _requestsPerPage.[key] <= settings.MaxNumOfRequestsToTheSamePage
        
    member this.Initialize(startUri: Uri) =
        match settings.Scope with
        | EnteredPath -> _pathRoot <- startUri.ToString()
        | WholeDomain -> _pathRoot <- "/"
        | EnteredPathAndBelow -> _pathRoot <- HttpUtility.getAbsolutePathDirectory(startUri)        

    member this.IsWebResponseValid(webResponse: WebResponse) =
       isContentTypeAllowed(webResponse)
        
    member this.GetStatus() =
        if isMaxNumOfPageToCrawlReached() then
            CrawlerStateAddPageStatusResult.MaxNumberOfPagesToCrawlReached
        else
            CrawlerStateAddPageStatusResult.Success

    member this.IsCrawlerStateAvailable() =
        this.GetStatus() = CrawlerStateAddPageStatusResult.Success
    
    member this.AddPageToCrawl(webLink: WebLink) =
        if _stopRequested then  
            CrawlerStateAddPageStatusResult.Success
        else
            let webRequest = webLink.Request

            let mutable status =
                if isHostAllowed(webRequest) |> not then CrawlerStateAddPageStatusResult.HostNotAllowed
                elif isBlacklisted(webRequest) then CrawlerStateAddPageStatusResult.PathBlacklisted
                elif isExtensionAllowed(webRequest) |> not then CrawlerStateAddPageStatusResult.ExtensionNotAllowed
                elif isBasePathAllowed(webRequest) |> not then CrawlerStateAddPageStatusResult.BasePathNoAllowed
                elif isHttpPostMethodAllowed(webRequest) |> not then CrawlerStateAddPageStatusResult.PostMethodNotAllowed
                elif isMaximumNumberOrRequestsPerPageAllowed(webRequest) |> not then CrawlerStateAddPageStatusResult.MaxNumOfRequestsToTheSamePageReached
                elif isMaxNumOfPageToCrawlReached() then CrawlerStateAddPageStatusResult.MaxNumberOfPagesToCrawlReached
                else CrawlerStateAddPageStatusResult.UnknownError

            if status = CrawlerStateAddPageStatusResult.UnknownError then                
                lock _syncRoot (fun () -> 
                    try
                        let pageFound = 
                            [seq _pagesToProcess; seq _pagesInProcess; seq _pagesProcessed]
                            |> List.exists(fun pages -> linkExists(pages, webLink))

                        if not pageFound then                            
                            _pagesToProcess.Add(webLink)
                            status <- CrawlerStateAddPageStatusResult.Success
                            updateMaximumNumberOrRequestsPerPage(webRequest)
                        else
                            status <- CrawlerStateAddPageStatusResult.PageAlredyPresent
                    with _ ->
                        status <- CrawlerStateAddPageStatusResult.UnknownError
                )

            status

    member this.StopServiceWebPages() =
        _stopRequested <- true
        _pagesToProcess.CompleteAdding()

    member this.IsStopRequested() =
        _stopRequested

    member this.GetNextWebRequest() =
        seq {
            for webRequest in _pagesToProcess.GetConsumingEnumerable() do
                if not _stopRequested then
                    lock _syncRoot (fun () -> _pagesInProcess.Add(webRequest))
                    yield webRequest
        }       

    member this.PageAnalyzed(webLink: WebLink) =
        lock _syncRoot (fun () -> 
            _pagesProcessed.Add(webLink)            
            _pagesInProcess.Remove(webLink))
        |> ignore

    member this.HasWebRequestToProcess
        with get() = 
            lock _syncRoot (fun () -> 
                (_pagesToProcess.Any() || _pagesInProcess.Any()) && not _stopRequested
            )

    member this.GetAllProcessedPages() =
        _pagesProcessed |> Seq.readonly

    member this.CompleteAdding() =
        _pagesToProcess.CompleteAdding()
