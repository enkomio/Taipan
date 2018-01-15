namespace ES.Taipan.Crawler

open System
open System.Collections.Generic
open System.Text.RegularExpressions
open System.Linq
open System.Text
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Infrastructure.Text
open ES.Taipan.Infrastructure.Service

type WebLinkMutator(settings: CrawlerSettings) =
    let _analyzedPagesLock = new Object()
    let _analyzedPages = new HashSet<String>()

    let addReferer(webLink: WebLink, templateLink: WebLink) =
        HttpUtility.setHeader("Referer", templateLink.Request.HttpRequest.Uri.AbsoluteUri, webLink.Request.HttpRequest.Headers)

    let getLinkInComment(webLinkTemplate: WebLink, webResponse: WebResponse) =
        seq {
            let mutable m = Regex.Match(webResponse.HttpResponse.Html, "<!--(.+?)-->", RegexOptions.Singleline)
            while m.Success do
                let comment = m.Groups.[0].Value.Trim()
                let mutable m1 = Regex.Match(comment, "(href|src)=['\"](.+?)['\"]", RegexOptions.Singleline)
                while m1.Success do
                    let uri = m1.Groups.[2].Value.Trim()
                    match WebUtility.getAbsoluteUriStringValueSameHost(webLinkTemplate.Request.HttpRequest.Uri.ToString(), uri) with
                    | Some absoluteUri -> 
                        let webLink = new WebLink(new WebRequest(absoluteUri), comment, webLinkTemplate.SessionId, OriginalWebLink = Some webLinkTemplate)
                        addReferer(webLink, webLinkTemplate)
                        yield webLink
                    | None -> ()

                    m1 <- m1.NextMatch()
                m <- m.NextMatch()
        }

    let getIntermediateDirectoryLink(webLinkTemplate: WebLink) =
        seq {
            let uriString = webLinkTemplate.Request.HttpRequest.Uri.AbsolutePath
            let segments = 
                let splittedString = uriString.Split([|'/'|])
                if uriString.EndsWith("/") then splittedString.ToList()
                else splittedString.ToList().GetRange(0, splittedString.Length - 1).ToList()
            
            let uriStringBuilder = new StringBuilder()
            for segment in segments do
                let httpRequest = HttpRequest.DeepClone(webLinkTemplate.Request.HttpRequest)
                let uriBuilder = new UriBuilder(httpRequest.Uri)  

                // create the partial uri path
                if String.IsNullOrWhiteSpace(segment) then                                        
                    uriBuilder.Path <- "/"
                else
                    uriStringBuilder.AppendFormat("{0}/", segment) |> ignore
                    uriBuilder.Path <- uriStringBuilder.ToString()

                httpRequest.Uri <- uriBuilder.Uri
                let mutateWebRequest = new WebRequest(httpRequest)                     
                let webLink = new WebLink(mutateWebRequest, webLinkTemplate.ParsedHtmlCode, webLinkTemplate.SessionId, OriginalWebLink = Some webLinkTemplate)
                addReferer(webLink, webLinkTemplate)
                yield webLink
        }

    let getWebLinkWithoutParameters(webLinkTemplate: WebLink) : WebLink seq =
        let mutable resultList = []
        let httpRequest = HttpRequest.DeepClone(webLinkTemplate.Request.HttpRequest)

        match httpRequest.Method with
        | HttpMethods.Get -> 
            if not <| String.IsNullOrWhiteSpace(httpRequest.Uri.Query) then
                let uriBuilder = new UriBuilder(httpRequest.Uri)
                uriBuilder.Query <- String.Empty
                httpRequest.Uri <- uriBuilder.Uri
                let mutateWebRequest = new WebRequest(httpRequest)                    
                resultList <- [new WebLink(mutateWebRequest, webLinkTemplate.ParsedHtmlCode, webLinkTemplate.SessionId, OriginalWebLink = Some webLinkTemplate)]
                addReferer(resultList.[0], webLinkTemplate)
        | HttpMethods.Post -> 
            if not <| String.IsNullOrWhiteSpace(httpRequest.Data) then
                httpRequest.Data <- String.Empty
                let mutateWebRequest = new WebRequest(httpRequest)                   
                resultList <- [new WebLink(mutateWebRequest, webLinkTemplate.ParsedHtmlCode, webLinkTemplate.SessionId, OriginalWebLink = Some webLinkTemplate)]
                addReferer(resultList.[0], webLinkTemplate)
        | _ -> ()

        resultList |> List.toSeq

    let getWebPageWithParametersAndMethodInverted(webLinkTemplate: WebLink) =
        let mutable resultList = []
        let httpRequest = HttpRequest.DeepClone(webLinkTemplate.Request.HttpRequest)
        
        match httpRequest.Method with
        | HttpMethods.Get when settings.SubmitPost ->             
            // move query string to data and change the method to POST
            if not <| String.IsNullOrWhiteSpace(httpRequest.Uri.Query) then
                httpRequest.Method <- HttpMethods.Post
                let uriBuilder = new UriBuilder(httpRequest.Uri)
                httpRequest.Data <- httpRequest.Uri.Query.Substring(1)
                uriBuilder.Query <- String.Empty
                httpRequest.Uri <- uriBuilder.Uri
                let mutateWebRequest = new WebRequest(httpRequest)                    
                resultList <- [new WebLink(mutateWebRequest, webLinkTemplate.ParsedHtmlCode, webLinkTemplate.SessionId, OriginalWebLink = Some webLinkTemplate)]
                addReferer(resultList.[0], webLinkTemplate)
        | HttpMethods.Post -> 
            // move data to query string and change the method to GET
            if not <| String.IsNullOrWhiteSpace(httpRequest.Data) then
                httpRequest.Method <- HttpMethods.Get
                let uriBuilder = new UriBuilder(httpRequest.Uri)
                uriBuilder.Query <- httpRequest.Data
                httpRequest.Data <- String.Empty
                httpRequest.Uri <- uriBuilder.Uri
                let mutateWebRequest = new WebRequest(httpRequest)                    
                resultList <- [new WebLink(mutateWebRequest, webLinkTemplate.ParsedHtmlCode, webLinkTemplate.SessionId, OriginalWebLink = Some webLinkTemplate)]
                addReferer(resultList.[0], webLinkTemplate)
        | _ -> ()

        resultList
        
    let getInexistenWebPage(webLinkTemplate: WebLink) = [        
            let uri = webLinkTemplate.Request.HttpRequest.Uri
            let pageId = Guid.NewGuid()
            match WebUtility.getAbsoluteUriStringValueSameHost(uri.ToString(), pageId.ToString("N")) with
            | Some inexistentPage ->
                let mutable webLink : WebLink option = None
                lock _analyzedPagesLock (fun _ ->                    
                    if _analyzedPages.Add(HttpUtility.getAbsolutePathDirectory(uri)) then
                        let httpRequest = HttpRequest.DeepClone(webLinkTemplate.Request.HttpRequest)
                        httpRequest.Uri <- new Uri(inexistentPage)
                        let mutateWebRequest = new WebRequest(httpRequest)                           
                        webLink <- Some <| new WebLink(mutateWebRequest, pageId.ToString("N"), webLinkTemplate.SessionId, Id = pageId)
                        addReferer(webLink.Value, webLinkTemplate)
                )                
                if webLink.IsSome then yield webLink.Value
            | None -> ()
        ]

    member this.CreateMutationLinksFromTemplate(webRequestTemplate: WebLink, webResponse: WebResponse) =
        getWebLinkWithoutParameters(webRequestTemplate)
        |> Seq.append (getLinkInComment(webRequestTemplate, webResponse))
        |> Seq.append (getIntermediateDirectoryLink(webRequestTemplate))
        |> Seq.append (getWebPageWithParametersAndMethodInverted(webRequestTemplate))
        |> Seq.append (getInexistenWebPage(webRequestTemplate))
