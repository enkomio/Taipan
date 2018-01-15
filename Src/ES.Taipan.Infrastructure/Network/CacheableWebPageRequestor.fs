namespace ES.Taipan.Infrastructure.Network

open System
open System.Collections.Generic

type CacheableWebPageRequestor(webPageRequestor: IWebPageRequestor) =
    let _syncRoot = new Object()
    let _cache = new Dictionary<String, WebResponse>()
    
    member this.RequestWebPage(webRequest: WebRequest) =   
        lock _syncRoot (fun () ->
            if webRequest.HttpRequest.Method = HttpMethods.Get then
                let uri = webRequest.HttpRequest.Uri.AbsoluteUri
                if _cache.ContainsKey(uri) then
                    _cache.[uri]
                else
                    let response = webPageRequestor.RequestWebPage(webRequest)
                    _cache.Add(uri, response)
                    response
            else
                webPageRequestor.RequestWebPage(webRequest)
        )

    member this.RequestInitialWebPage(webRequest: WebRequest) =   
        this.RequestWebPage(webRequest)

    member val HttpRequestor = webPageRequestor.HttpRequestor with get

    member this.SetPageNotFoundIdentifier(pageNotFoundIdentifier: IPageNotFoundIdentifier) =
        webPageRequestor.SetPageNotFoundIdentifier(pageNotFoundIdentifier)

    interface IWebPageRequestor with
        member this.RequestWebPage(webRequest: WebRequest) =
            this.RequestWebPage(webRequest)

        member this.RequestInitialWebPage(webRequest: WebRequest) =
            this.RequestInitialWebPage(webRequest)

        member this.HttpRequestor
            with get() = this.HttpRequestor

        member this.SetPageNotFoundIdentifier(pageNotFoundIdentifier: IPageNotFoundIdentifier) =
            this.SetPageNotFoundIdentifier(pageNotFoundIdentifier)