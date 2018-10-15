namespace ES.Taipan.Infrastructure.Network

open System

type DefaultWebPageRequestor(httpRequestor: IHttpRequestor) = 
    let _requestorSettings = httpRequestor.Settings

    let mutable _pageNotFoundIdentifier: IPageNotFoundIdentifier =
        {
            new IPageNotFoundIdentifier with
                member this.PageExists(httpRequest: HttpRequest, httpResponse: HttpResponse option) =                    
                    httpResponse.IsSome && 
                    httpResponse.Value <> HttpResponse.Empty &&
                    (
                        [
                            System.Net.HttpStatusCode.OK
                            System.Net.HttpStatusCode.Found
                            System.Net.HttpStatusCode.Redirect
                            System.Net.HttpStatusCode.Unauthorized
                        ] |> List.contains httpResponse.Value.StatusCode
                    )
        }
                    
    member this.RequestWebPage(webRequest: WebRequest) =   
        match httpRequestor.SendRequest(webRequest.HttpRequest) with
        | Some response ->
            let webResponse = new WebResponse(response)
            webResponse.PageExists <- _pageNotFoundIdentifier.PageExists(webRequest.HttpRequest, Some response)        
            webResponse
        | None -> new WebResponse(HttpResponse.Error)

    member this.RequestInitialWebPage(webRequest: WebRequest) =
        // the initial request is a bit special and needs to take into account if a journey path is defined        
        match httpRequestor with
        | :? DefaultHttpRequestor as defaultHttpRequestor -> 
            match defaultHttpRequestor.FollowJourneyPathNavigation() |> Array.tryLast with
            | Some httpResponse -> new WebResponse(httpResponse, PageExists = true)
            | None -> this.RequestWebPage(webRequest)
        | _ -> this.RequestWebPage(webRequest)

    member val HttpRequestor = httpRequestor with get

    member this.SetPageNotFoundIdentifier(pageNotFoundIdentifier: IPageNotFoundIdentifier) =
        _pageNotFoundIdentifier <- pageNotFoundIdentifier

    member this.Dispose() =
        match httpRequestor with
        | :? IDisposable as disposable -> disposable.Dispose()
        | _ -> ()

    interface IWebPageRequestor with
        member this.RequestWebPage(webRequest: WebRequest) =
            this.RequestWebPage(webRequest)

        member this.RequestInitialWebPage(webRequest: WebRequest) =
            this.RequestInitialWebPage(webRequest)

        member this.HttpRequestor
            with get() = this.HttpRequestor

        member this.SetPageNotFoundIdentifier(pageNotFoundIdentifier: IPageNotFoundIdentifier) =
            this.SetPageNotFoundIdentifier(pageNotFoundIdentifier)

    interface IDisposable with
        member this.Dispose() =
            this.Dispose()