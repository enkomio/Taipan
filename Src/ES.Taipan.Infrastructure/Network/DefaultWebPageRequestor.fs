namespace ES.Taipan.Infrastructure.Network

open System
open System.Text
open ES.Taipan.Infrastructure.Text

type DefaultWebPageRequestor(httpRequestor: IHttpRequestor) = 
    let _requestorSettings = httpRequestor.Settings

    let mutable _pageNotFoundIdentifier: IPageNotFoundIdentifier =
        {
            new IPageNotFoundIdentifier with
                member this.PageExists(httpRequest: HttpRequest, httpResponse: HttpResponse option) =
                    if httpResponse.IsNone then 
                        false
                    else
                        httpResponse.Value <> HttpResponse.Empty &&
                        ([
                            System.Net.HttpStatusCode.OK; 
                            System.Net.HttpStatusCode.Found; 
                            System.Net.HttpStatusCode.Redirect
                        ] |> List.contains httpResponse.Value.StatusCode)
        }

    let requestSinglePage(webRequest: WebRequest) =
        match httpRequestor.SendRequest(webRequest.HttpRequest) with
        | Some response ->
            let webResponse = new WebResponse(response)
            webResponse.PageExists <- _pageNotFoundIdentifier.PageExists(webRequest.HttpRequest, Some response)        
            webResponse
        | None ->
            new WebResponse(HttpResponse.Error)

    let rec sendTransaction (path: JourneyPath) (transaction: JourneyTransaction) : HttpResponse option =
        let httpRequest = transaction.BuildBaseHttpRequest()

        // manage parameters
        let data = new StringBuilder()
        let query = new StringBuilder()
        transaction.Parameters
        |> Seq.iter(fun parameter ->
            let parameterValue =
                if parameter.IsStatic || transaction.Index = 0 then parameter.Value
                else
                    // I have to request the template Uri request and retrieve the parameter value
                    let previousTransaction = path.[transaction.Index - 1]
                    match sendTransaction path previousTransaction with
                    | Some httpResponse -> RegexUtility.getHtmlInputValue(httpResponse.Html, parameter.Name)
                    | None -> parameter.Value
                    
            match parameter.Type with
            | Query -> query.AppendFormat("&{0}={1}", parameter.Name, parameterValue) |> ignore
            | Data -> data.AppendFormat("&{0}={1}", parameter.Name, parameterValue) |> ignore
        )

        if query.Length > 0 then    
            let uriBuilder = new UriBuilder(httpRequest.Uri)
            uriBuilder.Query <- query.ToString().Substring(1)
            httpRequest.Uri <- uriBuilder.Uri

        if data.Length > 0 then
            httpRequest.Data <- data.ToString().Substring(1)

        // send HttpRequest
        httpRequestor.SendRequest(httpRequest)

    let managePathNavigation(path: JourneyPath) =
        path.Transactions
        |> Seq.sortBy(fun transaction -> transaction.Index)
        |> Seq.map(sendTransaction path)
        |> Seq.toList
        |> List.last        
                    
    member this.RequestWebPage(webRequest: WebRequest) =   
        match _requestorSettings.Journey.Paths |> Seq.tryHead with
        | Some path -> 
            // follow the navigation path
            managePathNavigation(path) |> ignore

            // finally send the requested page
            requestSinglePage(webRequest)
        | _ -> requestSinglePage(webRequest)

    member this.RequestInitialWebPage(webRequest: WebRequest) =   
        match _requestorSettings.Journey.Paths |> Seq.tryHead with
        | Some path -> 
            // follow the navigation path
            match managePathNavigation(path) with
            | Some httpResponse -> new WebResponse(httpResponse, PageExists = true)
            | None -> new WebResponse(HttpResponse.Empty)
        | _ -> requestSinglePage(webRequest)

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