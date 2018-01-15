namespace ES.Taipan.Infrastructure.Network

// TODO: remove this class it is only used in server part
open System
open System.Linq
open System.IO
open System.Collections.Generic
open System.Collections.Concurrent
open System.Net
open ES.Fslog

type WebProxy(remoteAddr: Uri, httpRequestor: IHttpRequestor, logProvider: ILogProvider) =
    let _recordedRequests = new ConcurrentQueue<HttpRequest>()
    let _whitelistedHeaders = new List<String>()
    let _extensionToIgnore = new List<String>()
    let _injectors = new List<String * HttpRequest * HttpResponse -> unit>()

    let isHeaderAllowed(httpHeader: HttpHeader) =
        _whitelistedHeaders |> Seq.exists(fun whiteListPrefix -> httpHeader.Name.StartsWith(whiteListPrefix, StringComparison.OrdinalIgnoreCase))
            
    new(remoteAddr: Uri) =
        let settings = new HttpRequestorSettings()
        settings.AllowAutoRedirect <- false        
        let httpRequestor = new DefaultHttpRequestor(settings, LogProvider.GetDefault())
        new WebProxy(remoteAddr, httpRequestor, LogProvider.GetDefault())

    member val Id = Guid.NewGuid() with get
    
    abstract AnalyzeResponse : String * HttpRequest * HttpResponse -> unit
    default this.AnalyzeResponse(destPath: String, httpRequest: HttpRequest, httpResponse: HttpResponse) =
        // filter headers
        let copyOfHeaders = httpResponse.Headers.ToList()
        httpResponse.Headers.Clear()
        copyOfHeaders |> Seq.filter isHeaderAllowed |> Seq.iter httpResponse.Headers.Add
        
        // do modification         
        _injectors |> Seq.iter(fun injector -> injector(destPath, httpRequest, httpResponse))

    member this.AddInjector(codeInjector: String * HttpRequest * HttpResponse -> unit) =
        _injectors.Add(codeInjector)

    member this.AddExtensionToNotRecord(extension: String) =
        _extensionToIgnore.Add(extension)

    member this.AddWhitelistedHeader(headerPrefix: String) =
        _whitelistedHeaders.Add(headerPrefix)
            
    member this.GetRecordedRequests() =
        _recordedRequests

    member private this.SendHttpRequest(httpRequest: HttpRequest, destPath: String) =
        match httpRequestor.SendRequest(httpRequest) with
        | Some httpResponse -> 
            if not <| _extensionToIgnore.Contains(Path.GetExtension(httpRequest.Uri.AbsolutePath)) then
                _recordedRequests.Enqueue(httpRequest)
            this.AnalyzeResponse(destPath, httpRequest, httpResponse)
            Some httpResponse
        | _ -> None

    member this.ForwardPost(destPath: String, data: String) =  
        let destUri = new Uri(remoteAddr, destPath)
        let httpRequest = new HttpRequest(destUri)
        httpRequest.Method <- HttpMethods.Post
        httpRequest.Data <- data
        this.SendHttpRequest(httpRequest, destPath)

    member this.ForwardGet(destPath: String) =  
        let destUri = new Uri(remoteAddr, destPath)
        let httpRequest = new HttpRequest(destUri)
        this.SendHttpRequest(httpRequest, destPath)


