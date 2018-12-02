namespace ES.Taipan.Infrastructure.Network

open System
open System.Net

module internal HttpRequestorUtility =  
    
    let createHttpWebRequest(settings: HttpRequestorSettings, httpRequest: HttpRequest) =
        let httpWebRequest = WebRequest.Create( httpRequest.Uri ) :?> HttpWebRequest

        // check for proxy usage
        if settings.ProxyUrl.IsSome && Uri.IsWellFormedUriString(settings.ProxyUrl.Value, UriKind.Absolute) then
            httpWebRequest.Proxy <- new WebProxy(settings.ProxyUrl.Value, false, BypassProxyOnLocal=false)            
        else
            httpWebRequest.Proxy <- null

        // apply the settings
        httpWebRequest.Timeout <- settings.Timeout
        if httpRequest.AllowAutoRedirect.IsSome then
            httpWebRequest.AllowAutoRedirect <- httpRequest.AllowAutoRedirect.Value
        else
            httpWebRequest.AllowAutoRedirect <- settings.AllowAutoRedirect

        // set the method
        httpWebRequest.Method <- httpRequest.Method.ToString()

        // automatic decompress data
        httpWebRequest.AutomaticDecompression <- DecompressionMethods.GZip ||| DecompressionMethods.Deflate
        
        // set the headers
        for header in httpRequest.Headers do
            HttpUtility.addHttpHeader(header, httpWebRequest)

        // set the cookies
        if httpWebRequest.CookieContainer = null then
            httpWebRequest.CookieContainer <- new CookieContainer()

        for cookie in httpRequest.Cookies do
            httpWebRequest.CookieContainer.Add(cookie)

        // set the post data if present
        if not <| String.IsNullOrEmpty(httpRequest.Data) then
            HttpUtility.addPostData(httpRequest.Data, httpWebRequest)

        httpWebRequest
        
    let convertToHttpResponse(httpWebResponse: HttpWebResponse) =
        let httpResponseResult = new HttpResponse(ResponseUri = Some httpWebResponse.ResponseUri)
        
        // set the http response protocol version
        let (|Http10|_|) (v: Version) =
            if v = Version.Parse("1.0") then Some Http10
            else None

        let (|Http11|_|) (v: Version) =
            if v = Version.Parse("1.1") then Some Http11
            else None
                    
        httpResponseResult.HttpVersion <- 
            match httpWebResponse.ProtocolVersion with
            | Http10 -> HttpVersions.Http10
            | Http11 -> HttpVersions.Http11
            | _ as v -> HttpVersions.Custom(v.ToString())

        // set the http response status code
        httpResponseResult.StatusCode <- httpWebResponse.StatusCode

        // set the http response phrase
        httpResponseResult.ReasonPhrase <- httpWebResponse.StatusDescription

        // set the http response headers
        for httpHeaderName in httpWebResponse.Headers.AllKeys do
            httpResponseResult.Headers.Add(new HttpHeader(Name=httpHeaderName, Value=httpWebResponse.Headers.[httpHeaderName]))

        // add cookies to httpResponse by parsing the Set-Cookie header. This since the container doesn't manage cookie on different path very well
        // for more info see: https://stackoverflow.com/questions/3716144/cookiecontainer-handling-of-paths-who-ate-my-cookie
        for cookie in HttpUtility.getCookiesFromHeader(httpWebResponse) do
            httpResponseResult.Cookies.Add(cookie)
        
        httpResponseResult