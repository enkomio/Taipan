namespace ES.Taipan.Infrastructure.Network

open System
open System.Collections.Generic
open System.IO
open System.Net
open System.Threading.Tasks

module internal HttpRequestorUtility =
    let private parseCookieHeaderValue(hdrValue: String, host: String) =
        let cookies = new List<Cookie>()
        try
            let items = hdrValue.Split(';')
            let cookiePart = items.[0].Split('=')                
            let (name, value) = (cookiePart.[0], cookiePart.[1])
            let cookie = new Cookie(name, value, "/", host)

            // get flags
            items.[1..]
            |> Seq.map(fun item -> item.Trim())
            |> Seq.iter(fun item ->
                let lowerItem = item.ToLower()
                cookie.Secure <- lowerItem.Contains("secure")
                cookie.HttpOnly <- lowerItem.Contains("httponly")
            )

            cookies.Add(cookie)
        with _ -> ()
        cookies

    let addPostData(data: String, webRequest: HttpWebRequest) =
        try
            use streamWriter = new StreamWriter(webRequest.GetRequestStream())
            streamWriter.Write(data)
        with 
        | _ -> ()

    let getCookiesFromHeader(httpWebResponse: HttpWebResponse) =
        let cookies = new List<Cookie>()
        if httpWebResponse.Headers.AllKeys |> Seq.contains "Set-Cookie" then
            for hdrValue in httpWebResponse.Headers.GetValues("Set-Cookie") do
                cookies.AddRange(parseCookieHeaderValue(hdrValue, httpWebResponse.ResponseUri.Host))
        cookies
        
    let addHttpHeader(header: HttpHeader, webRequest: HttpWebRequest) =
        let headerName = header.Name.Replace("-", String.Empty).ToLower()
        match headerName with
        | "useragent" -> webRequest.UserAgent <- header.Value
        | "accept" -> webRequest.Accept <- header.Value
        | "referer" -> webRequest.Referer <- header.Value
        | "host" -> webRequest.Host <- header.Value
        | "contenttype" -> webRequest.ContentType <- header.Value
        | "contentlength" -> 
            let contentLen = ref 0L
            if Int64.TryParse(header.Value, contentLen) then webRequest.ContentLength <- !contentLen
        | "connection" 
        | "proxyconnection" -> 
            if header.Value.Equals("Keep-Alive", StringComparison.OrdinalIgnoreCase) then   
                webRequest.KeepAlive <- true
            else 
                webRequest.Connection <- header.Value
                webRequest.KeepAlive <- false
        | "date" ->     
            let date = ref DateTime.Now
            if DateTime.TryParse(header.Value, date) then webRequest.Date <- !date
        | "expect" -> 
            // 100-Continue must be setted with the System.Net.ServicePointManager.Expect100Continue Setted to true
            // see http://haacked.com/archive/2004/05/15/http-web-request-expect-100-continue.aspx
            if not <| header.Value.Equals("", StringComparison.OrdinalIgnoreCase) then webRequest.Expect <- header.Value
        | "ifmodifiedsince" -> 
            let date = ref DateTime.Now
            if DateTime.TryParse(header.Value, date) then webRequest.IfModifiedSince <- !date
        | "transferencoding" -> 
            webRequest.SendChunked <- true
            webRequest.TransferEncoding <- header.Value
        | "cookie" ->
            if webRequest.CookieContainer = null then
                webRequest.CookieContainer <- new CookieContainer()

            let cookieValue = header.Value
            parseCookieHeaderValue(cookieValue, webRequest.RequestUri.Host)
            |> Seq.iter(webRequest.CookieContainer.Add)
        | _ -> webRequest.Headers.[header.Name] <- header.Value
    
    let createHttpWebRequest(settings: HttpRequestorSettings, httpRequest: HttpRequest) =
        let httpWebRequest = WebRequest.Create( httpRequest.Uri ) :?> HttpWebRequest

        // check for proxy usage
        if settings.ProxyUrl.IsSome && Uri.IsWellFormedUriString(settings.ProxyUrl.Value, UriKind.Absolute) then
            httpWebRequest.Proxy <- new WebProxy(settings.ProxyUrl.Value, false)            
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
            addHttpHeader(header, httpWebRequest)

        // set the cookies
        httpWebRequest.CookieContainer <- new CookieContainer()
        for cookie in httpRequest.Cookies do
            httpWebRequest.CookieContainer.Add(cookie)

        // set the post data if present
        if not <| String.IsNullOrEmpty(httpRequest.Data) then
            addPostData(httpRequest.Data, httpWebRequest)

        httpWebRequest
        
    let convertToHttpResponse(httpWebResponse: HttpWebResponse, html: String) =
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
        for cookie in getCookiesFromHeader(httpWebResponse) do
            httpResponseResult.Cookies.Add(cookie)

        // set the http response html
        httpResponseResult.Html <- html
        
        httpResponseResult