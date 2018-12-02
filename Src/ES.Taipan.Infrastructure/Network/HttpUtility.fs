namespace ES.Taipan.Infrastructure.Network

open System
open System.IO
open System.Collections.Generic
open System.Net

module HttpUtility =
    let parseCookieHeaderValue(hdrValue: String, host: String) =
        let cookies = new List<Cookie>()
        let attributes = [
            "comment"; "domain"; "max-age"
            "path"; "secure"; "version"; 
            "httponly"
        ]
        
        let mutable isSecure = false
        let mutable isHttpOnly = false

        hdrValue.Split(';')
        |> Array.rev
        |> Array.map(fun item ->
            let keyValue = 
                item.Split('=') 
                |> Array.map(fun s -> s.Trim())
                |> Array.map(Uri.UnescapeDataString) 
                |> Array.map(Uri.EscapeDataString)

            if keyValue.Length > 1
            then (keyValue.[0], keyValue.[1])
            else (item, String.Empty)
        )
        |> Array.iter(fun (name, value) ->
            try
                if attributes |> List.contains(name.Trim().ToLower()) then
                    // it is an attribute
                    match name.Trim().ToLower() with
                    | "secure" -> isSecure <- true
                    | "httponly" -> isHttpOnly <- true
                    | _ -> ()
                else
                    // create a new cookie                    
                    let cookie = new Cookie(name, value, "/", host, Secure = isSecure, HttpOnly = isHttpOnly)
                    cookies.Add(cookie)
            with _ -> ()
        )
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

    /// Return the absolute path directory. Some examples:
    /// http://www.example.com/a/b/c/index.php    -> /a/b/c 
    /// http://www.example.com/a/b/c/index        -> /a/b/c
    /// http://www.example.com/a/b/c/             -> /a/b/c
    let getAbsolutePathDirectory(uri: Uri) =
        let uriWebsite = uri.AbsolutePath
        if not <| uriWebsite.EndsWith("/") then
            let lastIndexOfSlash = uriWebsite.LastIndexOf('/')
            uriWebsite.Substring(0, lastIndexOfSlash)
         elif uriWebsite.Length > 0 then
            uriWebsite.Substring(0, uriWebsite.Length - 1)
        else 
            uriWebsite

    /// Return the web page name. Some examples:
    /// http://www.example.com/a/b/c/index.php    -> index.php
    /// http://www.example.com/a/b/c/index        -> index
    /// http://www.example.com/a/b/c/             -> <String.Empty>
    let getPage(uri: Uri) =
        let absolutePath = uri.AbsolutePath
        if absolutePath.EndsWith("/") then
            String.Empty
        else
            let lastIndexOfSlash = absolutePath.LastIndexOf("/")
            absolutePath.Substring(lastIndexOfSlash + 1)

    let getHeader(hdrName: String, headers: HttpHeader seq) =
        headers |> Seq.find(fun hdr -> hdr.Name.Equals(hdrName, StringComparison.Ordinal))

    let tryGetHeader(hdrName: String, headers: HttpHeader seq) =
        headers |> Seq.tryFind(fun hdr -> hdr.Name.Equals(hdrName, StringComparison.Ordinal))

    let setHeader(headerName: String, headerValue: String, headers: List<HttpHeader>) =
        match tryGetHeader(headerName,  headers) with
        | Some header -> header.Value <- headerValue
        | None -> headers.Add(new HttpHeader(Name = headerName, Value = headerValue))

    let isRedirect(statusCode: HttpStatusCode) =
        match statusCode with
        | HttpStatusCode.Found
        | HttpStatusCode.Moved
        | HttpStatusCode.MovedPermanently
        | HttpStatusCode.MultipleChoices
        | HttpStatusCode.NotModified
        | HttpStatusCode.Redirect
        | HttpStatusCode.RedirectKeepVerb
        | HttpStatusCode.RedirectMethod
        | HttpStatusCode.SeeOther
        | HttpStatusCode.TemporaryRedirect
        | HttpStatusCode.Unused
        | HttpStatusCode.UseProxy -> true
        | _ -> false
