namespace ES.Taipan.Infrastructure.Network

open System
open System.Linq
open System.Net
open System.Collections.Generic

type SessionStateManager() = 
    let _syncRoot = new Object()
    let _sessionCookies = new Dictionary<String, List<Cookie>>()

    let fixCookiePath(cookie: Cookie) =
        let mutable cookiePath = cookie.Path
        if not <| cookiePath.EndsWith("/") then
            let lasIndexOfSlash = cookiePath.LastIndexOf('/')
            if lasIndexOfSlash >=  0 then
                cookiePath <- cookiePath.Substring(0, lasIndexOfSlash)
        cookie.Path <- cookiePath

    member this.ApplySessionParametersToRequest(httpRequest: HttpRequest) =
        let requestHost = httpRequest.Uri.Host
        lock _syncRoot (fun () ->
            if _sessionCookies.ContainsKey(requestHost) then
                // add all session cookies that wasn't alredy in the request
                for cookie in _sessionCookies.[requestHost] do
                    if not <| httpRequest.Cookies.Any(fun c -> c.Name.Equals(cookie.Name, StringComparison.Ordinal)) then
                        fixCookiePath(cookie)
                        httpRequest.Cookies.Add(cookie)
        )

    member this.AddCookieToSession(httpRequestDone: HttpRequest, cookies: List<Cookie>) =
        let requestHost = httpRequestDone.Uri.Host
        lock _syncRoot (fun () ->
            if not <| _sessionCookies.ContainsKey(requestHost) then
                _sessionCookies.Add(requestHost, new List<Cookie>())

            // save all the new cookie setted in the response
            let cookieCollection = _sessionCookies.[requestHost]

            for cookie in cookies do
                let storedCookie =
                    cookieCollection
                    |> Seq.tryFind (fun c -> c.Name.Equals(cookie.Name, StringComparison.Ordinal))
                
                if storedCookie.IsSome then
                    storedCookie.Value.Value <- cookie.Value
                else
                    cookieCollection.Add(cookie)
        )
        
    member this.RetrieveSessionParametersFromResponse(httpRequestDone: HttpRequest, httpResponse: HttpResponse) =
        this.AddCookieToSession(httpRequestDone, httpResponse.Cookies)