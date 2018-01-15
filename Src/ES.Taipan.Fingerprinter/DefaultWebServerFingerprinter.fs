namespace ES.Taipan.Fingerprinter

open System
open System.Collections.Generic
open System.IO
open System.Text.RegularExpressions
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Infrastructure.Text
open ES.Taipan.Fingerprinter.SimpleCrawler
open ES.Fslog

type DefaultWebServerFingerprinterLogger() =
    inherit LogSource("DefaultWebServerFingerprinter")
    
    [<Log(1, Message = "Start fingerprint web server: {0}", Level = LogLevel.Informational)>]
    member this.StartWebServerfingerprint(server: Uri) =
        this.WriteLog(1, [|server|])

    [<Log(2, Message = "Web server fingerprinted: {0}", Level = LogLevel.Informational)>]
    member this.WebServerfingerprint(fingerprint: WebServerFingerprint) =
        this.WriteLog(2, [|fingerprint|])

type DefaultWebServerFingerprinter(httpRequestor: IHttpRequestor, logProvider: ILogProvider) =
    let _logger = new DefaultWebServerFingerprinterLogger()
    let _cache = new Dictionary<String, WebServerFingerprint>()

    do 
        logProvider.AddLogSourceToLoggers(_logger)

        // remove cookies since it can cause the fingerprint to invalidate session cookie
        httpRequestor.Settings.AdditionalCookies.Clear()
    
    let checkExtension(rawDomain: Uri, url: String, fingerprint: WebServerFingerprint) =
        try
            let domain = rawDomain.Host.Replace("www.", String.Empty)
            let mutable nameToCheck = 
                if url.StartsWith("//") then "http://" + url.Substring(2).Replace("www.", String.Empty)
                else url

            nameToCheck <- nameToCheck.Replace("www.", String.Empty)

            // for absolute url must be the same domain
            if Uri.IsWellFormedUriString(nameToCheck, UriKind.Absolute) then
                let uri = new Uri(nameToCheck)
                if uri.Host.Equals(domain, StringComparison.OrdinalIgnoreCase) then          
                    nameToCheck <- Path.GetExtension(uri.AbsolutePath)
                else nameToCheck <- String.Empty
            else
                // check if there is a query string
                let m = Regex.Match(nameToCheck, "(.+?)\\?.*")
                if m.Success then
                    nameToCheck <- m.Groups.[1].Value                
                nameToCheck <- Path.GetExtension(nameToCheck.Trim([|'/'|]))

            // effectivly check the extension
            match nameToCheck.ToUpper() with
            | ".PHP" -> Some ProgrammingLanguage.Php
            | ".JSP" -> Some ProgrammingLanguage.Java
            | ".DO" -> Some ProgrammingLanguage.Java
            | ".ACTION" -> Some ProgrammingLanguage.Java
            | ".ASP" -> Some ProgrammingLanguage.Asp
            | ".ASPX" -> Some ProgrammingLanguage.AspNet
            | ".PY" -> Some ProgrammingLanguage.Python
            | _ -> None
            |> fun extOpt ->
                if extOpt.IsSome then 
                    fingerprint.Languages.Add(extOpt.Value)
                else
                    false

        with _ -> false

    let checkHttpHeaders(headers: HttpHeader seq, fingHeaders: (String * _) list, property: HashSet<_>, fingerprint: WebServerFingerprint) =        
        headers
        |> Seq.iter(fun header ->
            fingHeaders 
            |> List.iter(fun (regex, item) -> 
                if Regex.Match(header.Name, regex, RegexOptions.IgnoreCase).Success || Regex.Match(header.Value, regex, RegexOptions.IgnoreCase).Success then
                    property.Add(item) |> ignore
            )
        )

    let checkHttpHeadersDeepth(headers: HttpHeader seq, checks: (String * (String -> #Object)) list) =           
        let inspectHeader(hdrValue: String) (regex: String, callback: String -> #Object) =
            let m = Regex.Match(hdrValue, regex, RegexOptions.IgnoreCase)
            if m.Success then Some <| callback(m.Groups.[1].Value)
            else None

        let tmp = 
            checks
            |> List.map(fun check ->
                headers
                |> Seq.map(fun header -> inspectHeader (header.ToString()) check)
                |> Seq.filter(Option.isSome)
                |> Seq.tryHead                
            )
            |> Seq.tryHead

        if tmp.IsSome && tmp.Value.IsSome then tmp.Value.Value
        else None

    let checkHttpHeadersForLang(headers: HttpHeader seq, fingerprint: WebServerFingerprint) =        
        checkHttpHeaders(
            headers,
            [
                ("ASP\\.NET", ProgrammingLanguage.AspNet)
                ("ASP\\s", ProgrammingLanguage.Asp)
                ("PHP", ProgrammingLanguage.Php)
                ("PYTHON", ProgrammingLanguage.Python)
            ],
            fingerprint.Languages,
            fingerprint
        )

    let checkHttpHeadersForFramework(headers: HttpHeader seq, fingerprint: WebServerFingerprint) =        
        [
            ("MS-FP/([0-9.]+)", (fun v -> "Microsoft Front-Page " + v))
            ("MicrosoftOfficeWebServer: ([0-9.a-zA-Z]+)", (fun v -> "Microsoft Office WebServer " + v))
            ("X-AspNetMvc-Version: ([0-9.]+)", (fun v -> "Microsoft ASP.NET MVC " + v))
            ("X-AspNet-Version: ([0-9.]+)", (fun v -> "Microsoft ASP.NET " + v))
            ("X-Powered-By: PHP/([0-9.]+)", (fun v -> "PHP " + v))
        ]
        |> List.iter(fun check ->
            match checkHttpHeadersDeepth(headers, [check]) with
            | Some frm -> fingerprint.Frameworks.Add(frm) |> ignore
            | _ -> ()
        )

        // check X- header fo unknow framework
        if fingerprint.Frameworks |> Seq.isEmpty then            
            match checkHttpHeadersDeepth(headers, [("X-Powered-By: (.+)", id)]) with
            | Some frm -> fingerprint.Frameworks.Add(frm) |> ignore
            | _ -> ()
                    
    let checkHttpHeadersForWebServer(headers: HttpHeader seq, fingerprint: WebServerFingerprint) =      
        let checks = [
            ("Microsoft-IIS/([0-9.]+)", (fun v -> WebServer.IIS v))
            ("ZServer/([0-9.a-zA-Z]+)", (fun v -> WebServer.Zope2 v))
            ("Nginx/([0-9.]+)", (fun v -> WebServer.Nginx v))
            ("Apache/([0-9.]+)", (fun v -> WebServer.Apache v))
        ]

        match checkHttpHeadersDeepth(headers, checks) with
        | Some v -> fingerprint.Server <- v
        | _ -> 
            // try of less precise identification
            headers
            |> Seq.iter(fun header ->
                [
                    ("JSESSIONID=", WebServer.Apache String.Empty)
                    ("Apache", WebServer.Apache String.Empty)
                    ("Nginx", WebServer.Nginx String.Empty)
                    ("Microsoft-IIS", WebServer.IIS String.Empty)
                    ("ZServer/", WebServer.Zope2 String.Empty)
                ] |> Seq.iter(fun (regex, server) -> 
                    if Regex.Match(header.Value, regex, RegexOptions.IgnoreCase).Success then
                        fingerprint.Server <- server
                )
            )

    let checkLinkInHtml(domain: Uri, html: String, fingerprint: WebServerFingerprint) =
        let mutable matches = Regex.Match(html, "(href|src|action)=\"(.+?)\"", RegexOptions.IgnoreCase)
        let mutable toBeIdentified = matches.Success        
        while toBeIdentified do
            let urlStr = matches.Groups.[2].Value.Trim()
            if not(WebUtility.notHyperlinkSchemas |> List.exists(urlStr.StartsWith)) && checkExtension(domain, urlStr, fingerprint) then
                toBeIdentified <- false
            else
                matches <- matches.NextMatch()
                toBeIdentified <- matches.Success

    let checkWordsInHtml(html: String, fingerprint: WebServerFingerprint) =
        let struts2Keywords = (["jquery.ui.struts2.js"; "/struts2/"; "struts2_jquery"], "Struts")

        // inspect HTML
        for (keywords, frameworkName) in [struts2Keywords] do
            if keywords |> List.exists(html.Contains) then
                fingerprint.Frameworks.Add(frameworkName) |> ignore

    do httpRequestor.Settings.AllowAutoRedirect <- true
    
    member this.Fingerprint(url: Uri) =        
        let fingerprint = new WebServerFingerprint()

        if _cache.ContainsKey(url.Host) then
            _cache.[url.Host]
        else
            // do HTTP request to base domain
            _logger.StartWebServerfingerprint(url)

            (crawl url.AbsoluteUri 20 httpRequestor)
            |> Seq.iter(fun kv ->
                let url = new Uri(kv.Key)
                let httpResponse = kv.Value

                checkExtension(url, url.ToString(), fingerprint) |> ignore
                checkHttpHeadersForLang(httpResponse.Headers, fingerprint)
                checkHttpHeadersForFramework(httpResponse.Headers, fingerprint)
                checkHttpHeadersForWebServer(httpResponse.Headers, fingerprint)
                checkLinkInHtml(url, httpResponse.Html, fingerprint)
                checkWordsInHtml(httpResponse.Html, fingerprint)
            )

            _cache.Add(url.Host, fingerprint)
            _logger.WebServerfingerprint(fingerprint)
            fingerprint

    interface IWebServerFingerprinter with
        member this.Fingerprint(url: Uri) =
            this.Fingerprint(url)