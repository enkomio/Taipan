namespace ES.Taipan.Inspector.AddOns.DirectoryListing

open System
open System.Collections.Generic
open System.Text.RegularExpressions
open ES.Taipan.Inspector
open ES.Taipan.Inspector.AddOns
open ES.Taipan.Infrastructure.Service
open ES.Taipan.Infrastructure.Network
open ES.Fslog

type DirectoryListingAddOn() as this =
    inherit BaseStatelessAddOn("Directory Listing AddOn", string DirectoryListingAddOn.Id, 1)    
    let _analyzedPath = new HashSet<String>()

    let _regexes = [
        "Index of /"
        @"\[To Parent Directory\]"
        "[,]apache=<a href=\"\\?C=N;O=D\">"
        "[,]apache=<address>Apache/.*? Server at .*?Port.*?</address>"
        @"[,]iis=\[To Parent Directory\]"
        "[,]lighttpd=<div class=\"foot\">lighttpd"
        "[,]tomcat=<body><h1>Directory Listing For"
        "[,]nginx=<h1>Index of /.*?</h1><hr><pre><a href=\"\\.\\./\">\\.\\./</a>"
        "Django tried these URL patterns, in this order:"
    ]

    let tryGetDisclosedFiles(html: String) = [        
        let mutable matches = Regex.Match(html, "<td><a href=['\"](.+?)['\"]>(.+?)</a></td>", RegexOptions.Singleline ||| RegexOptions.IgnoreCase)
        while matches.Success do
            let link = matches.Groups.[1].Value.Trim()
            let title = matches.Groups.[2].Value.Trim()
            if not <| title.Equals("Parent Directory", StringComparison.OrdinalIgnoreCase) then
                yield link
            matches <- matches.NextMatch()
    ]

    let reportSecurityIssue(uri: Uri, webRequest: WebRequest, webResponse: WebResponse, matchedValue: String) =        
        let securityIssue = 
            new SecurityIssue(
                DirectoryListingAddOn.Id, 
                Name = "Directory Listing", 
                Uri = uri, 
                EntryPoint = EntryPoint.UriSegment
            )
        securityIssue.Transactions.Add(webRequest, webResponse)
        securityIssue.Details.Properties.Add("Html", webResponse.HttpResponse.Html)
        securityIssue.Details.Properties.Add("MatchedValue", matchedValue)

        // try to get the list of indexed files
        let files = tryGetDisclosedFiles(webResponse.HttpResponse.Html)
        let fileList = String.Join(",", files)
        securityIssue.Details.Properties.Add("Files", fileList)

        this.Context.Value.AddSecurityIssue(securityIssue)

    let identifyDirectoryListingPatterns(html: String) =
        match
            _regexes
            |> List.map(fun regexStr -> new Regex(regexStr, RegexOptions.IgnoreCase))
            |> List.map(fun regex -> regex.Match(html))
            |> List.tryFind(fun matches -> matches.Success) 
            
            with
            | Some matches -> Some matches.Value
            | None -> None

    static member Id = Guid.Parse("FDE5F6AD-C468-4ED4-AD95-BFC393D7F1AC")
        
    default this.Scan(testRequest: TestRequest, stateController: ServiceStateController) =
        let path = HttpUtility.getAbsolutePathDirectory(testRequest.WebRequest.HttpRequest.Uri) + "/"
        if _analyzedPath.Add(path) then
            let directoryUri = new Uri(testRequest.WebRequest.HttpRequest.Uri, path)
            let webRequest = new WebRequest(directoryUri)
            stateController.WaitIfPauseRequested()
            let webResponse = this.WebRequestor.Value.RequestWebPage(webRequest)
            if not <| Object.ReferenceEquals(webResponse.HttpResponse, null) then
                match identifyDirectoryListingPatterns(webResponse.HttpResponse.Html) with
                | Some matchedValue -> reportSecurityIssue(directoryUri, webRequest, webResponse, matchedValue)
                | None -> ()