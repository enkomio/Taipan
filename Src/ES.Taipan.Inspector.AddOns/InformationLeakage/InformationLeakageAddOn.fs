namespace ES.Taipan.Inspector.AddOns.InformationLeakage

open System
open System.Text
open System.Threading
open System.Collections.Generic
open System.Collections.Concurrent
open System.Text.RegularExpressions
open ES.Taipan.Inspector
open ES.Taipan.Inspector.AddOns
open ES.Taipan.Infrastructure.Service
open ES.Taipan.Infrastructure.Messaging
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Infrastructure.Text
open ES.Taipan.Fingerprinter
open ES.Taipan.Crawler
open ES.Fslog

type InformationLeakageAddOn() as this =
    inherit BaseStatelessAddOn("Information Leakage AddOn", "AFA1E309-2AC4-4504-86BD-35216950CEFA", 1)       
    let _analyzedPages = new HashSet<String>()
    let _signaledLeakage = new HashSet<String>()

    let getHtmlComments(html: String) =
        seq {
            let mutable m = Regex.Match(html, "<!--(.+?)-->", RegexOptions.Singleline)
            while m.Success do
                yield m.Groups.[1].Value.Trim()
                m <- m.NextMatch()
        }
        
    let extractEmailsFromComments(html: String) =
        seq {
            for comment in getHtmlComments(html) do
                let mutable m = Regex.Match(comment.ToUpperInvariant(), "[A-Z0-9._%-]+@[A-Z0-9.-]+\.[A-Z]{2,4}", RegexOptions.Singleline)
                while m.Success do
                    let email = comment.Substring(m.Index, m.Length).Trim()
                    let isValidTld = TldList.tdlList |> Array.exists(fun validTld -> email.EndsWith("." + validTld, StringComparison.OrdinalIgnoreCase))
                    if isValidTld then 
                        yield email
                    m <- m.NextMatch()
        }

    let blacklistedEmail = ["contact"; "hello"; "info"; "sales"]
    let extractEmails(rawHtml: String) =
        seq {
            let (html, _) = RegexUtility.removeHtmlComments(rawHtml)
            let mutable m = Regex.Match(html, "([A-Z0-9._%-]+)@[A-Z0-9.-]+\.[A-Z]{2,4}", RegexOptions.Singleline ||| RegexOptions.IgnoreCase)
            while m.Success do
                let email = m.Groups.[0].Value.Trim()
                let name = m.Groups.[1].Value.Trim()
                if not(blacklistedEmail |> List.contains name) then
                    yield email
                m <- m.NextMatch()
        }
        
    let extractIps(html: String) =
        seq {
            let mutable m = Regex.Match(html, "127\.0\.0\.1|10(\.[0-9]{1,3}){3}|172\.1[6-9]\.[0-9\.]+|172\.2[0-9]\.[0-9\.]+|172\.3[0-1]\.[0-9\.]+|192\.168\.[0-9\.]+", RegexOptions.Singleline)
            while m.Success do
                yield m.Groups.[0].Value.Trim()
                m <- m.NextMatch()
        }

    let extractCommentedLinks(webLink: WebLink) =
        seq {
            if webLink.OriginalWebLink.IsSome && webLink.ParsedHtmlCode.StartsWith("<!--") && webLink.ParsedHtmlCode.EndsWith("-->") then
                match HttpUtility.tryGetHeader("Referer", webLink.Request.HttpRequest.Headers) with
                | Some referer ->
                    // this found in comment, report as leak
                    yield referer.Value
                | None -> ()
        }   
        
    let extractStrings(data: Byte array) =
        let strings = new HashSet<String>()
        let currentString = new StringBuilder()
        for b in data do
            let c = Convert.ToChar(b)
            if c >= '-' && c <= 'z' then
                currentString.Append(c) |> ignore
            elif currentString.Length > 0 then
                ignore(
                    strings.Add(currentString.ToString()),
                    currentString.Clear()
                )

        if currentString.Length > 0 then
            strings.Add(currentString.ToString()) |> ignore

        strings

    let extractPathFromHiddenResource(testRequest: TestRequest) =
        let uris = new HashSet<String>()
        if 
            [".DS_Store"; ".log"; ".swp"; ".bp"; ".bak"; "thumbs.db"; ".raw"; ".conf"; ".ini"; ".txt"; ".csv"]
            |> List.exists(testRequest.WebRequest.HttpRequest.Uri.AbsolutePath.EndsWith) 
        then
            let data = this.WebRequestor.Value.HttpRequestor.DownloadData(testRequest.WebRequest.HttpRequest)
            extractStrings(data)
            |> Seq.filter(fun str -> Regex.IsMatch(str, "\\.[a-zA-Z0-9]+$"))
            |> Seq.iter(fun str ->
                // try to request this path to see if the file really exists
                match WebUtility.getAbsoluteUriStringValueSameHost(testRequest.WebRequest.HttpRequest.Uri.AbsoluteUri, str) with
                | Some newUri ->
                    let webRequest = new WebRequest(newUri)
                    let webResponse = this.WebRequestor.Value.RequestWebPage(webRequest)
                    if webResponse.PageExists then
                        // found a potential hidden file
                        uris.Add(newUri) |> ignore
                | _ -> ()
            )  
        uris
            
    let reportSecurityIssue(uri: Uri, webRequest: WebRequest, webResponse: WebResponse) (tagName: String) (rawTagValues: String seq) =
        if not(rawTagValues |> Seq.isEmpty) then
            let tagValues = rawTagValues |> Seq.sort |> Seq.distinct
            let allValues = String.Format("{0} = {1}", tagName, String.Join(",", tagValues))
            let leakKey = uri.AbsolutePath + allValues

            if _signaledLeakage.Add(leakKey) then
                let securityIssue = 
                    new SecurityIssue(
                        this.Id, 
                        Name = "Information Leakage", 
                        Uri = uri, 
                        EntryPoint = EntryPoint.Other "Page Content",
                        Note = allValues
                    )
                securityIssue.Transactions.Add(webRequest, webResponse)

                for tagValue in tagValues do
                    let mutable effectiveTagName = tagName
                    let index = ref 1
                    while securityIssue.Details.Properties.ContainsKey(effectiveTagName) do
                        effectiveTagName <- tagName + " " + (!index).ToString()
                        incr index
                    securityIssue.Details.Properties.Add(effectiveTagName, tagValue)

                this.Context.Value.AddSecurityIssue(securityIssue)
                        
    default this.Scan(testRequest: TestRequest, stateController: ServiceStateController) =
        if _analyzedPages.Add(testRequest.WebRequest.HttpRequest.Uri.PathAndQuery) then
            let html = testRequest.WebResponse.HttpResponse.Html            
            let securityIssueReporter = reportSecurityIssue(testRequest.WebRequest.HttpRequest.Uri, testRequest.WebRequest, testRequest.WebResponse)

            extractIps(html) |> (securityIssueReporter "Ip")
            extractEmailsFromComments(html) |> (securityIssueReporter "Email in HTML comment")
            extractEmails(html) |> (securityIssueReporter "Email")            
            extractPathFromHiddenResource(testRequest) |> (securityIssueReporter "File content has hidden resource")  

            // check hidden link. I have to do this dirty trick because I want to use the HTML parsing 
            // of the crawler to found Hyperlinks, otherwise I have to replicate here part of the html parsing
            match testRequest.GetData<Object>() with
            | :? WebLink as webLink -> 
                extractCommentedLinks(testRequest.GetData<WebLink>()) 
                |> Seq.iter(fun pageWithHiddenLinkEmbedded ->
                    let hiddenLink = testRequest.WebRequest.HttpRequest.Uri.ToString()
                    if _signaledLeakage.Add(hiddenLink) then
                        let securityIssue = 
                            new SecurityIssue(
                                this.Id, 
                                Name = "Information Leakage", 
                                Uri = new Uri(pageWithHiddenLinkEmbedded), 
                                EntryPoint = EntryPoint.Other "Page Content",
                                Note = "Hidden Link = " + hiddenLink
                            )
                        securityIssue.Transactions.Add(testRequest.WebRequest,  testRequest.WebResponse)
                            
                        let mutable effectiveTagName = "Link"
                        let index = ref 1
                        while securityIssue.Details.Properties.ContainsKey(effectiveTagName) do
                            effectiveTagName <- "Link " + (!index).ToString()
                            incr index

                        securityIssue.Details.Properties.Add(effectiveTagName, hiddenLink)
                        this.Context.Value.AddSecurityIssue(securityIssue)
                )
            | _ -> ()