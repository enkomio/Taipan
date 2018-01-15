namespace ES.Taipan.Inspector.AddOns.InformationLeakage

open System
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

type PhpInfoInformationDisclosureAddOn() as this =
    inherit BaseStatelessAddOn("PhpInfo Information Disclosure AddOn", "908DF9B9-61C5-4E45-8804-3889167853BF", 1)       
    let _analyzedPages = new HashSet<String>()
    let _phpInfoRegex = [
        "<title>phpinfo()</title>"
        "PHP logo"
        "<a href=\"http://www.php.net/\">"
    ]
                
    let createSecurityIssue(uri: Uri, webRequest: WebRequest, webResponse: WebResponse) =
        let securityIssue = 
            new SecurityIssue(
                this.Id, 
                Name = "PHPInfo Information Disclosure", 
                Uri = uri, 
                EntryPoint = EntryPoint.Other "Page Content"
            )
        securityIssue.Transactions.Add(webRequest, webResponse)
        securityIssue

    let getRegexFirstValue(text: String, pattern: String) =
        let matches = Regex.Match(text, pattern, RegexOptions.Singleline)
        match matches.Success with
        | true ->
            Some <| matches.Groups.[1].Value.Trim()
        | _ -> None

    let identifyPhpInfoDisclosure(html: String, securityIssue: SecurityIssue) =
        if _phpInfoRegex |> List.map(fun x -> x.ToLower()) |> List.forall(html.ToLower().Contains) then
            match getRegexFirstValue(html, "<h1 class=\"p\">PHP Version (.+?)</h1>") with
            | Some phpVersion ->
                securityIssue.Details.Properties.Add("PHP Version", phpVersion)
                securityIssue.Note <- String.Format("PHP version = {0}", phpVersion)
            | _ -> ()

            let mutable matches = Regex.Match(html, "<tr><td class=\"e\">(.+?)</td><td class=\"v\">(.+?)</td></tr>", RegexOptions.Singleline)
            while matches.Success do
                let proName = matches.Groups.[1].Value.Trim()
                let propValue = matches.Groups.[2].Value.Trim()

                let mutable effectivePropName = proName
                let index = ref 1
                while securityIssue.Details.Properties.ContainsKey(effectivePropName) do
                    effectivePropName <- proName + (!index).ToString()
                    incr index

                securityIssue.Details.Properties.Add(effectivePropName, propValue)
                matches <- matches.NextMatch()

            // finally add the security issue
            this.Context.Value.AddSecurityIssue(securityIssue)
                        
    default this.Scan(testRequest: TestRequest, stateController: ServiceStateController) =
        if testRequest.WebResponse.PageExists && _analyzedPages.Add(testRequest.WebRequest.HttpRequest.Uri.AbsolutePath) then
            let html = testRequest.WebResponse.HttpResponse.Html            
            let securityIssue = createSecurityIssue(testRequest.WebRequest.HttpRequest.Uri, testRequest.WebRequest, testRequest.WebResponse)
            identifyPhpInfoDisclosure(html, securityIssue)