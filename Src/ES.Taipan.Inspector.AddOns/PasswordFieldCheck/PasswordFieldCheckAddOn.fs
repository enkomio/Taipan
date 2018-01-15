namespace ES.Taipan.Inspector.AddOns.PasswordFieldCheck

open System
open System.Net
open System.Threading
open System.Collections.Generic
open System.Collections.Concurrent
open System.Text.RegularExpressions
open ES.Taipan.Inspector
open ES.Taipan.Inspector.AddOns
open ES.Taipan.Infrastructure.Service
open ES.Taipan.Infrastructure.Messaging
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Fingerprinter
open ES.Taipan.Crawler
open ES.Taipan.Crawler.WebScrapers
open ES.Taipan.Infrastructure.Text
open ES.Fslog

[<AutoOpen>]
module private PasswordFieldCheck =    
    let createSecurityIssue(action: Uri, inputHtml: String, testRequest: TestRequest, id: Guid, name: String, parameterName: String) =        
        let securityIssue = 
            new SecurityIssue(
                id, 
                Name = name,
                Uri = testRequest.WebRequest.HttpRequest.Uri, 
                EntryPoint = if testRequest.WebRequest.HttpRequest.Method = HttpMethods.Post then EntryPoint.DataString else EntryPoint.QueryString
            )
        securityIssue.Details.Properties.Add("Parameter", parameterName)
        securityIssue.Details.Properties.Add("Action", action.AbsoluteUri)
        securityIssue.Details.Properties.Add("Html", inputHtml)
        securityIssue.Details.Properties.Add("Synopsis", String.Format("{0} - Parameter: {1}", testRequest.WebRequest.HttpRequest.Uri.AbsolutePath, parameterName))
        securityIssue.Transactions.Add(testRequest.WebRequest, testRequest.WebResponse)        
        securityIssue        
        
    let getAllPasswordInputs(testRequest: TestRequest, messageBroker: IMessageBroker) = [
        let html = testRequest.WebResponse.HttpResponse.Html
        for formHtml in RegexUtility.getAllHtmlTags(html, "form") do
            let action = new Uri(testRequest.WebRequest.HttpRequest.Uri, defaultArg (RegexUtility.getHtmlAttributeValueFromChunk(formHtml, "action")) String.Empty)
            for inputHtml in RegexUtility.getAllHtmlTags(formHtml, "input") do
                    let inputType = RegexUtility.getHtmlInputValue(inputHtml, "type")
                    if inputType.Equals("password", StringComparison.Ordinal) then
                        let parameterName = defaultArg (RegexUtility.getHtmlAttributeValueFromChunk(inputHtml, "name")) "N/A"
                        yield (action, inputHtml, parameterName)
    ]     
                
type PasswordSentOverHttpAddOn() =
    inherit BaseStatelessAddOn("Password sent over HTTP AddOn", "5B4B319D-E0D8-4FBF-83B3-C8E71BA65D35", 1)
    let _analyzedPages = new HashSet<String>()
    let _syncRoot = new Object()

    member this.IsPathNew(path: String) =
        lock _syncRoot (fun () ->
            _analyzedPages.Add(path)
        )   
        
    default this.Scan(testRequest: TestRequest, stateController: ServiceStateController) =
        if this.IsPathNew(testRequest.WebRequest.HttpRequest.Uri.AbsolutePath) then
            getAllPasswordInputs(testRequest, this.MessageBroker.Value)
            |> List.iter(fun (action, tagHtml, parameterName) ->
                if action.Scheme.Equals("http", StringComparison.Ordinal) then   
                    let securityIssue = createSecurityIssue(action, tagHtml, testRequest, this.Id, "Sensitive Information Sent Via Unencrypted Channels", parameterName)
                    this.Context.Value.AddSecurityIssue(securityIssue)
            )

type MissingAutocompleteOffAttributeAddOn() =
    inherit BaseStatelessAddOn("Missing Autocomple Off Flag AddOn", "85EF16CC-3682-4CDC-A2F5-A5FD889474FF", 1)
    let _analyzedPages = new HashSet<String>()
    let _syncRoot = new Object()

    member this.IsPathNew(path: String) =
        lock _syncRoot (fun () ->
            _analyzedPages.Add(path)
        )   
        
    default this.Scan(testRequest: TestRequest, stateController: ServiceStateController) =
        if this.IsPathNew(testRequest.WebRequest.HttpRequest.Uri.AbsolutePath) then
            getAllPasswordInputs(testRequest, this.MessageBroker.Value)
            |> List.iter(fun (action, tagHtml, parameterName) ->
                let mutable isVulnerable = false
                match RegexUtility.getHtmlAttributeValueFromChunk(tagHtml, "autocomplete") with
                | Some autocomplete -> isVulnerable <- autocomplete.ToLower().Contains("on")
                | None -> isVulnerable <- true

                if isVulnerable then
                    let securityIssue = createSecurityIssue(action, tagHtml, testRequest, this.Id, "Password Field With Autocomplete Enabled", parameterName)
                    this.Context.Value.AddSecurityIssue(securityIssue)
            )