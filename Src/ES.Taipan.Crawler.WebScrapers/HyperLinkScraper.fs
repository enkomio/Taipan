namespace ES.Taipan.Crawler.WebScrapers

open System
open System.Collections.Generic
open System.Text.RegularExpressions
open System.ComponentModel.Composition
open System.ComponentModel.Composition.Hosting
open ES.Taipan.Crawler
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Infrastructure.Text
open ES.Taipan.Infrastructure.Messaging
open ES.Fslog

[<InheritedExport(typeof<ICrawlerAddOn>)>]
type HyperLinkScraper() = 
    let _allTagsRegex = @"<.*?(.*?)(>|/>)"
    let _hyperlinkAttrs = @"href|src"
    
    member this.Name = "Hyperlynk scraper AddOn"
    static member AddOnId = Guid.Parse("FF687A9E-3C00-4F04-9E08-0AC9270A9FB9")
    member this.Id = HyperLinkScraper.AddOnId   
    member this.Priority = 4

    member this.ExtractLinkFromHtml(html: String, sourceAbsoluteUri: String, sessionId: Guid) =
        seq {
            let regex = new Regex(_allTagsRegex, RegexOptions.Singleline ||| RegexOptions.Multiline ||| RegexOptions.IgnoreCase)
            let mutable regexMatch = regex.Match(html)

            // for each link found create a new link
            while regexMatch.Success do
                let matchText = regexMatch.Groups.[0].Value
                let tagBody = regexMatch.Groups.[1].Value
                regexMatch <- regexMatch.NextMatch()

                let linkFound = RegexUtility.getHtmlAttributeValueFromChunk(tagBody, _hyperlinkAttrs)
                if linkFound.IsSome then
                    let absoluteUriStringOpt = WebUtility.getAbsoluteUriStringValueSameHost(sourceAbsoluteUri, linkFound.Value)
                    if absoluteUriStringOpt.IsSome then
                        let newWebRequest = new WebRequest(new Uri(absoluteUriStringOpt.Value))
                        newWebRequest.HttpRequest.Headers.Add(new HttpHeader(Name = "Referer", Value = sourceAbsoluteUri))                        
                        yield new WebLink(newWebRequest, matchText, sessionId)
        }

    member this.DiscoverNewLinks(sourceWebLink: WebLink, webResponse: WebResponse, logProvider: ILogProvider) =
        let identifiedLinks = new List<WebLink>()

        if isValidContent(webResponse) then
            let cleanHtml = 
                RegexUtility.removeHtmlComments(webResponse.HttpResponse.Html)
                |> fun (html, _) -> RegexUtility.removeScriptContent(html)
                |> fun (html, _) -> html

            // extract all links from clean html
            this.ExtractLinkFromHtml(cleanHtml, sourceWebLink.Request.HttpRequest.Uri.AbsoluteUri, sourceWebLink.SessionId)
            |> identifiedLinks.AddRange
                    
        identifiedLinks

    interface ICrawlerAddOn with
        member this.Name 
            with get() = this.Name

        member this.Id
            with get() = this.Id

        member this.Priority
            with get() = this.Priority

        member this.DiscoverNewLinks(sourceWebLink: WebLink, webResponse: WebResponse, messageBroker: IMessageBroker, logProvider: ILogProvider) =
            upcast this.DiscoverNewLinks(sourceWebLink, webResponse, logProvider)


