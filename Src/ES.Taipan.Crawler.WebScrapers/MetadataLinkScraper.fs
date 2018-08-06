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
type MetadataLinkScraper() = 
    member this.Name = "Metadata scraper AddOn"
    static member AddOnId = Guid.Parse("3A5FD36F-48B6-4CDE-A6BF-7871D62C8D56")
    member this.Id = MetadataLinkScraper.AddOnId
    member this.Priority = 5

    member this.DiscoverNewLinks(sourceWebLink: WebLink, webResponse: WebResponse, logProvider: ILogProvider) =
        let identifiedLinks = new List<WebLink>()

        if isValidContent(webResponse) then
            let cleanHtml = 
                RegexUtility.removeHtmlComments(webResponse.HttpResponse.Html)
                |> fun (html, _) -> RegexUtility.removeScriptContent(html)
                |> fun (html, _) -> html

            let regex = new Regex(@"<meta(.*?)(>|/>)", RegexOptions.Singleline ||| RegexOptions.Multiline ||| RegexOptions.IgnoreCase)
            let mutable regexMatch = regex.Match(cleanHtml)

            // for each metadata tag found check if the are new link definition
            while regexMatch.Success do
                let matchText = regexMatch.Groups.[0].Value
                let tagBody = regexMatch.Groups.[1].Value
                regexMatch <- regexMatch.NextMatch()

                // those two attributes contains the relevant information for the refresh link
                let httpEquivAttributeValue = RegexUtility.getHtmlAttributeValueFromChunk(tagBody, @"http-equiv")
                let contentAttributeValue = RegexUtility.getHtmlAttributeValueFromChunk(tagBody, @"content")

                if httpEquivAttributeValue.IsSome && httpEquivAttributeValue.Value.Equals("refresh", StringComparison.OrdinalIgnoreCase) then
                    if contentAttributeValue.IsSome then
                        // delete from the content attribute value the timeout number if present
                        let contentValue =
                            let indexOfDotComma = contentAttributeValue.Value.IndexOf(';')
                            if indexOfDotComma >= 0 then contentAttributeValue.Value.Substring(indexOfDotComma + 1)
                            else contentAttributeValue.Value

                        // retrieve the refresh url and create a new web link
                        let url = RegexUtility.getHtmlAttributeValueFromChunk(contentValue.Trim(), @"url")
                        if url.IsSome then
                            let sourceAbsoluteUri = sourceWebLink.Request.HttpRequest.Uri.AbsoluteUri
                            let absoluteUriStringOpt = WebUtility.getAbsoluteUriStringValueSameHost(sourceAbsoluteUri, url.Value)
                            if absoluteUriStringOpt.IsSome then
                                let newWebRequest = new WebRequest(new Uri(absoluteUriStringOpt.Value))
                                newWebRequest.HttpRequest.Headers.Add(new HttpHeader(Name = "Referer", Value = sourceWebLink.Request.HttpRequest.Uri.AbsoluteUri))
                                let newWebLink = new WebLink(newWebRequest, matchText, sourceWebLink.SessionId)
                                identifiedLinks.Add(newWebLink)
                    
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


