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
type HeaderRedirectLinkScraper() = 

    let getRedirectLocation(webResponse: WebResponse) =
        webResponse.HttpResponse.Headers
        |> Seq.tryFind (fun header -> header.Name.Equals("Location", StringComparison.OrdinalIgnoreCase))

    member this.Name = "Header redirect scraper AddOn"
    static member AddOnId = Guid.Parse("D2743ED4-C0B5-4166-9DC2-828CA7C7D7B3")
    member this.Id = HeaderRedirectLinkScraper.AddOnId
    member this.Priority = 4

    member this.DiscoverNewLinks(sourceWebLink: WebLink, webResponse: WebResponse, logProvider: ILogProvider) =
        let identifiedLinks = new List<WebLink>()

        let redirectHeader = getRedirectLocation(webResponse)
        if redirectHeader.IsSome then
            let sourceAbsoluteUri = sourceWebLink.Request.HttpRequest.Uri.AbsoluteUri
            let absoluteUriStringOpt = WebUtility.getAbsoluteUriStringValueSameHost(sourceAbsoluteUri, redirectHeader.Value.Value)
            if absoluteUriStringOpt.IsSome then
                let newWebRequest = new WebRequest(new Uri(absoluteUriStringOpt.Value))
                newWebRequest.HttpRequest.Headers.Add(new HttpHeader(Name = "Referer", Value = sourceWebLink.Request.HttpRequest.Uri.AbsoluteUri))
                let newWebLink = new WebLink(newWebRequest, redirectHeader.Value.ToString(), sourceWebLink.SessionId)
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


