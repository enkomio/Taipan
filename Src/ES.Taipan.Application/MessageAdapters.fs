namespace ES.Taipan.Application

open System
open System.Collections.Generic
open ES.Taipan.Crawler
open ES.Taipan.Inspector
open ES.Taipan.Fingerprinter
open ES.Taipan.Discoverer
open ES.Taipan.Infrastructure.Network

[<AutoOpen>]
module MessageAdapters =

    // page re-processed conversion functions
    let convertPageReProcessedToTestRequest(message: PageReProcessedMessage) =
        new TestRequest(message.Link.Request, message.WebResponse, ReCrawledPage, message.Link)

    // page processed conversion functions
    let convertPageProcessedToTestRequest(message: PageProcessedMessage) =
        new TestRequest(message.Link.Request, message.WebResponse, CrawledPage, message.Link)

    let convertPageProcessedToFingerprintRequest(message: PageProcessedMessage) =
        new FingerprintRequest(message.Link.Request.HttpRequest)

    let convertPageProcessedToResourceDiscovererRequest(message: PageProcessedMessage) =
        new DiscoverRequest(message.Link.Request.HttpRequest)

    // resource discovered conversion functions
    let convertNewResourceDiscoveredToFingerprintRequest(message: NewResourceDiscoveredMessage) =
        new FingerprintRequest(message.Resource.Request)

    let convertNewResourceDiscoveredToTestRequest(message: NewResourceDiscoveredMessage) =
        let webRequest = new WebRequest(message.Resource.Request)
        let emptyWebResponse = new WebResponse(new HttpResponse())
        new TestRequest(webRequest, emptyWebResponse, HiddenResource, message.Resource)

    let convertNewResourceDiscoveredToCrawlRequest(message: NewResourceDiscoveredMessage) =
        new CrawlRequest(new WebRequest(message.Resource.Request)) 
        
    // fingerprinter conversion functions   
    let convertWebApplicationIdentifiedToTestRequest(message: NewWebApplicationIdentifiedMessage) =
        let webRequest = new WebRequest(message.WebApplication.Request.Request)
        let emptyWebResponse = new WebResponse(new HttpResponse())
        new TestRequest(webRequest, emptyWebResponse, TestRequestType.WebApplicationIdentified, message.WebApplication)