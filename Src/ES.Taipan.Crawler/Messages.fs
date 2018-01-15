namespace ES.Taipan.Crawler

open System
open System.Collections.Generic
open ES.Taipan.Infrastructure.Network

type PageProcessedMessage(link: WebLink, webResponse: WebResponse, crawlerId: Int32) =     
    member val CrawlerId = crawlerId with get
    member val Link = link with get
    member val WebResponse = webResponse with get

type NewPageAddedMessage(link: WebLink, crawlerId: Int32) =     
    member val CrawlerId = crawlerId with get
    member val Link = link with get

type ExtractWebLinksMessage(id: Guid, webRequest: WebRequest, webResponse: WebResponse) =
    member val Request = webRequest with get
    member val Response = webResponse with get
    member val Id = id
    member val BlackListedAddOn = List.empty<Guid> with get, set

type WebLinksExtractedMessage(id: Guid, webLinks: WebLink list) =
    member val Links = webLinks with get
    member val Id = id

type GetSettingsMessage(id: Guid) =
    member val Id = id
    member val CrawlerSettings: CrawlerSettings option = None with get, set
    member val HttpRequestorSettings: HttpRequestorSettings option = None with get, set