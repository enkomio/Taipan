namespace ES.Taipan.Crawler

open System
open System.Collections.Generic
open ES.Taipan.Infrastructure.Network

type CrawlerStateAddPageStatusResult =
    | MaxNumberOfPagesToCrawlReached
    | MaxNumOfRequestsToTheSamePageReached
    | HostNotAllowed
    | BasePathNoAllowed
    | ExtensionNotAllowed
    | PageAlredyPresent
    | PathBlacklisted
    | PostMethodNotAllowed
    | UnknownError
    | Success
       
