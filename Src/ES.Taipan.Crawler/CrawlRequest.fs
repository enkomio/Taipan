namespace ES.Taipan.Crawler

open System
open System.Collections.Generic
open ES.Taipan.Infrastructure.Network

type CrawlRequest(request: WebRequest) =    
    member val Request = request with get