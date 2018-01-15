namespace ES.Taipan.Crawler

open System
open System.Net
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Infrastructure.Network
open ES.Fslog

type CrawlerLogger() =
    inherit LogSource("DefaultCrawler")

    [<Log(1, Message = "Added web page to crawl: {0} [{1}]", Level = LogLevel.Verbose)>]
    member this.NewPageAdded(webLink: WebLink) = 
        let referer = 
            match HttpUtility.tryGetHeader("Referer", webLink.Request.HttpRequest.Headers) with
            | Some refHdr -> refHdr.Value
            | None -> String.Empty

        this.WriteLog(1, [|webLink; referer|])

    [<Log(2, Message = "{0} [Referer: {1}] {2}=> {3} - Length: {4}", Level = LogLevel.Informational)>]
    member this.PageProcessed(webLink: WebLink, response: HttpResponse) = 
        let modification =  if webLink.OriginalWebLink.IsSome then "[Mutation] " else String.Empty
        let referer = 
            match HttpUtility.tryGetHeader("Referer", webLink.Request.HttpRequest.Headers) with
            | Some refHdr -> refHdr.Value
            | None -> String.Empty
            
        let statusCode =
            if HttpUtility.isRedirect(response.StatusCode) then
                match HttpUtility.tryGetHeader("Location", response.Headers) with
                | Some hdr -> String.Format("{0} to {1}", response.StatusCode, hdr.Value)
                | _ -> response.StatusCode.ToString()
            else response.StatusCode.ToString()
        this.WriteLog(2, [|webLink; referer; modification; statusCode; response.Html.Length|])

    [<Log(3, Message = "Limit of {0} maximum pages to crawl reached", Level = LogLevel.Warning)>]
    member this.LimitOfMaxNumberOfPagesToCrawlReached(limit: Int32) =
        this.WriteLog(3, [|limit.ToString()|])

    [<Log(4, Message = "Crawler Stopped", Level = LogLevel.Informational)>]
    member this.CrawlerStopped() =
        this.WriteLog(4, [||])

    [<Log(5, Message = "Crawler Paused", Level = LogLevel.Informational)>]
    member this.CrawlerPaused() =
        this.WriteLog(5, [||])

    [<Log(6, Message = "Crawler Resumed", Level = LogLevel.Informational)>]
    member this.CrawlerResumed() =
        this.WriteLog(6, [||])

    [<Log(7, Message = "Activated addOn: {0}", Level = LogLevel.Verbose)>]
    member this.AddOnActivated(addOnName: String) =
        this.WriteLog(7, [|addOnName|])

    [<Log(8, Message = "Stop requested", Level = LogLevel.Verbose)>]
    member this.StopRequested() =
        this.WriteLog(8, [||])

    [<Log(9, Message = "Stop requested and wait for RunToCompletation message", Level = LogLevel.Verbose)>]
    member this.WaitRunToCompletation() =
        this.WriteLog(9, [||])

    [<Log(10, Message = "RunToCompletation message received", Level = LogLevel.Verbose)>]
    member this.RunToCompletation() =
        this.WriteLog(10, [||])

    [<Log(11, Message = "Go in Idle state", Level = LogLevel.Verbose)>]
    member this.GoIdle() =
        this.WriteLog(11, [||])