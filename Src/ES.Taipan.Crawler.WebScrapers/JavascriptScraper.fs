namespace ES.Taipan.Crawler.WebScrapers

open System
open System.Threading
open System.IO
open System.Reflection
open System.Collections.Concurrent
open System.Collections.Generic
open System.ComponentModel.Composition
open System.ComponentModel.Composition.Hosting
open Newtonsoft.Json
open ES.Taipan.Crawler
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Infrastructure.Common
open ES.Taipan.Infrastructure.Text
open ES.Taipan.Infrastructure.Messaging
open ES.Fslog

[<InheritedExport(typeof<ICrawlerAddOn>)>]
type JavascriptScraper() as this = 
    let _messages = new ConcurrentDictionary<Guid, WebLinksExtractedMessage>()
    let _seleniumInitializationLock = new Object()
    let mutable _seleniumDriver : SeleniumDriver option = None
    let mutable _isInitialized = false            

    let handleWebLinksExtractedMessage (waitLock: ManualResetEventSlim) (id: Guid) (sender: Object, message: Envelope<WebLinksExtractedMessage>) =
        _messages.[id] <- message.Item
        waitLock.Set()

    let initialize(messageBroker: IMessageBroker, logProvider: ILogProvider) =
        lock _seleniumInitializationLock (fun () ->
            if not _isInitialized then
                let getSettings = new GetSettingsMessage(Guid.NewGuid())
                messageBroker.Dispatch(this, getSettings)

                _seleniumDriver <- Some <| new SeleniumDriver(logProvider)
                _seleniumDriver.Value.ProxyUrl <- getSettings.HttpRequestorSettings.Value.ProxyUrl

                _seleniumDriver.Value.Initialize()
                _isInitialized <- true
        )        

    member this.Name = "Javascript scraper AddOn"
    static member AddOnId = Guid.Parse("CC166F23-51BB-4E64-A0DC-30D19CAC1A43")
    member this.Id = JavascriptScraper.AddOnId
    member this.Priority = 2

    member this.DiscoverNewLinks(sourceWebLink: WebLink, webResponse: WebResponse, messageBroker: IMessageBroker, logProvider: ILogProvider) =
        let identifiedLinks = new List<WebLink>()

        if isValidContentType(webResponse) then            
            if webResponse.PageExists && sourceWebLink.OriginalWebLink.IsNone then
                initialize(messageBroker, logProvider)

                let httpRequest = sourceWebLink.Request.HttpRequest
                let savedValue = httpRequest.Source
                httpRequest.Source <- Some {
                    ElementId = String.Empty
                    DocumentHtml = webResponse.HttpResponse.Html
                    Info = String.Empty
                }
                                    
                let file = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "JavascriptScraper.js")
                let jsSrc = File.ReadAllText(file)

                match _seleniumDriver.Value.ExecuteScript(httpRequest, jsSrc, new Dictionary<String, Object>()) with
                | Some dict -> 
                    let pageHtml = string dict.["html"]
                    let result = dict.["output"] :?> Dictionary<String, Object>                    
                    let extractedLinks = result.["Result"] :?> IEnumerable<Object>

                    for item in extractedLinks do
                        // get properties values
                        let extractedLink = item :?> Dictionary<String, Object>
                        let elementId = string extractedLink.["Id"]
                        let html = string extractedLink.["Html"]
                        let url = string extractedLink.["Url"]
                        let events = string extractedLink.["Events"]

                        match WebUtility.getAbsoluteUriStringValueSameHost(httpRequest.Uri.AbsoluteUri, url) with
                        | Some url ->
                            // create message to parse output to extract links
                            let forgedResponse = new HttpResponse(Html = html)
                            forgedResponse.Headers.Add(new HttpHeader(Name = "Content-Type", Value ="text/html"))
                            let id = Guid.NewGuid()
                            let extractLinkMessage = new ExtractWebLinksMessage(id, new WebRequest(url), new WebResponse(forgedResponse, PageExists = true))
                            extractLinkMessage.BlackListedAddOn <- [this.Id]

                            // send message and wait for response       
                            let waitLock = new ManualResetEventSlim()                               
                            messageBroker.Subscribe(handleWebLinksExtractedMessage waitLock id)
                            messageBroker.Dispatch(this, extractLinkMessage)
                            waitLock.Wait()

                            // add extracted links and fill Source property
                            let responseMessage = _messages.[id]
                            responseMessage.Links
                            |> Seq.iter(fun webLink ->
                                webLink.Request.HttpRequest.Source <- Some {
                                    ElementId = elementId
                                    DocumentHtml = pageHtml
                                    Info = events
                                }
                                identifiedLinks.Add(webLink)
                            )       
                        | None -> ()
                | _ -> ()

                httpRequest.Source <- savedValue
                        
        identifiedLinks

    member this.Dispose() =
        if _isInitialized then
            _seleniumDriver.Value.Dispose()

    interface ICrawlerAddOn with
        member this.Name 
            with get() = this.Name

        member this.Id
            with get() = this.Id

        member this.Priority
            with get() = this.Priority

        member this.DiscoverNewLinks(sourceWebLink: WebLink, webResponse: WebResponse, messageBroker: IMessageBroker, logProvider: ILogProvider) =
            upcast this.DiscoverNewLinks(sourceWebLink, webResponse, messageBroker, logProvider)

    interface IDisposable with
        member this.Dispose() =
            this.Dispose()


