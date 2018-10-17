namespace ES.Taipan.Inspector

open System
open System.Threading
open System.Threading.Tasks
open System.Collections.Concurrent
open System.ComponentModel.Composition
open ES.Taipan.Inspector
open ES.Taipan.Infrastructure.Service
open ES.Taipan.Infrastructure.Messaging
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Crawler
open ES.Fslog

[<InheritedExport(typeof<IVulnerabilityScannerAddOn>)>]
[<AbstractClass>]
type BaseStatelessAddOn(name: String, id: String, priority: Int32) =      
    let _syncRoot = new Object()
    let mutable _serviceMetrics = new ServiceMetrics(name)
    let mutable _isInitialized = false
    let mutable _pendingMessageIds = Map.empty<Guid, ManualResetEventSlim>
    let mutable _completedRequests = Map.empty<Guid, WebLinksExtractedMessage>

    let handleWebLinksExtractedMessage(sender: Object, message: Envelope<WebLinksExtractedMessage>) =        
        let id = message.Item.Id
        if _pendingMessageIds.ContainsKey(id) then
            _completedRequests <- _completedRequests.Add(id, message.Item)
            let waitLock = _pendingMessageIds.[id]
            _pendingMessageIds <- _pendingMessageIds.Remove(id)
            waitLock.Set()    

    member val Context : Context option = None with get, set
    member val MessageBroker : IMessageBroker option = None with get, set
    member val WebRequestor : IWebPageRequestor option = None with get, set
    member val LogProvide : ILogProvider option = None with get, set

    member val Id = Guid.Parse(id) with get
    member val Name = name with get
    member val Priority = priority with get

    abstract IsBackgroundService: Boolean with get
    default val IsBackgroundService = false with get
        
    abstract RunToCompletation : ServiceStateController -> unit
    default this.RunToCompletation(stateController: ServiceStateController) =
        // do nothing
        ()

    abstract Initialize : Context * IWebPageRequestor * IMessageBroker *  ILogProvider -> Boolean
    default this.Initialize(context: Context, webRequestor: IWebPageRequestor, messageBroker: IMessageBroker, logProvider: ILogProvider) =
        lock _syncRoot (fun () ->
            this.Context <- Some context
            this.WebRequestor <- Some webRequestor
            this.LogProvide <- Some logProvider
            this.MessageBroker <- Some messageBroker
            _isInitialized <- true

            _serviceMetrics <- context.ServiceMetrics            
            webRequestor.HttpRequestor.Metrics <- _serviceMetrics.GetSubMetrics(this.Name + "AddOnHttpRequestor_" + webRequestor.HttpRequestor.Id.ToString("N"))
        )

        // regist to satisfy rebuild request
        messageBroker.Subscribe<WebLinksExtractedMessage>(handleWebLinksExtractedMessage)
        true

    abstract RebuildTestRequestFromReferer: TestRequest -> TestRequest
    default this.RebuildTestRequestFromReferer(testRequest: TestRequest) =
        lock _syncRoot (fun () ->
            if not _isInitialized then
                failwith(String.Format("Add On '{0}' [{1}] must be initialized before to invoke RebuildTestRequestFromReferer", this.Name, this.Id))

            match HttpUtility.tryGetHeader("Referer", testRequest.WebRequest.HttpRequest.Headers) with
            | Some header -> 
                let webRequest = new WebRequest(header.Value)
                let webResponse = this.WebRequestor.Value.RequestWebPage(webRequest)
                let html = webResponse.HttpResponse.Html

                // send the message in order to parse the HTML
                let messageId = Guid.NewGuid()
                let rebuildWaitLock = new ManualResetEventSlim()
                let message = new ExtractWebLinksMessage(messageId, webRequest, webResponse)
                _pendingMessageIds <- _pendingMessageIds.Add(messageId, rebuildWaitLock)
                this.MessageBroker.Value.Dispatch(this, message)
                rebuildWaitLock.Wait()

                // html processed I can extract the links
                let message = _completedRequests.[messageId]
                _completedRequests <- _completedRequests.Remove(messageId)
                let link = 
                    message.Links
                    |> List.tryFind(fun webLink -> webLink.Request.HttpRequest.Uri.Equals(testRequest.WebRequest.HttpRequest.Uri))

                match link with
                | Some link -> new TestRequest(link.Request, testRequest.WebResponse, testRequest.RequestType, testRequest.GetData())
                | None -> testRequest
            | None -> testRequest
        )

    abstract Scan : TestRequest * ServiceStateController -> unit

    member this.Dispose() =
        // dispose web requestor, this is importance, since if we use the Javascript
        // Engine the dispose will tear down the browser
        if this.WebRequestor.IsSome then
            match this.WebRequestor.Value with
            | :? IDisposable as disposable -> disposable.Dispose()
            | _ -> ()

    interface IDisposable with
        member this.Dispose() =
            this.Dispose()

    interface IVulnerabilityScannerAddOn with
        member this.Id with get() = this.Id            
        member this.Name with get() = this.Name
        member this.Priority with get() = this.Priority
        member this.IsBackgroundService with get() = this.IsBackgroundService

        member this.Initialize(context: Context, webRequestor: IWebPageRequestor, messageBroker: IMessageBroker, logProvider: ILogProvider) =
            this.Initialize(context, webRequestor, messageBroker, logProvider)

        member this.Scan(testRequest: TestRequest, stateController: ServiceStateController) =
            this.Scan(testRequest, stateController)

        member this.RunToCompletation(stateController: ServiceStateController) =
            this.RunToCompletation(stateController)

