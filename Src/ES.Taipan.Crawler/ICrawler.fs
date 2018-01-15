namespace ES.Taipan.Crawler

open System
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Infrastructure.Service

type ICrawler =     
    interface
        inherit IService
        abstract CrawlRequest : WebRequest -> unit
        abstract State : CrawlerState with get
        abstract NoMoreWebRequestsToProcess : IEvent<ICrawler> with get
        abstract LinkMutator : WebLinkMutator option with get, set
        abstract Run : HttpRequest -> Boolean
        abstract SetAuthentication : AuthenticationType -> unit
        abstract TriggerIdleState: unit -> unit
    end
