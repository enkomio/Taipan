namespace ES.Taipan.Discoverer

open System
open ES.Taipan.Infrastructure.Service

type IResourceDiscoverer =    
    interface
        inherit IService
        abstract Discover: DiscoverRequest -> ResourceDiscovered list
        abstract NoMoreWebRequestsToProcess : IEvent<IResourceDiscoverer> with get
    end

