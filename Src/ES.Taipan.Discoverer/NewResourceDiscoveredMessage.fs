namespace ES.Taipan.Discoverer

open System
open System.Collections.Generic
open ES.Taipan.Infrastructure.Network

type NewResourceDiscoveredMessage(resourceDiscovered: ResourceDiscovered) =     
    member val Resource = resourceDiscovered with get