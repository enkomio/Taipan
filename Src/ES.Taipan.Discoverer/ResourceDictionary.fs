namespace ES.Taipan.Discoverer

open System
open System.Collections.Generic

type ResourceDictionary(id: Guid) =
    member val Id = id with get
    member val Name = String.Empty with get, set
    member val Resources = new List<Resource>() with get

