namespace ES.Taipan.Infrastructure.Messaging

open System
open System.Collections.Generic

/// This kind of message is used in order to receive a result object 
/// when it was processed by all subscribers
type ResultMessage() =
    let _results = new Dictionary<Object, Object>()

    member this.AddResult(source: Object, result: Object) =
        _results.[source] <- result

    member this.GetResults() =
        _results |> Seq.readonly