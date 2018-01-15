namespace ES.Taipan.Infrastructure.Messaging

open System

[<AutoOpen>]
module Envelope =

    [<CLIMutable>]
    type Envelope<'a> = {
        Id : Guid
        Created : DateTimeOffset
        Item : 'a }

    let envelop id created item = {
        Id = id
        Created = created
        Item = item }

    let envelopWithDefaults item =
        envelop (Guid.NewGuid()) (DateTimeOffset.Now) item

