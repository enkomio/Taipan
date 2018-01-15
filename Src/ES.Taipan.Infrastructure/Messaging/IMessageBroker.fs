namespace ES.Taipan.Infrastructure.Messaging

open System

type IMessageBroker =
    interface
        abstract Subscribe : callback: (Object * Envelope<'a> -> unit) -> unit
        abstract Unsubscribe : subscriber: Object -> unit
        abstract Dispatch : sender : Object * _ -> unit
    end