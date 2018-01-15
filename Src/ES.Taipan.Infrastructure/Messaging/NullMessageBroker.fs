namespace ES.Taipan.Infrastructure.Messaging

open System

type NullMessageBroker() =    
    member this.Subscribe(callback: Object * 'a -> unit) =
        // do nothing
        ()

    member this.Unsubscribe(subscriber: Object) =
        // do nothing
        ()

    member this.Dispatch(sender: Object, message: Object) =
    // do nothing
        ()

    interface IMessageBroker with
        member this.Subscribe(callback: Object * Envelope<'a> -> unit) =
            this.Subscribe(callback)

        member this.Unsubscribe(subscriber: Object) =
            this.Unsubscribe(subscriber)

        member this.Dispatch(sender: Object, message) =
            this.Dispatch(sender, message)