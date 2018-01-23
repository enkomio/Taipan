namespace ES.Taipan.Infrastructure.Messaging

open System
open System.Collections.Generic

type DefaultMessageBroker() =
    let _subscriberLock = new Object()
    let _messageSubscribers = new Dictionary<Type, List<Object>>()
    
    let getSubscriberFor(message: 'a) =
        lock _subscriberLock (fun _ ->
            _messageSubscribers
            |> Seq.filter( fun kv -> kv.Key.IsAssignableFrom(message.GetType()))
            |> Seq.map (fun kv -> kv.Value)
            |> Seq.concat
            |> Seq.map(fun o -> 
                o :?> (Object * Envelope<_> -> unit)
            )
            |> Seq.toList
        )
        
    member this.Subscribe(callback: Object * Envelope<'a> -> unit) =
        let subscriberType = typeof<'a>
        lock _subscriberLock (fun _ ->
            if _messageSubscribers.ContainsKey(subscriberType) then
                _messageSubscribers.[subscriberType].Add(callback)
            else
                let newList = new List<Object>()
                newList.Add(callback)
                _messageSubscribers.Add(subscriberType, newList)
        )

    member this.Unsubscribe<'a>(subscriber: 'a) =
        lock _subscriberLock (fun _ ->                        
            // delete the specified subscriber
            for subscriberList in _messageSubscribers.Values do
                if subscriberList |> Seq.exists(fun sub -> Object.ReferenceEquals(sub, subscriber)) then
                    subscriberList.Remove(subscriber) |> ignore
                    
            // delete all empty list of subscriber
            _messageSubscribers
            |> Seq.toList
            |> List.filter (fun kv -> kv.Value.Count = 0)
            |> List.iter (fun kv -> _messageSubscribers.Remove(kv.Key) |> ignore)
        )

    member this.Dispatch(sender: Object, message) =
        getSubscriberFor(message)
        |> List.iter (fun callback -> callback(sender, envelopWithDefaults message))

    interface IMessageBroker with
        member this.Subscribe(callback: Object * Envelope<_> -> unit) =     
            this.Subscribe(callback)
            
        member this.Unsubscribe(subscriber: Object) =
            this.Unsubscribe(subscriber)

        member this.Dispatch(sender: Object, message) =
            this.Dispatch(sender, message)