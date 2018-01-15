namespace ES.Taipan.Crawler

open System
open System.Collections.Generic
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Infrastructure.Messaging
open ES.Fslog

type ICrawlerAddOn =     
    interface        
        abstract Name: String with get
        abstract Id: Guid with get
        abstract Priority: Int32 with get
        abstract DiscoverNewLinks : WebLink * WebResponse * IMessageBroker * ILogProvider -> IEnumerable<WebLink>
    end
