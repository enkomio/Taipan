namespace ES.Taipan.Crawler

open System
open System.Collections.Generic
open ES.Taipan.Infrastructure.Network

type ICrawlerAddOnManager =     
    interface        
        abstract LoadAddOns: unit -> unit
        abstract GetAddOns: unit -> ICrawlerAddOn list
    end
