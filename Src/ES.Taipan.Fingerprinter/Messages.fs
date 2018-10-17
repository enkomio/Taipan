namespace ES.Taipan.Fingerprinter

open System
open System.Collections.Generic
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Infrastructure.Service

type GetAvailableVersionsMessage(id: Guid, appName: String) =
    member val Application = appName with get
    member val Id = id with get
    member val Versions = List.empty<String> with get, set

type NewWebApplicationIdentifiedMessage(webAppIdentified: WebApplicationIdentified) =     
    member val WebApplication = webAppIdentified with get