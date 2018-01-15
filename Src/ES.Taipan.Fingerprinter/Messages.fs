namespace ES.Taipan.Fingerprinter

open System
open System.Collections.Generic
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Infrastructure.Service

type GetAvailableVersionsMessage(id: Guid, appName: String) =
    member val Application = appName with get
    member val Id = id with get

type AvailableApplicationVersionMessage(appName: String, versions: String list, requestId: Guid) =
    member val Application = appName with get
    member val Versions = versions with get
    member val RequestId = requestId with get

type NewWebApplicationIdentifiedMessage(webAppIdentified: WebApplicationIdentified) =     
    member val WebApplication = webAppIdentified with get