namespace ES.Taipan.Inspector

open System
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Infrastructure.Service

type Context(addOnStorage: IAddOnStorage, serviceMetrics: ServiceMetrics, addSecIssue: SecurityIssue -> unit) =
    member val AddOnStorage = addOnStorage with get
    member val ServiceMetrics = serviceMetrics with get
    
    member this.AddSecurityIssue(secIssue: SecurityIssue) =
        addSecIssue(secIssue)