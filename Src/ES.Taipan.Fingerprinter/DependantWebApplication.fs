namespace ES.Taipan.Fingerprinter

open System

type DependantWebApplication() =
    member val Id = Guid.NewGuid() with get, set
    member val ApplicationName = String.Empty with get, set

