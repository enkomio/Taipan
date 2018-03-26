namespace ES.Taipan.Application

open System
open System.Collections.Generic
open ES.Taipan.Infrastructure.Network

/// This class is specific to each scan instance
type ScanContext() =
    member val Id = Guid.NewGuid() with get, set
    member val StartRequest = new WebRequest("http://0.0.0.0") with get, set
    member val Template = new TemplateProfile() with get, set