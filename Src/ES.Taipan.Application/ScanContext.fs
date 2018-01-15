namespace ES.Taipan.Application

open System
open System.Collections.Generic
open System.Xml.Linq
open System.Linq
open System.Net
open ES.Taipan.Crawler
open ES.Taipan.Inspector
open ES.Taipan.Fingerprinter
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Infrastructure.Validation
open ES.Taipan.Discoverer

/// This class is specific to each scan instance
type ScanContext() =
    let _authentications = new List<AuthenticationType>()

    member val Id = Guid.NewGuid() with get, set
    member val StartRequest = new WebRequest("http://0.0.0.0") with get, set
    member val Authentications = _authentications with get
    member val Template = new TemplateProfile() with get, set