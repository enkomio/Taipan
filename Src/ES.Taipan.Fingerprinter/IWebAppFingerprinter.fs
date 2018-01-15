namespace ES.Taipan.Fingerprinter

open System
open System.Collections.Generic
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Infrastructure.Service

type IWebAppFingerprinter =
    interface
        inherit IService
        abstract Fingerprint : FingerprintRequest -> List<WebApplicationIdentified>
        abstract NoMoreWebRequestsToProcess : IEvent<IWebAppFingerprinter> with get
    end

