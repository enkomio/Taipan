namespace ES.Taipan.Fingerprinter

open System
open ES.Taipan.Infrastructure.Network

type FingerprintRequest(httpRequest: HttpRequest) =    
    member val Request = httpRequest with get

    new(uri: String) = new FingerprintRequest(new HttpRequest(uri))

    override this.ToString() =
        this.Request.ToString()