namespace ES.Taipan.Fingerprinter

open System
open ES.Taipan.Infrastructure.Network

type ISignature =
    interface
        abstract Id: Guid with get, set
        abstract Verify: String * IWebPageRequestor -> SignatureVerificationResult
        abstract AcquireFromXml : String -> unit
    end

and SignatureVerificationResult(found: Boolean, request: WebRequest, response: WebResponse, signature: ISignature option) =
    member this.Found = found
    member this.Request = request
    member this.Response = response
    member val Signature = signature with get, set

    new (found, request, response) = new SignatureVerificationResult(found, request, response, None)

    override this.ToString() =
        this.Request.ToString()