namespace ES.Taipan.Fingerprinter

open System

open ES.Taipan.Infrastructure.Network

[<AbstractClass>]
type BaseSignature() =
    
    member val Id = Guid.NewGuid() with get, set
    abstract Verify: String * IWebPageRequestor -> SignatureVerificationResult
    abstract AcquireFromXml : String -> unit

    interface ISignature with

        member this.Verify(directory: String, webPageRequestor: IWebPageRequestor) =
            this.Verify(directory, webPageRequestor)

        member this.AcquireFromXml(xml: String) =
            this.AcquireFromXml(xml)
            
        member this.Id
            with get() = this.Id
            and set(v) = this.Id <- v

