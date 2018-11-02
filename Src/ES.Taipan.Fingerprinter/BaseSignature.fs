namespace ES.Taipan.Fingerprinter

open System

open ES.Taipan.Infrastructure.Network
open ES.Taipan.Infrastructure.Text

[<AbstractClass>]
type BaseSignature() =
    
    member val Id = Guid.NewGuid() with get, set
    abstract Verify: String * IWebPageRequestor -> SignatureVerificationResult
    abstract AcquireFromXml : String -> unit

    member this.ComposeSignaturePath(directory: String, path: String) =
        let mutable normalizedPath = path.Replace("\\", "/")
        if normalizedPath.StartsWith("/")
        then normalizedPath <- normalizedPath.Substring(1)
        WebUtility.getAbsoluteUriStringValueSameHost(directory, normalizedPath)

    interface ISignature with

        member this.Verify(directory: String, webPageRequestor: IWebPageRequestor) =
            this.Verify(directory, webPageRequestor)

        member this.AcquireFromXml(xml: String) =
            this.AcquireFromXml(xml)
            
        member this.Id
            with get() = this.Id
            and set(v) = this.Id <- v

