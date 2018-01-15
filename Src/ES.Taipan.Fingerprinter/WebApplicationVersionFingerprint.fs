namespace ES.Taipan.Fingerprinter

open System
open System.Globalization
open System.Collections.Generic
open ES.Taipan.Infrastructure.Network
open System.Xml.Linq
open System.Linq

type WebApplicationVersionFingerprint() =
    static let x str = XName.Get str   

    member val Id = Guid.NewGuid() with get, set
    member val Version = String.Empty with get, set
    member val Signatures = new List<BaseSignature>() with get
    member val AcceptanceRate = 1.0 with get, set

    abstract Fingeprint : IWebPageRequestor * FingerprintRequest * FingerprintingStrategy -> Boolean * FingerprintResult
    override this.Fingeprint(webPageRequestor: IWebPageRequestor, fingerprintRequest: FingerprintRequest, fingStrategy: FingerprintingStrategy) =
        let result = fingStrategy.Calculate(fingerprintRequest.Request.Uri.AbsoluteUri, this.Signatures)
        (result.IsHighThan(this.AcceptanceRate), result)

    member this.AcquireFromXml(xmlContent: String) =
        let doc = XDocument.Parse(xmlContent)
        let root = doc.Element(x"WebApplicationVersion")
        
        this.Id <- Guid.Parse(root.Element(x"Id").Value)
        this.Version <- root.Element(x"Version").Value
        this.AcceptanceRate <- Double.Parse(root.Element(x"AcceptanceRate").Value, CultureInfo.InvariantCulture)

    override this.ToString() =
        String.Format("{0} AcceptRate={1}", this.Version, this.AcceptanceRate)