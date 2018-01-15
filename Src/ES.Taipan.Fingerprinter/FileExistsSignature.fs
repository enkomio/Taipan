namespace ES.Taipan.Fingerprinter

open System
open System.Text.RegularExpressions
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Infrastructure.Text
open System.Xml.Linq
open System.Linq

type FileExistsSignature() =
    inherit BaseSignature()

    static let x str = XName.Get str

    member val Id = Guid.NewGuid() with get, set
    member val FilePath = String.Empty with get, set

    static member Create(filePath: String) =
        new FileExistsSignature
            (
                FilePath = filePath
            )

    static member IsValidXmlSignature(xml: String) =
        let doc = XDocument.Parse(xml)
        let root = doc.Element(x"FileExistsSignature")
        root <> null

    override this.Verify(directory: String, webPageRequestor: IWebPageRequestor) =
        match WebUtility.getAbsoluteUriStringValueSameHost(directory, this.FilePath) with
        | Some urlString ->
            let httpRequest = new HttpRequest(urlString)
            httpRequest.Headers.Add(new HttpHeader(Name = "Referer", Value = directory))
            let webRequest = new WebRequest(httpRequest)
            let webResponse = webPageRequestor.RequestWebPage(webRequest)
            new SignatureVerificationResult(webResponse.PageExists, webRequest, webResponse, Some (this :> ISignature))
        | None -> new SignatureVerificationResult(false, new WebRequest("http://127.0.0.1"), new WebResponse(new HttpResponse()), Some (this :> ISignature))
           
    override this.AcquireFromXml(xml: String) =
        let doc = XDocument.Parse(xml)
        let root = doc.Element(x"FileExistsSignature")
        this.Id <- Guid.Parse(root.Element(x"Id").Value)
        this.FilePath <- root.Element(x"FilePath").Value

    override this.ToString() =
        String.Format("File: {0}", this.FilePath)

    override this.Equals(o: Object) =
        match o with
        | :? FileExistsSignature as s -> s.FilePath.Equals(this.FilePath, StringComparison.Ordinal) 
        | _ -> false