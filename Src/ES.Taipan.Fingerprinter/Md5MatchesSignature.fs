namespace ES.Taipan.Fingerprinter

open System
open System.Text.RegularExpressions
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Infrastructure.Text
open System.Xml.Linq
open System.Linq

type Md5MatchesSignature() =
    inherit BaseSignature()

    static let x str = XName.Get str    

    member val Id = Guid.NewGuid() with get, set
    member val FilePath = String.Empty with get, set
    member val Md5 = String.Empty with get, set

    static member Create(filePath: String, md5Value: String) =
        new Md5MatchesSignature
            (
                FilePath = filePath,
                Md5 = md5Value
            )

    static member IsValidXmlSignature(xml: String) =
        let doc = XDocument.Parse(xml)
        let root = doc.Element(x"MD5Signature")
        root <> null

    override this.Verify(directory: String, webPageRequestor: IWebPageRequestor) =
        match this.ComposeSignaturePath(directory, this.FilePath) with
        | Some urlString ->
            let httpRequest = new HttpRequest(urlString)
            httpRequest.Headers.Add(new HttpHeader(Name = "Referer", Value = directory))
            let webRequest = new WebRequest(httpRequest)
            let webResponse = webPageRequestor.RequestWebPage(webRequest)
            if webResponse.PageExists then
                let html = webResponse.HttpResponse.Html
                let md5 = toCleanTextMd5(html)
                let matchSuccess = md5.Equals(this.Md5, StringComparison.OrdinalIgnoreCase)
                new SignatureVerificationResult(matchSuccess, webRequest, webResponse, Some (this :> ISignature))
            else
                new SignatureVerificationResult(false, webRequest, webResponse, Some (this :> ISignature))
        | None -> new SignatureVerificationResult(false, new WebRequest("http://127.0.0.1"), new WebResponse(new HttpResponse()), Some (this :> ISignature))
                    
    override this.AcquireFromXml(xml: String) =
        let doc = XDocument.Parse(xml)
        let root = doc.Element(x"MD5Signature")
        this.Id <- Guid.Parse(root.Element(x"Id").Value)
        this.FilePath <- root.Element(x"FilePath").Value
        this.Md5 <- root.Element(x"MD5").Value
        
    override this.ToString() =
        String.Format("File: {0}, MD5 Value: {1}", this.FilePath, this.Md5)

    override this.Equals(o: Object) =
        match o with
        | :? Md5MatchesSignature as s -> 
            s.FilePath.Equals(this.FilePath, StringComparison.Ordinal) && 
            s.Md5.Equals(this.Md5, StringComparison.Ordinal)

        | _ -> false