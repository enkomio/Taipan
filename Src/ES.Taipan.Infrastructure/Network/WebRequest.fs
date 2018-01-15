namespace ES.Taipan.Infrastructure.Network

open System
open System.Xml.Linq
open System.Linq
open System.Net

type WebRequest(httpRequest: HttpRequest) = 
    static let x str = XName.Get str
    
    new(uri: Uri) = new WebRequest(new HttpRequest(uri))
    new(uri: String) = new WebRequest(new Uri(uri))

    member val Id = Guid.NewGuid() with get, set    
    member val HttpRequest = httpRequest with get, set

    override this.ToString() =
        this.HttpRequest.ToString()

    member this.ToXml() =
        let httpRequest = this.HttpRequest
        new XElement(x"WebRequest",
            new XElement(x"Id", this.Id),
            new XElement(x"HttpRequest",
                new XElement(x"Id", httpRequest.Id),
                new XElement(x"Uri", httpRequest.Uri),
                new XElement(x"Method", httpRequest.Method),
                new XElement(x"Data", httpRequest.Data),
                new XElement(x"AllowAutoRedirect", defaultArg httpRequest.AllowAutoRedirect false),
                new XElement(x"Cookies",
                    httpRequest.Cookies
                    |> Seq.map(fun c -> 
                        new XElement(x"Cookie", 
                            new XElement(x"Name", c.Name),
                            new XElement(x"Value", c.Value)
                        )
                    )
                ),
                new XElement(x"Headers",
                    httpRequest.Headers
                    |> Seq.map(fun h -> 
                        new XElement(x"Header", 
                            new XElement(x"Id", h.Id),
                            new XElement(x"Name", h.Name),
                            new XElement(x"Value", h.Value)
                        )
                    )
                )
            )
        )

    static member FromXml(xmlStr: String) =
        let doc = XDocument.Parse(xmlStr)
        let root = doc.Element(x"WebRequest")

        let webRequest = new WebRequest("http://0.0.0.0")
        webRequest.Id <- Guid.Parse(root.Element(x"Id").Value)
        webRequest.HttpRequest.Id <- Guid.Parse(root.Element(x"HttpRequest").Element(x"Id").Value)
        webRequest.HttpRequest.Uri <- new Uri(root.Element(x"HttpRequest").Element(x"Uri").Value)
        webRequest.HttpRequest.Method <- HttpMethods.ToHttpMethod(root.Element(x"HttpRequest").Element(x"Method").Value)
        webRequest.HttpRequest.Data <- root.Element(x"HttpRequest").Element(x"Data").Value
        webRequest.HttpRequest.AllowAutoRedirect <- Some <| Boolean.Parse(root.Element(x"HttpRequest").Element(x"AllowAutoRedirect").Value)
        
        root.Element(x"HttpRequest").Elements(x"Cookies")
        |> Seq.map (fun xelem -> (xelem.Element(x"Name").Value, xelem.Element(x"Value").Value))
        |> Seq.iter(fun (name, value) -> webRequest.HttpRequest.Cookies.Add(new Cookie(name, value, Path = "/")))

        root.Element(x"HttpRequest").Elements(x"Headers")
        |> Seq.map (fun xelem -> (xelem.Element(x"Id").Value, xelem.Element(x"Name").Value, xelem.Element(x"Value").Value))
        |> Seq.iter(fun (id, name, value) -> webRequest.HttpRequest.Headers.Add(new HttpHeader(Id = Guid.Parse(id), Name = name, Value = value)))

        webRequest