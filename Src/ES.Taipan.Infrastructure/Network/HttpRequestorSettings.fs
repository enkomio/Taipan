namespace ES.Taipan.Infrastructure.Network

open System
open System.Net
open System.Xml.Linq
open System.Linq
open System.Collections.Generic

type HttpRequestorSettings() = 
    static let x str = XName.Get str
    
    member val Id = Guid.NewGuid() with get, set

    /// timeout before to discard the request
    member val Timeout = 1000 with get, set

    /// Specify if the redirect must be followed
    member val AllowAutoRedirect = true with get, set

    /// Additional http header to add to every request sent to the host
    member val AdditionalHttpHeaders = new Dictionary<String, String>()

    /// Additional cookie to be added to every request sent to the host
    member val AdditionalCookies = new Dictionary<String, String>()
    
    /// Specify if a proxy must be used
    member val ProxyUrl : String option = None with get, set    
    
    /// Specify the optional Journey to follow before to send the requests
    member val Journey: Journey = new Journey() with get, set

    /// Specify if the authentication is enabled and its details
    member val Authentication = new AuthenticationInfo() with get, set

    /// This property specify which extension should identify static resources. A static resource is not requested via PhantomJS for performance reason
    member val StaticExtensions = new List<String>() with get, set

    /// This property specify if the Javascript engine should be used to send requests
    member val UseJavascriptEngineForRequest = true with get, set
    
    member this.ToXml() =
        let additionalHttpHeaders = new XElement(x"AdditionalHttpHeaders")
        this.AdditionalHttpHeaders
        |> Seq.iter (fun kv -> additionalHttpHeaders.Add(new XElement(x"HttpHeader", [|new XElement(x"Name", kv.Key); new XElement(x"Value", kv.Value)|])))

        let additionalCookies = new XElement(x"AdditionalCookies")
        this.AdditionalCookies
        |> Seq.iter (fun kv -> additionalCookies.Add(new XElement(x"Cookie", [|new XElement(x"Name", kv.Key); new XElement(x"Value", kv.Value)|])))
        
        let doc =
          new XDocument(
            new XElement(x"HttpRequestorSettings",
              new XElement(x"Timeout", this.Timeout),
              new XElement(x"AllowAutoRedirect", this.AllowAutoRedirect),
              new XElement(x"UseJavascriptEngineForRequest", this.UseJavascriptEngineForRequest),
              new XElement(x"Proxy",
                if this.ProxyUrl.IsSome && Uri.IsWellFormedUriString(this.ProxyUrl.Value, UriKind.Absolute) then this.ProxyUrl.Value
                else String.Empty
              ),
              new XElement(x"StaticExtensions", String.Join(",", this.StaticExtensions)),
              additionalHttpHeaders,
              additionalCookies,
              this.Journey.ToXElement(),
              this.Authentication.ToXElement()
            )            
          )
          
        doc.ToString()

    member this.AcquireSettingsFromXml(xmlSettings: String) =
        let doc = XDocument.Parse(xmlSettings)
        let root = doc.Element(x"HttpRequestorSettings")

        this.Timeout <- Int32.Parse(root.Element(x"Timeout").Value)
        this.AllowAutoRedirect <- Boolean.Parse(root.Element(x"AllowAutoRedirect").Value)
        this.UseJavascriptEngineForRequest <- Boolean.Parse(root.Element(x"UseJavascriptEngineForRequest").Value)

        this.StaticExtensions.AddRange(
            root.Element(x"StaticExtensions").Value.Split([|","|], StringSplitOptions.RemoveEmptyEntries)
            |> Array.map(fun ext -> ext.Trim())
        )

        let proxyElement = root.Element(x"Proxy")
        this.ProxyUrl <-
            if proxyElement <> null then Some <| proxyElement.Value.Trim()
            else None

        root.Element(x"AdditionalHttpHeaders").Elements(x"HttpHeader")
        |> Seq.map (fun xelem -> 
            let headerName = xelem.Element(x"Name").Value
            let headerValue = xelem.Element(x"Value").Value
            (headerName, headerValue)
        )
        |> Seq.iter (fun (headerName, headerValue) -> this.AdditionalHttpHeaders.Add(headerName, headerValue))

        root.Element(x"AdditionalCookies").Elements(x"Cookie")
        |> Seq.map (fun xelem -> 
            let cookieName = xelem.Element(x"Name").Value
            let cookieValue = xelem.Element(x"Value").Value
            (cookieName, cookieValue)
        )
        |> Seq.iter (fun (cookieName, cookieValue) -> this.AdditionalCookies.Add(cookieName, cookieValue))

        let journeyXElem = root.Element(x"Journey")
        this.Journey.AcquireSettingsFromXElement(journeyXElem)

        let authInfoXElem = root.Element(x"AuthenticationInfo")
        this.Authentication.AcquireSettingsFromXElement(authInfoXElem)