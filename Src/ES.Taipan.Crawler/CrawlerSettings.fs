namespace ES.Taipan.Crawler

open System
open System.Collections.Generic
open System.Xml.Linq
open System.Linq
open ES.Taipan.Infrastructure.Validation
open ES.Taipan.Infrastructure.Network

type DefaultParameter = {
    Name: String
    Value: String
    Path: String
}

type CrawlerSettings() = 
    let x(str) = XName.Get str

    /// If true activate all loaded addOns
    member val ActivateAllAddOns = true with get, set

    /// If ActivateAllAddOns is false the addOn with the Id present will be activated
    member val AddOnIdsToActivate = new List<Guid>() with get, set

    /// Define the navigation scope
    member val Scope = NavigationScope.WholeDomain with get, set

    /// A list of hosts that can be crawled
    member val AllowedHosts = new List<String>() with get

    /// Specify the max number of page to crawl
    member val MaxNumberOfPagesToCrawl = 1000 with get, set

    /// Specify if the crawler has a maximum number of link to crawl
    member val HasLinkNavigationLimit = true with get, set

    /// The list of extension that must be considered
    member val WebPageExtensions = new List<String>() with get

    /// A list of content type of resources that shouldn't be analyzed
    member val ContentTypeToFilter = new List<String>() with get

    /// If set to true only the page that has the extension in WebPageExtensions list will be crawled
    member val CrawlOnlyPageWithTheSpecifiedExtensions = false with get, set

    /// If a page doesn't have an extension will be crawled if this property is true
    member val CrawlPageWithoutExtension = true with get, set   

    /// Try to do some mutation to the found link in order to discover hidden pages
    member val MutateWebLinks = false with get, set

    /// Tell if the crawler should submit POST request
    member val SubmitPost = true with get, set

    /// Specify the maximum number of request that must be done to the same page. This avoid the case of infinite loop due to parameter value changing
    member val MaxNumOfRequestsToTheSamePage = 5 with get, set

    /// Specify which path mustn't be visited by the crawler
    member val BlacklistedPattern = new List<String>() with get, set

    /// A list of default value to set when specific query or data parameter are found
    member val DefaultParameters = new List<DefaultParameter>() with get, set

    /// If true, when the crawler completes, it re-crawl all pages that were founf
    member val ReCrawlPages = false with get, set

    member this.ToXml() =
        let addOnIdsToActivate = new XElement(x"AddOnIdsToActivate")
        this.AddOnIdsToActivate
        |> Seq.iter (fun addOnId -> addOnIdsToActivate.Add(new XElement(x"AddOnId", addOnId)))

        let webPagesExtensions = new XElement(x"WebPagesExtensions")
        this.WebPageExtensions
        |> Seq.iter (fun ext -> webPagesExtensions.Add(new XElement(x"Extension", ext.Trim())))

        let contentTypeToFilter = new XElement(x"ContentTypeToFilter")
        this.ContentTypeToFilter
        |> Seq.iter (fun ext -> contentTypeToFilter.Add(new XElement(x"ContentType", ext.Trim())))

        let allowedHosts = new XElement(x"AllowedHosts")
        this.AllowedHosts
        |> Seq.iter (fun ext -> allowedHosts.Add(new XElement(x"Host", ext.Trim())))

        let blacklistedPattern = new XElement(x"BlacklistedPattern")
        this.BlacklistedPattern
        |> Seq.iter (fun ext -> blacklistedPattern.Add(new XElement(x"Pattern", ext.Trim())))

        let defaultParameters = new XElement(x"DefaultParameters")
        this.DefaultParameters
        |> Seq.iter(fun p ->
            let xmlParameter = new XElement(x"Parameter")
            defaultParameters.Add(xmlParameter)
            xmlParameter.Add(new XElement(x"Name", p.Name))
            xmlParameter.Add(new XElement(x"Value", p.Value))
            xmlParameter.Add(new XElement(x"Path", p.Path)) 
        )

        let doc =
          new XDocument(
            new XElement(x"CrawlerSettings",
              new XElement(x"Scope", this.Scope),
              new XElement(x"MaxNumberOfPagesToCrawl", this.MaxNumberOfPagesToCrawl),
              new XElement(x"MaxNumOfRequestsToTheSamePage", this.MaxNumOfRequestsToTheSamePage),
              new XElement(x"CrawlPageWithoutExtension", this.CrawlPageWithoutExtension),
              new XElement(x"CrawlOnlyPageWithTheSpecifiedExtensions", this.CrawlOnlyPageWithTheSpecifiedExtensions),
              new XElement(x"ActivateAllAddOns", this.ActivateAllAddOns),
              new XElement(x"MutateWebLinks", this.MutateWebLinks),
              new XElement(x"SubmitPost", this.SubmitPost),
              new XElement(x"ReCrawlPages", this.ReCrawlPages),
              allowedHosts,
              blacklistedPattern,
              defaultParameters,
              addOnIdsToActivate,
              contentTypeToFilter,
              webPagesExtensions
            )
          )          
        doc.ToString()

    member this.AcquireSettingsFromXml(xmlSettings: String) =
        notEmpty xmlSettings "xmlSettings"

        let doc = XDocument.Parse(xmlSettings)
        let root = doc.Element(x"CrawlerSettings")

        this.Scope <- NavigationScope.Parse(root.Element(x"Scope").Value)
        this.MaxNumberOfPagesToCrawl <- Int32.Parse(root.Element(x"MaxNumberOfPagesToCrawl").Value)
        this.MaxNumOfRequestsToTheSamePage <- Int32.Parse(root.Element(x"MaxNumOfRequestsToTheSamePage").Value)
        this.CrawlPageWithoutExtension <- Boolean.Parse(root.Element(x"CrawlPageWithoutExtension").Value)
        this.CrawlOnlyPageWithTheSpecifiedExtensions <- Boolean.Parse(root.Element(x"CrawlOnlyPageWithTheSpecifiedExtensions").Value)
        this.ActivateAllAddOns <- Boolean.Parse(root.Element(x"ActivateAllAddOns").Value)
        this.MutateWebLinks <- Boolean.Parse(root.Element(x"MutateWebLinks").Value)
        this.SubmitPost <- Boolean.Parse(root.Element(x"SubmitPost").Value)
        this.ReCrawlPages <- Boolean.Parse(root.Element(x"ReCrawlPages").Value)

        root.Element(x"AllowedHosts").Elements(x"Host")
        |> Seq.map (fun xelem -> xelem.Value)
        |> Seq.iter this.AllowedHosts.Add

        root.Element(x"BlacklistedPattern").Elements(x"Pattern")
        |> Seq.map (fun xelem -> xelem.Value)
        |> Seq.iter this.BlacklistedPattern.Add

        root.Element(x"AddOnIdsToActivate").Elements(x"AddOnId")
        |> Seq.map (fun xelem -> Guid.Parse(xelem.Value))
        |> Seq.iter this.AddOnIdsToActivate.Add

        root.Element(x"WebPagesExtensions").Elements(x"Extension")
        |> Seq.map (fun xelem -> xelem.Value)
        |> Seq.iter this.WebPageExtensions.Add

        root.Element(x"ContentTypeToFilter").Elements(x"ContentType")
        |> Seq.map (fun xelem -> xelem.Value)
        |> Seq.iter this.ContentTypeToFilter.Add

        root.Element(x"DefaultParameters").Elements(x"Parameter")
        |> Seq.map (fun xelem ->
            {
                Name = xelem.Element(x"Name").Value
                Value = xelem.Element(x"Value").Value
                Path = xelem.Element(x"Path").Value
            }
        )
        |> Seq.iter this.DefaultParameters.Add