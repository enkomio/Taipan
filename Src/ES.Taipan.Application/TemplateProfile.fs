namespace ES.Taipan.Application

open System
open System.Collections.Generic
open System.Xml.Linq
open System.Net
open ES.Taipan.Crawler
open ES.Taipan.Inspector
open ES.Taipan.Fingerprinter
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Infrastructure.Validation
open ES.Taipan.Discoverer

/// This class is idependent of the scan instance
type TemplateProfile() =
    static let x str = XName.Get str

    member val Id = Guid.NewGuid() with get, set
    member val Name = String.Empty with get, set
    member val Description = String.Empty with get, set
    member val RunCrawler = false with get, set
    member val RunVulnerabilityScanner = false with get, set
    member val RunWebAppFingerprinter = false with get, set
    member val RunResourceDiscoverer = false with get, set
    member val HttpRequestorSettings = new HttpRequestorSettings() with get, set
    member val CrawlerSettings = new CrawlerSettings() with get, set
    member val VulnerabilityScannerSettings = new VulnerabilityScannerSettings() with get, set
    member val WebAppFingerprinterSettings = new WebAppFingerprinterSettings() with get, set
    member val ResourceDiscovererSettings = new ResourceDiscovererSettings() with get, set
    
    member this.ToXml() =
        let httpSettingsXml = this.HttpRequestorSettings.ToXml()
        let crawlerSettingsXml = this.CrawlerSettings.ToXml()
        let vulnerabilityScannerSettingsXml = this.VulnerabilityScannerSettings.ToXml()   
        let webAppFingerprinterSettingsXml = this.WebAppFingerprinterSettings.ToXml()   
        let resourceDiscovererSettingsXml = this.ResourceDiscovererSettings.ToXml()  
        
        let doc =
          new XDocument(
                new XElement(x"Profile",
                    new XElement(x"Id", this.Id),
                    new XElement(x"Name", this.Name),
                    new XElement(x"Description", this.Description),
                    new XElement(x"RunCrawler", this.RunCrawler),
                    new XElement(x"RunVulnerabilityScanner", this.RunVulnerabilityScanner),
                    new XElement(x"RunWebAppFingerprinter", this.RunWebAppFingerprinter),
                    new XElement(x"RunResourceDiscoverer", this.RunResourceDiscoverer),
                    XElement.Parse(httpSettingsXml),
                    XElement.Parse(crawlerSettingsXml),
                    XElement.Parse(vulnerabilityScannerSettingsXml),
                    XElement.Parse(webAppFingerprinterSettingsXml),
                    XElement.Parse(resourceDiscovererSettingsXml)
                )
            )      
        doc.ToString()

    member this.AcquireSettingsFromXml(xmlSettings: String) =
        notEmpty xmlSettings "xmlSettings"

        let doc = XDocument.Parse(xmlSettings)
        let root = doc.Element(x"Profile")

        let httpSettingsElement = root.Element(x"HttpRequestorSettings")
        this.HttpRequestorSettings.AcquireSettingsFromXml(httpSettingsElement.ToString())
        
        let crawlerSettingsElement = root.Element(x"CrawlerSettings")
        this.CrawlerSettings.AcquireSettingsFromXml(crawlerSettingsElement.ToString())

        let vulnerabilityScannerSettingsElement = root.Element(x"VulnerabilityScannerSettings")
        this.VulnerabilityScannerSettings.AcquireSettingsFromXml(vulnerabilityScannerSettingsElement.ToString())

        let webAppFingerprinterSettingsElement = root.Element(x"WebAppFingerprinterSettings")
        this.WebAppFingerprinterSettings.AcquireSettingsFromXml(webAppFingerprinterSettingsElement.ToString())
        
        let resourceDiscovererSettingsElement = root.Element(x"ResourceDiscovererSettings")
        this.ResourceDiscovererSettings.AcquireSettingsFromXml(resourceDiscovererSettingsElement.ToString())

        this.Id <- Guid.Parse(root.Element(x"Id").Value)
        this.Name <- root.Element(x"Name").Value
        this.Description <- root.Element(x"Description").Value
        this.RunCrawler <- Boolean.Parse(root.Element(x"RunCrawler").Value)
        this.RunVulnerabilityScanner <- Boolean.Parse(root.Element(x"RunVulnerabilityScanner").Value)
        this.RunWebAppFingerprinter <- Boolean.Parse(root.Element(x"RunWebAppFingerprinter").Value)
        this.RunResourceDiscoverer <- Boolean.Parse(root.Element(x"RunResourceDiscoverer").Value)