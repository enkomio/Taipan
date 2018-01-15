namespace ES.Taipan.Fingerprinter

open System
open System.Collections.Generic
open System.Xml.Linq
open System.Linq
open ES.Taipan.Infrastructure.Validation

type WebAppFingerprinterSettings() = 
    static let x str = XName.Get str

    /// If true the first web application identified will break the process. This is the common case 
    /// since it is odd that more than one application is installed on the same directory. This setting consider only 
    /// applications that doesn't have any dependencies
    member val StopAtTheFirstApplicationIdentified = true with get, set 
    
    /// If True, during the process, for each identified version a message is raised
    member val RaiseAnEventForEachVersionIdentified = false with get, set

    /// If true try to fingerprint every directory identified during the scan process
    member val BeRecursive = true with get, set 
        
    /// If true use only the scripts in order to fingerprint the web application
    member val UseOnlyScripts = false with get, set
        
    member this.ToXml() =
        let doc =
          new XDocument(
            new XElement(x"WebAppFingerprinterSettings",
              new XElement(x"StopAtTheFirstApplicationIdentified", this.StopAtTheFirstApplicationIdentified),
              new XElement(x"RaiseAnEventForEachVersionIdentified", this.RaiseAnEventForEachVersionIdentified),
              new XElement(x"BeRecursive", this.BeRecursive),
              new XElement(x"UseOnlyScripts", this.UseOnlyScripts)
            )
          )          
        doc.ToString()

    member this.AcquireSettingsFromXml(xmlSettings: String) =
        notEmpty xmlSettings "xmlSettings"

        let doc = XDocument.Parse(xmlSettings)
        let root = doc.Element(x"WebAppFingerprinterSettings")

        this.StopAtTheFirstApplicationIdentified <- Boolean.Parse(root.Element(x"StopAtTheFirstApplicationIdentified").Value)
        this.RaiseAnEventForEachVersionIdentified <- Boolean.Parse(root.Element(x"RaiseAnEventForEachVersionIdentified").Value)
        this.BeRecursive <- Boolean.Parse(root.Element(x"BeRecursive").Value)
        this.UseOnlyScripts <- Boolean.Parse(root.Element(x"UseOnlyScripts").Value)