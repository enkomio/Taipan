namespace ES.Taipan.Discoverer

open System
open System.Collections.Generic
open System.Xml.Linq
open System.Linq
open ES.Taipan.Infrastructure.Validation

type ResourceDiscovererSettings() = 
    let x(str) = XName.Get str

    /// If true execute the discovery process on every directory found
    member val BeRecursive = true with get, set 

    /// A list of dictionary id to use for discovery
    member val Dictionaries = new List<String>() with get

    /// A list of forbidden directories that mustn't be scanned
    member val ForbiddenDirectories = new List<String>() with get

    /// A list of extension (eg. .php) to use during the discovery process
    member val Extensions = new HashSet<String>() with get

    /// Specify how deep the recursive process need go to. Eg. /a/b/c/ has a recursive depth of 3 if the root is /
    member val RecursiveDepth = 3 with get, set

    /// Tell if during discover a page with blank extension should also be sent
    member val UseBlankExtension = true with get, set

    /// A set of words that if found in the response will not signal the resource as discovered
    member val BlackListedWords = new HashSet<String>() with get

    /// A set of HTTP status codes that if returned by the response will not signal the resource as discovered
    member val BlackListedStatusCodes = new HashSet<Int32>() with get

    member this.ToXml() =
        let dictionaries = new XElement(x"Dictionaries")
        this.Dictionaries
        |> Seq.iter (fun dictionary -> dictionaries.Add(new XElement(x"Id", dictionary)))

        let forbiddenDirectories = new XElement(x"ForbiddenDirectories")
        this.ForbiddenDirectories
        |> Seq.iter (fun directory -> forbiddenDirectories.Add(new XElement(x"Name", directory)))

        let blackListedWords = new XElement(x"BlackListedWords")
        this.BlackListedWords
        |> Seq.iter (fun word -> blackListedWords.Add(new XElement(x"Word", word)))

        let blackListedStatusCodes = new XElement(x"BlackListedStatusCodes")
        this.BlackListedStatusCodes
        |> Seq.iter (fun statusCode -> blackListedStatusCodes.Add(new XElement(x"Code", statusCode)))

        let extensions = new XElement(x"Extensions")
        this.Extensions
        |> Seq.iter (fun extension -> extensions.Add(new XElement(x"Name", extension)))

        let doc =
          new XDocument(
            new XElement(x"ResourceDiscovererSettings",
              new XElement(x"BeRecursive", this.BeRecursive),
              new XElement(x"RecursiveDepth", this.RecursiveDepth),
              new XElement(x"UseBlankExtension", this.UseBlankExtension),
              blackListedStatusCodes,
              blackListedWords,
              dictionaries,
              forbiddenDirectories,
              extensions
            )
          )          
        doc.ToString()

    member this.AcquireSettingsFromXml(xmlSettings: String) =
        notEmpty xmlSettings "xmlSettings"

        let doc = XDocument.Parse(xmlSettings)
        let root = doc.Element(x"ResourceDiscovererSettings")

        root.Element(x"Dictionaries").Elements(x"Id")
        |> Seq.map (fun xelem -> xelem.Value)
        |> Seq.iter this.Dictionaries.Add

        root.Element(x"ForbiddenDirectories").Elements(x"Name")
        |> Seq.map (fun xelem -> xelem.Value)
        |> Seq.iter this.ForbiddenDirectories.Add

        root.Element(x"BlackListedWords").Elements(x"Word")
        |> Seq.toList
        |> List.map (fun xelem -> xelem.Value)
        |> List.map this.BlackListedWords.Add
        |> ignore

        root.Element(x"BlackListedStatusCodes").Elements(x"Code")
        |> Seq.toList
        |> List.map (fun xelem -> int32 xelem.Value)
        |> List.map this.BlackListedStatusCodes.Add
        |> ignore

        root.Element(x"Extensions").Elements(x"Name")
        |> Seq.toList
        |> List.map (fun xelem -> xelem.Value)
        |> List.map this.Extensions.Add
        |> ignore

        this.BeRecursive <- Boolean.Parse(root.Element(x"BeRecursive").Value)
        this.RecursiveDepth <- Int32.Parse(root.Element(x"RecursiveDepth").Value)
        this.UseBlankExtension <- Boolean.Parse(root.Element(x"UseBlankExtension").Value)