namespace ES.Taipan.Inspector

open System
open System.Collections.Generic
open System.IO
open System.Xml
open System.Xml.Linq
open System.Reflection
open Newtonsoft.Json

type AddOnStorageValue = {
    AddOn: String
    Name: String
    Type: String
    Value: Object
} with
    member this.ToXml() =
        let x(str) = XName.Get str
        (new XDocument(
            new XElement(x"AddOnStorageValue",
                new XElement(x"AddOn", this.AddOn),
                new XElement(x"Name", this.Name),
                new XElement(x"Type", this.Type),
                new XElement(x"Value", new XCData(JsonConvert.SerializeObject(this.Value, Formatting.Indented)))
            )
        )).ToString()

    static member FromXml(xmlString: String) =
        let x(str) = XName.Get str
        let doc = XDocument.Parse(xmlString)                
        let root = doc.Element(x"AddOnStorageValue")
        let typeStr = root.Element(x"Type").Value   
        
        let objType = 
            AppDomain.CurrentDomain.GetAssemblies()
            |> Array.filter(fun a -> typeStr.StartsWith(a.GetName().Name))
            |> Array.map(fun assembly -> assembly.GetType(typeStr))
            |> Array.filter(fun t -> t <> null)
            |> Array.head        

        {
            AddOn = root.Element(x"AddOn").Value
            Name = root.Element(x"Name").Value
            Type = typeStr
            Value = JsonConvert.DeserializeObject(root.Element(x"Value").Value, objType)
        }

type FilesystemAddOnStorage(addOn: IVulnerabilityScannerAddOn, baseDir: String) =
    let _addOnsDirectory = Path.Combine(baseDir, "Data", "AddOnStorage")

    let getFilename(propertyName: String) =
        let mutable fileName = propertyName
        Path.GetInvalidFileNameChars() |> Array.iter(fun c -> fileName <- fileName.Replace(string c, String.Empty))        

        // ensure that no other file with the same name exists
        let mutable effectiveFileName = fileName
        let index = ref 1
        while File.Exists(effectiveFileName) do
            effectiveFileName <- fileName + (!index).ToString()
            incr index

        effectiveFileName + ".xml"

    let getAddOnDirectoryStorage() =
        Path.Combine(_addOnsDirectory, addOn.Name)

    let getPropertyFilename(propertyName: String) =
        Path.Combine(getAddOnDirectoryStorage(), getFilename(propertyName))

    new (addOn: IVulnerabilityScannerAddOn) = 
        let curDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)
        new FilesystemAddOnStorage(addOn, curDir)

    member this.ReadProperty<'a>(propertyName: String) =
        let filename = getPropertyFilename(propertyName)
        if File.Exists(filename) then
            let fileContent = File.ReadAllText(filename)
            let addOnData = AddOnStorageValue.FromXml(fileContent)
            Some(addOnData.Value :?> 'a)
        else None

    member this.GetProperties<'a>(filter: 'a -> Boolean) = seq {
        for filename in Directory.GetFiles(getAddOnDirectoryStorage()) do
            let fileContent = File.ReadAllText(filename)
            let addOnData = AddOnStorageValue.FromXml(fileContent)
            if filter(addOnData.Value :?> 'a) then
                yield addOnData.Value :?> 'a
    }

    member this.SaveProperty<'a>(propertyName: String, propertyValue: 'a) =
        let addOnData = {
            AddOn = addOn.Name
            Name = propertyName
            Type = propertyValue.GetType().FullName
            Value = propertyValue
        }
        let serializedAddOnData = addOnData.ToXml()
        
        // save the data value
        let addOnDirectory = Path.Combine(_addOnsDirectory, addOn.Name)
        Directory.CreateDirectory(addOnDirectory) |> ignore
        let filename = getPropertyFilename(propertyName)
        File.WriteAllText(filename, serializedAddOnData)

    interface IAddOnStorage with
        member this.ReadProperty<'a>(propertyName: String) =
            this.ReadProperty<'a>(propertyName)

        member this.SaveProperty<'a>(propertyName: String, propertyValue: 'a) =
            this.SaveProperty(propertyName, propertyValue)    

        member this.GetProperties<'a>(filter: 'a -> Boolean) =
            this.GetProperties<'a>(filter)

