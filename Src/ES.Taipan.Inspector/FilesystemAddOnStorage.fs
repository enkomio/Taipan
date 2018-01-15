namespace ES.Taipan.Inspector

open System
open System.IO
open System.Reflection
open MBrace.FsPickler

type private AddOnStorageValue = {
    AddOn: String
    Name: String
    Value: String
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
        
    new (addOn: IVulnerabilityScannerAddOn) = 
        let curDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)
        new FilesystemAddOnStorage(addOn, curDir)

    member this.ReadProperty<'a>(propertyName: String) =
        let filename = Path.Combine(_addOnsDirectory, addOn.Name, getFilename(propertyName))
        if File.Exists(filename) then
            try
                let fileContent = File.ReadAllText(filename)
                let xmlSerializer = FsPickler.CreateXmlSerializer()
                let storageValue = xmlSerializer.Deserialize<AddOnStorageValue>(new StringReader(fileContent))
                Some <| xmlSerializer.Deserialize<'a>(new StringReader(storageValue.Value))
            with _ -> None
        else None

    member this.SaveProperty<'a>(propertyName: String, propertyValue: 'a) =
        // serialize the value and create the data object
        let xmlSerializer = FsPickler.CreateXmlSerializer()
        let serializedValue = new StringWriter()
        xmlSerializer.Serialize(serializedValue, propertyValue)

        let serializedData = new StringWriter()
        let addOnData = {AddOn = addOn.Name; Name = propertyName; Value = serializedValue.ToString()}
        xmlSerializer.Serialize(serializedData, addOnData)
        
        // save the data value
        let addOnDirectory = Path.Combine(_addOnsDirectory, addOn.Name)
        Directory.CreateDirectory(addOnDirectory) |> ignore
        File.WriteAllText(Path.Combine(addOnDirectory, getFilename(propertyName)), serializedData.ToString())

    interface IAddOnStorage with
        member this.ReadProperty<'a>(propertyName: String) =
            this.ReadProperty<'a>(propertyName)

        member this.SaveProperty<'a>(propertyName: String, propertyValue: 'a) =
            this.SaveProperty(propertyName, propertyValue)    

