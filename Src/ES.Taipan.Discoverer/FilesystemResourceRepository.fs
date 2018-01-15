namespace ES.Taipan.Discoverer

open System
open System.Reflection
open System.IO
open System.Collections.Generic
open System.Xml.Linq
open System.Linq
open System.Xml
open ES.Fslog

type internal FilesystemResourceRepositoryLogger() =
    inherit LogSource("FilesystemResourceRepository")
    
    [<Log(1, Message = "Unable to load dictionary file: {0}", Level = LogLevel.Error)>]
    member this.UnableToLoadDictionaryFile(filename: String) = 
        this.WriteLog(1, [|filename|])

type FilesystemResourceRepository(logProvider: ILogProvider) =
    static let x str = XName.Get str
    let _logger = new FilesystemResourceRepositoryLogger()
    let _dictionaries = new List<ResourceDictionary>()
    let _forbiddenDirectories = new List<String>()

    let addResourcesToDictionary(resourcesDirectory: String, dictionaryFile: String, dictionary: ResourceDictionary) =
        let dictionaryFileFullPath = Path.Combine(resourcesDirectory, dictionaryFile)
        if File.Exists(dictionaryFileFullPath) then
            for rawLine in File.ReadAllLines(dictionaryFileFullPath) do
                let line = rawLine.Trim()
                if not <| line.StartsWith("#") && not <| String.IsNullOrWhiteSpace(line) then
                    let resource = new Resource(line, Group = dictionary.Name)
                    dictionary.Resources.Add(resource)

    do
        logProvider.AddLogSourceToLoggers(_logger)
        let path = FileInfo(Assembly.GetExecutingAssembly().Location).Directory.FullName
        let resourcesDirectory = Path.Combine(path, "Data", "Dictionaries")

        // read resources dictionaries
        for filename in Directory.EnumerateFiles(resourcesDirectory, "*.xml") do
            let fileContent = File.ReadAllText(filename).Trim()
            try
                let doc = XDocument.Parse(fileContent)
                let root = doc.Element(x"Dictionary")

                let id = Guid.Parse(root.Element(x"Id").Value)
                let name = root.Element(x"Name").Value
                let dictionaryFile = root.Element(x"Path").Value

                let dictionary = new ResourceDictionary(id, Name = name)
                addResourcesToDictionary(resourcesDirectory, dictionaryFile, dictionary)
                _dictionaries.Add(dictionary)
            with _ -> 
                _logger.UnableToLoadDictionaryFile(filename)

        // read forbidden directories
        let forbiddenDirFile = Path.Combine(resourcesDirectory, "forbidden.txt")
        if File.Exists(forbiddenDirFile) then
            for rawLine in File.ReadAllLines(forbiddenDirFile) do
                let line = rawLine.Trim()
                if not <| line.StartsWith("#") then
                    let directoryPath = if line.EndsWith("/") then line else line + "/"
                    _forbiddenDirectories.Add(directoryPath)
                                
    member this.GetAllDictionaries() =
        _dictionaries |> Seq.toList

    member this.GetAllSelectedDictionaries(ids: Guid list) =
        _dictionaries 
        |> Seq.filter(fun dictionary -> ids.Contains(dictionary.Id))
        |> Seq.toList

    member this.GetForbiddenDirectories() =
        _forbiddenDirectories |> Seq.toList

    interface IResourceRepository with
        member this.GetAllSelectedDictionaries(ids: Guid list) =
            this.GetAllSelectedDictionaries(ids)

        member this.GetAllDictionaries() =
            this.GetAllDictionaries()

        member this.GetForbiddenDirectories() = 
            this.GetForbiddenDirectories()