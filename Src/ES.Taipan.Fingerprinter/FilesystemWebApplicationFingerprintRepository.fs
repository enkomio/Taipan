namespace ES.Taipan.Fingerprinter

open System
open System.Reflection
open System.IO
open System.IO.Compression
open System.Collections.Generic
open System.Xml.Linq
open System.Linq
open System.Xml
open ES.Fslog
open ES.Taipan.Fingerprinter

type internal FilesystemWebApplicationFingerprintRepositoryLogger() =
    inherit LogSource("FilesystemWebApplicationFingerprintRepository")
    
    [<Log(1, Message = "Loaded {0} versions, {1} signatures of application {2}", Level = LogLevel.Verbose)>]
    member this.LoadedWebApplication(appName, numOfVersions, numSign) = 
        this.WriteLog(1, [|numOfVersions; numSign; appName|])

    [<Log(2, Message = "Loaded scripts: {0}", Level = LogLevel.Informational)>]
    member this.LoadedScripts(scripts: BaseSignature seq) = 
        let scriptsTxt = String.Join(", ", scripts)
        this.WriteLog(2, [|scriptsTxt|])

    [<Log(3, Message = "Load all signatures, this may take a while...", Level = LogLevel.Informational)>]
    member this.LoadAllSignatures() = 
        this.WriteLog(3, [||])

    [<Log(4, Message = "Signature loading complete: {0} applications, {1} version, and {2} signatures", Level = LogLevel.Informational)>]
    member this.LoadSignaturesCompleted(apps: Int32, versions: Int32, signs: Int32) = 
        this.WriteLog(4, [|apps; versions; signs|])

    [<Log(5, Message = "Load signatures of application written in: {0}", Level = LogLevel.Verbose)>]
    member this.LoadApplicationPerLanguage(language: String) = 
        this.WriteLog(5, [|language|])

    [<Log(6, Message = "Load signatures from compressed file: {0}", Level = LogLevel.Verbose)>]
    member this.LoadSignatureInZipFile(file: String) = 
        this.WriteLog(6, [|file|])

    [<Log(7, Message = "Load signatures from directory: {0}", Level = LogLevel.Verbose)>]
    member this.LoadSignatureInDirectory(directory: String) = 
        this.WriteLog(7, [|directory|])

/// Read all the stored signatures from the filesystem
type FilesystemWebApplicationFingerprintRepository(path: String, logProvider: ILogProvider) =
    static let x str = XName.Get str    
    let _logger = new FilesystemWebApplicationFingerprintRepositoryLogger()
    let mutable _customScriptCheckers : List<BaseSignature> option = None    
    let mutable _webApplicationFingerprints : List<WebApplicationFingerprint> option = None

    do logProvider.AddLogSourceToLoggers(_logger)

    let loadWebAppVersionFingerprint (webApp: WebApplicationFingerprint) (directory: String) (interruptLoading: unit -> Boolean) =
        for versionDirectory in Directory.EnumerateDirectories(directory) do
            if not(interruptLoading()) then
                let webAppVersionFingerprint = new WebApplicationVersionFingerprint()
            
                let versionFile = Path.Combine(versionDirectory, "version.xml")
                if File.Exists(versionFile) then
                    let versionXml = File.ReadAllText(versionFile)

                    // populate the web app version Fingerprint base properties
                    let doc = XDocument.Parse(versionXml)
                    let root = doc.Element(x"WebApplicationVersion")        
                    webAppVersionFingerprint.Version <- root.Element(x"Version").Value            
                    webAppVersionFingerprint.AcceptanceRate <- XmlConvert.ToDouble(root.Element(x"AcceptanceRate").Value)

                    // read version signatures
                    for signatureFile in Directory.EnumerateFiles(Path.Combine(versionDirectory, "Signatures")) do
                        if not(interruptLoading()) then
                            let signatureXml = File.ReadAllText(signatureFile)
                            let signature = SignatureFactory.createSignatureFromXml(signatureXml, logProvider)
                            webAppVersionFingerprint.Signatures.Add(signature)
                                    
                    webApp.Versions.Add(webAppVersionFingerprint)

    let loadSignatures (fingerprintsDirectory: String) (webAppFingerprint: WebApplicationFingerprint) (interruptLoading: unit -> Boolean) =
        // load standard signatures            
        let numOfSignatures = ref 0
        let signaturesDirectory = Path.Combine(fingerprintsDirectory, webAppFingerprint.Name, "Apps")
        if Directory.Exists(signaturesDirectory) then
            for versionDirectory in Directory.EnumerateDirectories(signaturesDirectory) do
                if not(interruptLoading()) then
                    let versionName = Path.GetFileName(versionDirectory)
                    let versionFingerprintOpt = 
                        webAppFingerprint.Versions
                        |> Seq.tryFind(fun webAppVer -> webAppVer.Version.Equals(versionName, StringComparison.Ordinal))
            
                    if versionFingerprintOpt.IsSome then
                        // load all signatures of the current version
                        for file in Directory.EnumerateFiles(versionDirectory) do
                            if not(interruptLoading()) then
                                let signatureXml = File.ReadAllText(file)
                                let signature = SignatureFactory.createSignatureFromXml(signatureXml, logProvider)
                                incr numOfSignatures
                                versionFingerprintOpt.Value.Signatures.Add(signature)
                    else
                        // load all signatures of the web application
                        for file in Directory.EnumerateFiles(versionDirectory) do
                            if not(interruptLoading()) then
                                let signatureXml = File.ReadAllText(file)
                                let signature = SignatureFactory.createSignatureFromXml(signatureXml, logProvider)
                                incr numOfSignatures
                                webAppFingerprint.BaseSignatures.Add(signature)

        !numOfSignatures

    let loadWebApplicationVersion(appName: String, appDirectory: String, interruptLoading: unit -> Boolean) =
        // read the application file descriptor
        let appFilename = appName + ".xml"
        let filePath = Path.Combine(appDirectory, appFilename) 
        
        let webAppFingerprint = new WebApplicationFingerprint(logProvider)

        if File.Exists(filePath) then            
            let appFileDescriptorXmlContent = File.ReadAllText(filePath)                  
            webAppFingerprint.AcquireFromXml(appFileDescriptorXmlContent)

        // read the version file descriptor
        for versionFile in Directory.EnumerateFiles(appDirectory) do
            let fileName = Path.GetFileName(versionFile)
            if not <| fileName.Equals(appFilename, StringComparison.OrdinalIgnoreCase) && not(interruptLoading()) then
                let appVerFileDescriptorXmlContent = File.ReadAllText(versionFile)
                let webAppVerFingerprint = new WebApplicationVersionFingerprint()
                webAppVerFingerprint.AcquireFromXml(appVerFileDescriptorXmlContent)
                webAppFingerprint.Versions.Add(webAppVerFingerprint)

        webAppFingerprint

    let getDirectories(language: String) =        
        let fingerprintsDirectory = Path.Combine(path, "Data", "Signatures", language.ToString())
        let scriptDirectory = Path.Combine(path, "Data", "Scripts", language)
        (fingerprintsDirectory, scriptDirectory)

    let loadWebAppFingerprint(appDirectory: String, interruptLoading: unit -> Boolean) =        
        let appName = Path.GetFileName(appDirectory)
        let configurationDirectory = Path.Combine(appDirectory, "Configuration")
        loadWebApplicationVersion(appName, configurationDirectory, interruptLoading)

    let loadScripts(supportedLanguages: String seq, interruptLoading: unit -> Boolean) =
        _customScriptCheckers <- Some <| new List<BaseSignature>()
                        
        for language in supportedLanguages do
            let (_, scriptDirectory) = getDirectories(language)
                
            // load script signatures
            if Directory.Exists(scriptDirectory) && not(interruptLoading()) then
                for scriptDirectory in Directory.EnumerateDirectories(scriptDirectory) do
                    let directoryName = Path.GetFileName(scriptDirectory)
                    let mutable scriptContent = String.Empty
                    let mutable fileName = String.Empty
                    let signature = new LuaScriptSignature(logProvider)

                    for file in Directory.EnumerateFiles(scriptDirectory) do 
                        if  not(interruptLoading()) then                   
                            // script content    
                            if 
                                Path.GetFileNameWithoutExtension(file).Equals(directoryName, StringComparison.OrdinalIgnoreCase) && 
                                not <| Path.GetExtension(file).Equals(".xml", StringComparison.OrdinalIgnoreCase) 
                            then
                                scriptContent <- File.ReadAllText(file)
                                fileName <- Path.GetFileName(file)

                            // script configuration file
                            elif Path.GetExtension(file).Equals(".xml", StringComparison.OrdinalIgnoreCase) then
                                let scriptDescription = File.ReadAllText(file)
                                signature.AcquireFromXml(scriptDescription)

                    if not <| String.IsNullOrEmpty(scriptContent) then
                        signature.Code <- scriptContent
                        signature.FilePath <- fileName
                        _customScriptCheckers.Value.Add(signature)  

                _logger.LoadedScripts(_customScriptCheckers.Value)

    let loadSignatures(supportedLanguages: String seq, interruptLoading: unit -> Boolean) =
        _logger.LoadAllSignatures()
        _webApplicationFingerprints <- Some <| new List<WebApplicationFingerprint>()

        // load all web application signatures
        let mutable loadedApplications = 0
        let mutable loadedVersions = 0
        let mutable loadedSignatures = 0
            
        // load all web apps configuration
        for language in supportedLanguages do
            _logger.LoadApplicationPerLanguage(language)
            let (fingerprintsDirectory, _) = getDirectories(language)                    
            
            if Directory.Exists(fingerprintsDirectory) then                
                // load all zipped files
                for appZippedFile in Directory.EnumerateFiles(fingerprintsDirectory, "*.zip") do
                    if not(interruptLoading()) then
                        _logger.LoadSignatureInZipFile(appZippedFile)
                        loadedApplications <- loadedApplications + 1

                        let tempDirectory = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName())
                        Directory.CreateDirectory(tempDirectory) |> ignore

                        // extract zip file
                        let appName = Path.GetFileNameWithoutExtension(appZippedFile)                            
                        use zipFile = ZipFile.OpenRead(appZippedFile)
                            
                        zipFile.Entries
                        |> Seq.iter(fun zipEntry ->
                            if zipEntry.Length > 0L then
                                // it is a file
                                let fileName = Path.Combine(tempDirectory, zipEntry.FullName)
                                Directory.CreateDirectory(Path.GetDirectoryName(fileName)) |> ignore
                                zipEntry.ExtractToFile(Path.Combine(tempDirectory, zipEntry.FullName))
                        )

                        // load the signature
                        let webAppFingerprint = loadWebAppFingerprint(Path.Combine(tempDirectory, appName), interruptLoading)
                        let numSign = loadSignatures tempDirectory webAppFingerprint interruptLoading
                        loadedVersions <- loadedVersions + webAppFingerprint.Versions.Count
                        loadedSignatures <- loadedSignatures + numSign
                        _logger.LoadedWebApplication(appName, webAppFingerprint.Versions.Count, numSign)
                        Directory.Delete(tempDirectory, true)
                        _webApplicationFingerprints.Value.Add(webAppFingerprint)

                // load all signatures files
                for appDirectory in Directory.EnumerateDirectories(fingerprintsDirectory) do
                    if not(interruptLoading()) then
                        _logger.LoadSignatureInDirectory(appDirectory)
                        loadedApplications <- loadedApplications + 1
                        let appName = Path.GetFileName(appDirectory)
                        let webAppFingerprint = loadWebAppFingerprint(appDirectory, interruptLoading)                     
                        let numSign = loadSignatures fingerprintsDirectory webAppFingerprint interruptLoading
                        loadedVersions <- loadedVersions + webAppFingerprint.Versions.Count
                        loadedSignatures <- loadedSignatures + numSign
                        _logger.LoadedWebApplication(appName, webAppFingerprint.Versions.Count, numSign)
                        _webApplicationFingerprints.Value.Add(webAppFingerprint)

        _logger.LoadSignaturesCompleted(loadedApplications, loadedVersions, loadedSignatures)

    new (logProvider:ILogProvider) = new FilesystemWebApplicationFingerprintRepository(FileInfo(Assembly.GetExecutingAssembly().Location).Directory.FullName, logProvider)

    member this.LoadSignatures(supportedLanguages: String seq, interruptLoading: unit -> Boolean) =        
        if _webApplicationFingerprints.IsNone then
            loadSignatures(supportedLanguages, interruptLoading)

    member this.LoadScripts(supportedLanguages: String seq, interruptLoading: unit -> Boolean) =  
        if _customScriptCheckers.IsNone then 
            loadScripts(supportedLanguages, interruptLoading)
        
    member this.GetCustomScriptCheckers() =
        _customScriptCheckers.Value

    member this.GetAllWebApplications() =
        _webApplicationFingerprints.Value

    member this.GetWebApplication(webAppName: String) =        
        this.GetAllWebApplications()
        |> Seq.tryFind(fun webApp -> webApp.Name.Equals(webAppName, StringComparison.Ordinal))
    
    interface IWebApplicationFingerprintRepository with
        member this.GetAllWebApplications() =
            this.GetAllWebApplications()

        member this.LoadSignatures(supportedLanguages: String seq, interruptLoading: unit -> Boolean) =
            this.LoadSignatures(supportedLanguages, interruptLoading)

        member this.LoadScripts(supportedLanguages: String seq, interruptLoading: unit -> Boolean) =
            this.LoadScripts(supportedLanguages, interruptLoading)

        member this.GetCustomScriptCheckers() =
            this.GetCustomScriptCheckers()
