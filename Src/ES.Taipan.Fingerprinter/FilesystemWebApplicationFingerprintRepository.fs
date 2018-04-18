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

type internal WebAppVersionDescriptor() =
    member val Info = String.Empty with get, set
    member val Signatures = new List<String>() with get

type internal WebAppDescriptor() =
    member val Info = String.Empty with get, set
    member val Signatures = new List<String>() with get
    member val Versions = new Dictionary<String, WebAppVersionDescriptor>() with get

/// Read all the stored signatures from the filesystem
type FilesystemWebApplicationFingerprintRepository(path: String, logProvider: ILogProvider) =
    let _logger = new FilesystemWebApplicationFingerprintRepositoryLogger()
    let mutable _customScriptCheckers : List<BaseSignature> option = None    
    let mutable _webApplicationFingerprints : List<WebApplicationFingerprint> option = None

    do logProvider.AddLogSourceToLoggers(_logger)

    let createWebApplicationFingerprint(webAppDescriptor: WebAppDescriptor, interruptLoading: unit -> Boolean) =
        let webAppFingeprint = new WebApplicationFingerprint(logProvider)
        webAppFingeprint.AcquireFromXml(webAppDescriptor.Info)

        // add web app signatures
        for xmlSignature in webAppDescriptor.Signatures do
            if not(interruptLoading()) then
                let signature = SignatureFactory.createSignatureFromXml(xmlSignature, logProvider)
                webAppFingeprint.BaseSignatures.Add(signature)

        // add all versions
        for versionDesc in webAppDescriptor.Versions.Values do
            if not(interruptLoading()) then
                let version = new WebApplicationVersionFingerprint()
                version.AcquireFromXml(versionDesc.Info)
                webAppFingeprint.Versions.Add(version)

                // load all version signatures
                for xmlSignature in versionDesc.Signatures do
                    if not(interruptLoading()) then
                        let signature = SignatureFactory.createSignatureFromXml(xmlSignature, logProvider)
                        version.Signatures.Add(signature)
        webAppFingeprint

    let getDirectories(language: String) =        
        let fingerprintsDirectory = Path.Combine(path, "Data", "Signatures", language.ToString())
        let scriptDirectory = Path.Combine(path, "Data", "Scripts", language)
        (fingerprintsDirectory, scriptDirectory)

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

    let processFileContent(appName: String, fullname: String, fileContent: String, webAppDescriptor: WebAppDescriptor) =
        let filename = Path.GetFileNameWithoutExtension(fullname)
        if fullname.Contains("Configuration") then
            // it is a configuration file                                    
            let isWebAppConfig = filename.Equals(appName, StringComparison.OrdinalIgnoreCase)

            if isWebAppConfig then
                // it is the web app descriptor
                webAppDescriptor.Info <- fileContent
            else
                // it is a web app version descriptor
                if not <| webAppDescriptor.Versions.ContainsKey(filename) then
                    webAppDescriptor.Versions.Add(filename, new WebAppVersionDescriptor())
                webAppDescriptor.Versions.[filename].Info <- fileContent
        else
            // it is a signature file
            let version = Path.GetFileName(Path.GetDirectoryName(fullname))

            let isWebAppSignature = version.Equals(appName, StringComparison.OrdinalIgnoreCase)
            if isWebAppSignature then
                webAppDescriptor.Signatures.Add(fileContent)
            else
                if not <| webAppDescriptor.Versions.ContainsKey(version) then
                    webAppDescriptor.Versions.Add(version, new WebAppVersionDescriptor())
                webAppDescriptor.Versions.[version].Signatures.Add(fileContent)

    let analyzeZipFile(appZippedFile: String) =
        use zipFile = ZipFile.OpenRead(appZippedFile)
        let webAppDescriptor = new WebAppDescriptor()
        zipFile.Entries
        |> Seq.iter(fun zipEntry ->
            if zipEntry.Length > 0L then
                // read and process content
                use streamReader = new StreamReader(zipEntry.Open())
                let entryValue = streamReader.ReadToEnd()
                let appName = Path.GetFileNameWithoutExtension(appZippedFile)
                processFileContent(appName, zipEntry.FullName, entryValue, webAppDescriptor)
        )
        webAppDescriptor

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

                        // analyze zip file                        
                        let webAppDescriptor = analyzeZipFile(appZippedFile)

                        // create the fingerprint object
                        let webAppFingerprint = createWebApplicationFingerprint(webAppDescriptor, interruptLoading)
                        let webAppTotalSign = webAppFingerprint.BaseSignatures.Count + (webAppFingerprint.Versions |> Seq.sumBy(fun v -> v.Signatures.Count))
                        
                        // update counter
                        loadedVersions <- loadedVersions + webAppFingerprint.Versions.Count
                        loadedSignatures <- loadedSignatures + webAppTotalSign                        
                        
                        _logger.LoadedWebApplication(webAppFingerprint.Name, webAppFingerprint.Versions.Count, webAppTotalSign)
                        _webApplicationFingerprints.Value.Add(webAppFingerprint)

                // load all signatures files
                for appDirectory in Directory.EnumerateDirectories(fingerprintsDirectory) do
                    let webAppDescriptor = new WebAppDescriptor()
                    let appName = Path.GetFileName(appDirectory)
                                        
                    _logger.LoadSignatureInDirectory(appDirectory)
                    loadedApplications <- loadedApplications + 1

                    // process all web application files
                    for appFile in Directory.EnumerateFiles(appDirectory, "*", SearchOption.AllDirectories) do
                        if not(interruptLoading()) then
                            let fileContent = File.ReadAllText(appFile)
                            processFileContent(appName, appFile, fileContent, webAppDescriptor)

                    // create the fingerprint object
                    let webAppFingerprint = createWebApplicationFingerprint(webAppDescriptor, interruptLoading)
                    let webAppTotalSign = webAppFingerprint.BaseSignatures.Count + (webAppFingerprint.Versions |> Seq.sumBy(fun v -> v.Signatures.Count))

                    // update counter
                    loadedVersions <- loadedVersions + webAppFingerprint.Versions.Count
                    loadedSignatures <- loadedSignatures + webAppTotalSign                        
                        
                    _logger.LoadedWebApplication(webAppFingerprint.Name, webAppFingerprint.Versions.Count, webAppTotalSign)
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
