namespace ES.Taipan.Infrastructure.Network

open System
open System.Collections.Generic
open System.IO
open System.Reflection
open OpenQA.Selenium
open OpenQA.Selenium.Chrome
open OpenQA.Selenium.Remote
open ES.Fslog

type Platform =
    | Windows
    | Unix
    | MacOSX
    with 
        override this.ToString() =
            match this with
            | Windows -> "Windows"
            | Unix -> "Unix"
            | MacOSX -> "MacOSX"
            
// see: https://stackoverflow.com/questions/18657976/disable-images-in-selenium-google-chromedriver
type ChromeOptionsWithPrefs() =
    inherit ChromeOptions()
    member val prefs = new Dictionary<String, Object>() with get, set

type SeleniumDriver(logProvider: ILogProvider) =
    let _basePath = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)
    let _syncRoot = new Object()
    let mutable _driver: ChromeDriver option = None
    let mutable _extensionDir = String.Empty
    
    let _log = 
        log "SeleniumDriver"
        |> error "Exception" "Exception Message: {0}. Stack trace: {1}"
        |> verbose "ConsoleLog" "Browser [{0}]: {1}"
        |> build
    do logProvider.AddLogSourceToLoggers(_log)

    let getPlatform() =
        match Environment.OSVersion.Platform with
        | PlatformID.Win32NT
        | PlatformID.Win32S
        | PlatformID.Win32Windows
        | PlatformID.WinCE -> Platform.Windows
        | PlatformID.MacOSX -> Platform.MacOSX
        | PlatformID.Unix -> Platform.Unix
        | _ -> failwith "Unable to determinate which platform is running on"

    let getChromePath() =
        let platformDirectory = 
            match getPlatform() with
            | Windows -> "Windows"
            | Unix -> 
                if Environment.Is64BitOperatingSystem then "Unix64"
                else "Unix32"
            | MacOSX -> failwith "OS not yet supported"
        Path.Combine(_basePath, "ChromeBins", platformDirectory)
        
    let getChromeDriverExec() =
        match getPlatform() with
        | Platform.Windows -> Path.Combine(_basePath, "driver", "win32", "chromedriver.exe")
        | Platform.Unix -> 
            let arch = if Environment.Is64BitOperatingSystem  then "linux64" else "linux32"
            Path.Combine(_basePath, "driver", arch, "chromedriver")
        | Platform.MacOSX -> failwith "OS not yet supported"

    let getChromeExecName() =
        match getPlatform() with
        | Platform.Windows -> "chrome.exe"
        | Platform.Unix -> "chrome"
        | Platform.MacOSX -> "chrome"

    // The following two methods are currently not useful since Chromium headless
    // doesn't support, at the time of this writing, extensions. When Extension will be
    // supported, the methods below will allow to read the body of the response.
    (*
    let packExtension() =        
        let baseDir = Path.Combine(_basePath, "Network", "Javascript")
        let templateDir = Path.Combine(baseDir, "SnifferExtension")
        let extensionPath = Path.Combine(baseDir, Guid.NewGuid().ToString("N"))
        
        // copy content
        Directory.CreateDirectory(extensionPath) |> ignore        
        for directory in Directory.GetDirectories(templateDir, "*", SearchOption.AllDirectories) do
            Directory.CreateDirectory(directory.Replace(templateDir, extensionPath)) |> ignore

        for file in Directory.GetFiles(templateDir, "*.*", SearchOption.AllDirectories) do
            File.Copy(file, file.Replace(templateDir, extensionPath), true)

        // create manifest file
        let manifestFile = Path.Combine(extensionPath, "manifest_template.json")
        if File.Exists(manifestFile) then
            let page = HttpUtility.getPage(httpRequest.Uri)
            let target = 
                String.Format("{0}://{1}:{2}{3}*", 
                    httpRequest.Uri.Scheme, 
                    httpRequest.Uri.Host, 
                    httpRequest.Uri.Port, 
                    if String.IsNullOrWhiteSpace(page) then "/"
                    else httpRequest.Uri.AbsolutePath.Replace(page, String.Empty)
                )
            let manifest = File.ReadAllText(manifestFile).Replace("TARGET_URL", target)
            File.WriteAllText(Path.Combine(extensionPath, "manifest.json"), manifest)

        extensionPath    

    let cleanUpExtension(extensionDir: String) =
        Directory.Delete(extensionDir, true)
    *)

    let getLogs() = [
        for logType in _driver.Value.Manage().Logs.AvailableLogTypes do            
            for logEntry in _driver.Value.Manage().Logs.GetLog(logType) do
                yield logEntry
    ]
            
    let _chrome = Path.Combine(getChromePath(), getChromeExecName())

    member val ProxyUrl: String option = None with get, set
    member val TakeScreenShot = false with get, set

    member this.Initialize() =      
        lock _syncRoot (fun () ->
            //_extensionDir <- packExtension() 

            try
                let chromeOptions = new ChromeOptionsWithPrefs(BinaryLocation = _chrome)            
                chromeOptions.AddArguments
                    (
                        "--headless", 
                        "--disable-gpu", 
                        "--no-sandbox", 
                        "--disable-infobar",
                        "--disable-setuid-sandbox",
                        "--ignore-certificate-errors",
                        "--disable-web-security",
                        "--silent"
                        //"load-extension=" + _extensionDir
                    )
                chromeOptions.AddExcludedArgument("test-type")   
            
                // set proxy if necessary
                if this.ProxyUrl.IsSome && not(String.IsNullOrWhiteSpace(this.ProxyUrl.Value)) then
                    chromeOptions.Proxy.HttpProxy <- this.ProxyUrl.Value

                // avoid to load images
                // see: https://stackoverflow.com/questions/18657976/disable-images-in-selenium-google-chromedriver
                let images = new Dictionary<String, Object>()
                images.Add("images", 2)                
                chromeOptions.prefs.Add("profile.default_content_settings", images)
                
                // create the driver
                let chromeDriverService = ChromeDriverService.CreateDefaultService(_basePath,  getChromeDriverExec())
                _driver <- Some <| new ChromeDriver(chromeDriverService, chromeOptions)
             with _ as ex -> 
                _log?Exception(ex.Message, ex.StackTrace)
        )        

    member this.Dispose() =
        //cleanUpExtension(_extensionDir)

        if _driver.IsSome then
            _driver.Value.Quit()

    member this.ExecuteScript(httpRequest: HttpRequest, scriptSrc: String, args: Object) =
        lock _syncRoot (fun () ->
            let mutable result: Dictionary<String, Object> option = None
            let urlData = "data:text/html;charset=utf-8," + Uri.UnescapeDataString(httpRequest.Source.Value.DocumentHtml)
 
            try
                // try to reset browser state
                _driver.Value.ResetInputState()            
                try
                    // from time to time this operation generates an exception :?
                    _driver.Value.Manage().Cookies.DeleteAllCookies()
                with _ -> ()
                    
                _driver.Value.Url <- urlData
                let beforeExecutionLogs = getLogs() |> List.map(fun log -> log.Message)
                
                // add cookies
                for cookie in httpRequest.Cookies do
                    _driver.Value.Manage().Cookies.AddCookie(new Cookie(cookie.Name, cookie.Value, cookie.Path))

                // execute send request script
                let scriptOutput = _driver.Value.ExecuteScript(scriptSrc, [|args|])
                getLogs()
                |> List.filter(fun log -> not(beforeExecutionLogs |> List.contains log.Message))
                |> List.iter(fun logEntry ->
                    let level = logEntry.Level.ToString()
                    let msg = logEntry.Message
                    _log?ConsoleLog(level, msg)
                )   

                // verify if page has full loaded by checking the existence of result variable
                let mutable executionCompleted = false
                while not executionCompleted do
                    try
                        result <- Some(_driver.Value.ExecuteScript("return result;", [||])  :?> Dictionary<String, Object>)
                        let counter = ref 1
                        while result.IsSome && (!counter) < 20 do
                            incr counter
                            if not(String.IsNullOrWhiteSpace(result.Value.["error"].ToString())) then
                                executionCompleted <- true
                            else
                                // read result againt until I get an exception
                                System.Threading.Thread.Sleep(500 * (!counter))
                                result <- Some(_driver.Value.ExecuteScript("return result;", [||])  :?> Dictionary<String, Object>)

                        // some unknow error :\
                        result.Value.["error"] <- "Unknow error"
                        executionCompleted <- true
                    with 
                        | :? UnhandledAlertException as e ->
                            let alert = _driver.Value.SwitchTo().Alert()
                            alert.Accept()
                        | _ ->
                            // result not defined, this means final page has loaded
                            executionCompleted <- true

                if result.IsNone || String.IsNullOrWhiteSpace(result.Value.["error"].ToString()) then
                    // page full loaded without errors, read content
                    result <- Some(new Dictionary<String, Object>())
                    result.Value.["error"] <- String.Empty
                    result.Value.["html"] <- _driver.Value.PageSource
                    result.Value.["output"] <- scriptOutput
                
                // save a screenshot if specified
                if this.TakeScreenShot then
                    let screenshot = _driver.Value.GetScreenshot()
                    let filename = Guid.NewGuid().ToString("N")
                    screenshot.SaveAsFile(filename, OpenQA.Selenium.ScreenshotImageFormat.Gif)
                    result.Value.["gif"] <- File.ReadAllBytes(filename)
                    File.Delete(filename)

                // add cookies
                let cookies = new List<System.Net.Cookie>()
                result.Value.["cookies"] <- cookies
                for cookie in _driver.Value.Manage().Cookies.AllCookies do                
                    let netCookie = new System.Net.Cookie(cookie.Name, cookie.Value, cookie.Path, cookie.Domain)
                    netCookie.HttpOnly <- cookie.IsHttpOnly
                    netCookie.Secure <- cookie.Secure
                    cookies.Add(netCookie)

                // This features is not implemented since Chrome HEadless doesn't support extension at this time
                // Try to use installed extension to read all the requests and responses done
                if result.IsSome && String.IsNullOrWhiteSpace(result.Value.["error"].ToString()) then                              
                    let responses = _driver.Value.ExecuteScript("if (typeof networkRequests !== 'undefined') {return networkRequests;}", [||])
                    result.Value.["network"] <- responses
            
            with _ as ex -> 
                _log?Exception(ex.Message, ex.StackTrace)

            result
        )        
        
    interface IDisposable with
        member this.Dispose() =
            this.Dispose()