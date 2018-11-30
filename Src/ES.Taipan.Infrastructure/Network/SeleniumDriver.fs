namespace ES.Taipan.Infrastructure.Network

open System
open System.Collections.Generic
open System.IO
open System.Reflection
open OpenQA.Selenium
open OpenQA.Selenium.Chrome
open ES.Fslog
open System.Text

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
    let mutable _initialRequestDone = false
    
    let _log = 
        log "SeleniumDriver"
        |> error "Exception" "Exception Message: {0}. Stack trace: {1}"
        |> warning "BinaryNotFound" "The Chrome binary wasn't found, unable to run Javascript"
        |> verbose "ConsoleLog" "Browser [{0}]: {1}"
        |> buildAndAdd logProvider

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
            | Windows -> "Windows32"
            | Unix -> "Linux64"
            | MacOSX -> failwith "OS not yet supported"
        Path.Combine(_basePath, "ChromeBins", platformDirectory)

    let getChromeDriverPath() =
        match getPlatform() with
        | Platform.Windows -> Path.Combine(_basePath, "driver", "win32")
        | Platform.Unix -> Path.Combine(_basePath, "driver", "linux64")
        | Platform.MacOSX -> failwith "OS not yet supported"
        
    let getChromeDriverExecName() =
        match getPlatform() with
        | Platform.Windows -> "chromedriver.exe"
        | Platform.Unix -> "chromedriver"
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

    let doInitialRequestIfNecessary(httpRequest: HttpRequest) =
        if not _initialRequestDone then
            _initialRequestDone <- true
            let ub = new UriBuilder(httpRequest.Uri)
            ub.Path <- String.Empty
            ub.Query <- String.Empty
            let initialUri = new Uri(ub.Uri, Guid.NewGuid().ToString("N"))
            _driver.Value.Url <- initialUri.AbsoluteUri    
            
    let _chrome = Path.Combine(getChromePath(), getChromeExecName())

    member val ProxyUrl: String option = None with get, set
    member val TakeScreenShot = false with get, set

    member this.Initialize() =      
        lock _syncRoot (fun () ->
            //_extensionDir <- packExtension() 
            try
                if File.Exists(_chrome) then
                    let chromeOptions = new ChromeOptionsWithPrefs(BinaryLocation = _chrome)            
                    chromeOptions.AddArguments
                        (
                            "--headless" ,
                            "--disable-gpu", 
                            "--no-sandbox", 
                            "--disable-infobar",
                            "--disable-setuid-sandbox",
                            "--ignore-certificate-errors",
                            "--disable-web-security",
                            "--disable-xss-auditor",
                            "--log-level=3",
                            "--silent",
                            "--blink-settings=imagesEnabled=false"
                            //"load-extension=" + _extensionDir
                        )
                    chromeOptions.AddExcludedArgument("test-type")
                
                    // set proxy if necessary (must be in the form: <IP>:<PORT>)
                    if this.ProxyUrl.IsSome && not(String.IsNullOrWhiteSpace(this.ProxyUrl.Value)) then                    
                        // in headless mode the HTTPS proxy doesn't seem to work :\
                        let proxySettings= String.Format("--proxy-server=https={0};http={0}", this.ProxyUrl.Value)
                        chromeOptions.AddArgument(proxySettings)

                    // avoid to load images
                    // see: https://stackoverflow.com/questions/18657976/disable-images-in-selenium-google-chromedriver
                    let images = new Dictionary<String, Object>()
                    images.Add("images", 2)                
                    chromeOptions.prefs.Add("profile.default_content_settings", images)

                    // create the driver                
                    let chromeDriverService = ChromeDriverService.CreateDefaultService(getChromeDriverPath(),  getChromeDriverExecName())
                    _driver <- Some <| new ChromeDriver(chromeDriverService, chromeOptions)
                else
                    _log?BinaryNotFound()
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
            let urlData = Uri.UnescapeDataString(httpRequest.Source.Value.DocumentHtml)
            
            try
                if _driver.IsSome && not(String.IsNullOrWhiteSpace(urlData)) then
                    // try to reset browser state
                    _driver.Value.ResetInputState()            
                    try
                        // from time to time this operation generates an exception :?
                        _driver.Value.Manage().Cookies.DeleteAllCookies()
                    with _ -> ()
                
                    // make the initial request if necessary, this will set the
                    // origin inside the Chrome browser
                    doInitialRequestIfNecessary(httpRequest)

                    let beforeExecutionLogs = 
                        getLogs() 
                        |> List.map(fun log -> log.Message)
                
                    // add cookies via Javascript, for some reason I wasn't able to set it via webdriver
                    for cookie in httpRequest.Cookies do  
                        // if you wonder why of this replacement, take a look at: https://googlechrome.github.io/samples/cookie-prefixes/
                        let cookieValue = cookie.Value.Replace("__Host-", String.Empty).Replace("__Secure-", String.Empty)
                        let setCookieJs = String.Format("document.cookie = '{0}={1}';", cookie.Name, cookieValue)
                        _driver.Value.ExecuteScript(setCookieJs, Array.empty<Object>) |> ignore

                    // load the data by doing a document.write. Not the origin should already be set
                    let encodedUrlData = Convert.ToBase64String(Encoding.Default.GetBytes(urlData))
                    let evalScript = String.Format("document.write(atob('{0}'));", encodedUrlData)
                    _driver.Value.ExecuteScript(evalScript, Array.empty<Object>) |> ignore

                    // wait until the content is fully loaded
                    let mutable trialLimit = 0
                    let mutable fullyLoaded = _driver.Value.ExecuteScript("return document.readyState;", Array.empty<Object>)
                    while trialLimit < 10 && not(fullyLoaded.ToString().Equals("complete", StringComparison.OrdinalIgnoreCase)) do
                        Async.Sleep(500) |> Async.RunSynchronously
                        fullyLoaded <- _driver.Value.ExecuteScript("return document.readyState;", Array.empty<Object>)
                        trialLimit <- trialLimit + 1

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
                            result.Value.["html"] <- String.Empty
                            result.Value.["output"] <- new Dictionary<String, Object>()
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

                    elif result.IsSome then
                        result.Value.["html"] <- _driver.Value.PageSource
                        result.Value.["output"] <- scriptOutput
                
                    // save a screenshot if specified
                    if this.TakeScreenShot then
                        let screenshot = _driver.Value.GetScreenshot()
                        result.Value.["gif"] <- screenshot.AsByteArray

                    // add cookies
                    let cookies = new List<System.Net.Cookie>()
                    result.Value.["cookies"] <- cookies
                    for cookie in _driver.Value.Manage().Cookies.AllCookies do                
                        let netCookie = new System.Net.Cookie(cookie.Name, cookie.Value, cookie.Path, cookie.Domain)
                        netCookie.HttpOnly <- cookie.IsHttpOnly
                        netCookie.Secure <- cookie.Secure
                        cookies.Add(netCookie)

                    // This features is not implemented since Chrome Headless doesn't support extension at this time
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