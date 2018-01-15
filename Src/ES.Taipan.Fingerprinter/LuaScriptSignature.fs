namespace ES.Taipan.Fingerprinter

open System
open System.IO
open System.Text.RegularExpressions
open ES.Taipan.Infrastructure.Network
open System.Xml.Linq
open System.Linq
open MoonSharp.Interpreter
open ES.Fslog

type LuaSignatureVerificationResult(found: Boolean, request: WebRequest, response: WebResponse) =
    inherit SignatureVerificationResult(found, request, response)
    member val AppName = String.Empty with get, set
    member val AppVersion = String.Empty with get, set

type LuaScriptSignatureLogger() =
    inherit LogSource("LuaScriptSignature")
    
    [<Log(1, Message = "Lua [{0}]: {1}", Level = LogLevel.Verbose)>]
    member this.Log(scriptId: Guid, txt: Object) =
        this.WriteLog(1, [|scriptId; txt|])

    [<Log(2, Message = "Lua [{0}]: {1}", Level = LogLevel.Error)>]
    member this.ScriptError(scriptId: Guid, txt: Object) =
        this.WriteLog(2, [|scriptId; txt|])

    [<Log(3, Message = "Execute LUA script '{0}' on url: {1}", Level = LogLevel.Verbose)>]
    member this.StartExecution(scriptName: String, url: String) =
        this.WriteLog(3, [|scriptName; url|])

type LuaScriptSignature(logProvider: ILogProvider) =
    inherit BaseSignature()

    static let x str = XName.Get str

    let mutable _lastRequest = new WebRequest("http://0.0.0.0")
    let mutable _lastResponse = new WebResponse(new HttpResponse())
    let _logger = new LuaScriptSignatureLogger()
    do logProvider.AddLogSourceToLoggers(_logger)

    let getRequest (webPageRequestor: IWebPageRequestor) (uri: String) =
        let webRequest = new WebRequest(uri)
        let webResponse = webPageRequestor.RequestWebPage(webRequest)
        if webResponse.PageExists then
            _lastRequest <- webRequest
            _lastResponse <- webResponse
            webResponse.HttpResponse.Html
        else 
            String.Empty

    let postRequest (webPageRequestor: IWebPageRequestor) (uri: String) (data: String) =
        let webRequest = new WebRequest(uri)
        webRequest.HttpRequest.Data <- data
        webRequest.HttpRequest.Method <- HttpMethods.Post
        let webResponse = webPageRequestor.RequestWebPage(webRequest)
        if webResponse.PageExists then
            _lastRequest <- webRequest
            _lastResponse <- webResponse
            webResponse.HttpResponse.Html
        else 
            String.Empty

    member val Id = Guid.NewGuid() with get, set
    member val Code = String.Empty with get, set
    member val FilePath = String.Empty with get, set
    member val ApplicationName = String.Empty with get, set
    member val TargetLanguage = String.Empty with get, set

    static member IsValidXmlSignature(xml: String) =
        let doc = XDocument.Parse(xml)
        let root = doc.Element(x"LuaScriptSignature")
        root <> null

    override this.Verify(directory: String, webPageRequestor: IWebPageRequestor) =
        let script = new Script()
        script.Globals.["getRequest"] <- new Func<String, String>(getRequest webPageRequestor)
        script.Globals.["postRequest"] <- new Func<String, String, String>(postRequest webPageRequestor)
        script.Globals.["log"] <- new Func<Object, unit>(fun v -> _logger.Log(this.Id, v))
        script.Globals.["uri"] <- directory
        try
            _logger.StartExecution(this.FilePath, directory)
            if script.DoString(this.Code).Boolean then                
                let appVersion = script.Globals.["appVersion"]
                if appVersion <> null then
                    upcast new LuaSignatureVerificationResult(true, _lastRequest, _lastResponse, AppName = this.ApplicationName, AppVersion = appVersion.ToString(), Signature = (this :> ISignature |> Some))
                else
                    upcast new LuaSignatureVerificationResult(false, _lastRequest, _lastResponse, Signature = (this :> ISignature |> Some))
            else
                upcast new LuaSignatureVerificationResult(false, _lastRequest, _lastResponse, Signature = (this :> ISignature |> Some))
        with 
            :? ScriptRuntimeException as ex ->
                _logger.ScriptError(this.Id, ex.DecoratedMessage)
                upcast new LuaSignatureVerificationResult(false, _lastRequest, _lastResponse, Signature = (this :> ISignature |> Some))
            
    override this.AcquireFromXml(xml: String) =
        let doc = XDocument.Parse(xml)
        let root = doc.Element(x"LuaScriptSignature")
        this.Id <- Guid.Parse(root.Element(x"Id").Value)
        this.ApplicationName <- root.Element(x"ApplicationName").Value
        this.TargetLanguage <- root.Element(x"TargetLanguage").Value

    override this.ToString() =
        String.Format("Script: {0}", this.FilePath)

    override this.Equals(o: Object) =
        match o with
        | :? LuaScriptSignature as s -> s.Code.Equals(this.Code, StringComparison.Ordinal) 
        | _ -> false