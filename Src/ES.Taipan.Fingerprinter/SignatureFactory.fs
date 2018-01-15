namespace ES.Taipan.Fingerprinter

open System
open System.Xml.Linq
open System.Linq
open ES.Fslog

module SignatureFactory =
    let private x str = XName.Get str
        
    let (|MD5|FILE|LUA|) xmlContent =
        
        if Md5MatchesSignature.IsValidXmlSignature(xmlContent) then MD5
        elif FileExistsSignature.IsValidXmlSignature(xmlContent) then FILE
        elif LuaScriptSignature.IsValidXmlSignature(xmlContent) then LUA
        else raise <| new ApplicationException("Signature not recognized. Unable to create the signature object from XML content: " + xmlContent)

    let createSignatureFromXml(xmlContent: String, logProvider: ILogProvider) : BaseSignature =
        match xmlContent with
        | FILE -> 
            let fileSign = new FileExistsSignature()
            fileSign.AcquireFromXml(xmlContent)
            upcast fileSign
        | MD5 -> 
            let md5Sign = new Md5MatchesSignature()
            md5Sign.AcquireFromXml(xmlContent)
            upcast md5Sign
        | LUA ->
            let luaScriptSign = new LuaScriptSignature(logProvider)
            luaScriptSign.AcquireFromXml(xmlContent)
            upcast luaScriptSign 