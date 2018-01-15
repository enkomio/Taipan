namespace ES.Taipan.Fingerprinter

open System
open System.Collections.Generic
open Microsoft.FSharp.Reflection

type ProgrammingLanguage =
    | Php
    | Html
    | Java
    | Asp
    | AspNet
    | Python
    | Ruby
    | NotRecognized of String

    override this.ToString() =
        match this with
        | Php -> "Php"
        | Html -> "Html"
        | Java -> "Java"
        | Asp -> "Asp"
        | AspNet -> "AspNet"
        | Python -> "Python"
        | Ruby -> "Ruby"
        | NotRecognized v -> "[NotRecognized] " + v

    member this.GetCommonExtensions() =
        match this with
        | Php -> [".php"]
        | Html -> [".htm"; ".html"]
        | Java -> [".jsp"; ".do"]
        | Asp -> [".asp"]
        | AspNet -> [".aspx"]
        | Python -> [".py"]
        | Ruby -> [".rb"]
        | _ -> []

    static member Parse(lang: String) =
        match lang.Trim().ToUpper() with
        | "PHP" -> Php
        | "HTML" -> Html
        | "JAVA" -> Java
        | "ASP" -> Asp
        | "ASPNET" -> AspNet
        | "PYTHON" -> Python
        | "RUBY" -> Ruby
        | v -> NotRecognized v

type WebServer =
    | Apache of String
    | Nginx of String
    | IIS of String
    | Zope2 of String
    | NotRecognized of String

    override this.ToString() =
        match this with
        | Apache v -> "Apache " + v
        | Nginx v -> "Nginx " + v
        | IIS v -> "Microsoft-IIS " + v
        | Zope2 v -> "Zope2 " + v
        | NotRecognized v -> "[Not recognized] " + v

type WebServerFingerprint() =
    member val Languages = new HashSet<ProgrammingLanguage>() with get
    member val Server = WebServer.NotRecognized String.Empty with get, set
    member val Frameworks = new HashSet<String>() with get

    override this.ToString() =
        let frameworks = String.Join(", ", this.Frameworks)
        let languages = 
            if this.Languages |> Seq.isEmpty then (ProgrammingLanguage.NotRecognized String.Empty).ToString()
            else String.Join(", ", this.Languages)
        String.Format("Lang={0}, Server={1}, Frameworks={2}", languages, this.Server, frameworks)


[<AutoOpen>]
module WebServerFingerprintUtils =

    let getAllSupportedLanguageNames() =
        FSharpType.GetUnionCases typeof<ProgrammingLanguage>
        |> Array.map(fun info -> info.Name)