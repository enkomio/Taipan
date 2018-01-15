namespace ES.Taipan.Fingerprinter

open System
open System.Collections.Generic

type IWebApplicationFingerprintRepository =
    interface
        abstract LoadSignatures : String seq * (unit -> Boolean)-> unit
        abstract LoadScripts : String seq * (unit -> Boolean)-> unit
        abstract GetAllWebApplications : unit -> List<WebApplicationFingerprint>
        abstract GetCustomScriptCheckers : unit -> List<BaseSignature>
    end

