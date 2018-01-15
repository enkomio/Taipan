namespace ES.Taipan.Fingerprinter

open System

type IWebServerFingerprinter =
    interface
        abstract Fingerprint: Uri -> WebServerFingerprint        
    end

