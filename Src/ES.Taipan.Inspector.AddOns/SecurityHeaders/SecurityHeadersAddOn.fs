namespace ES.Taipan.Inspector.AddOns.SecurityHeaders

open System
open System.Collections.Generic
open System.Text.RegularExpressions
open ES.Taipan.Inspector
open ES.Taipan.Inspector.AddOns
open ES.Taipan.Infrastructure.Service
open ES.Taipan.Infrastructure.Network

[<AutoOpen>]
module private SecurityHeadersChecks =
    let createSecurityIssue(testRequest: TestRequest, id: Guid, name: String) =        
        let securityIssue = 
            new SecurityIssue(
                id, 
                Name = "Missing " + name.Split([|' '|]).[0], 
                Uri = testRequest.WebRequest.HttpRequest.Uri, 
                EntryPoint = EntryPoint.Header
            )
        securityIssue.Transactions.Add(testRequest.WebRequest, testRequest.WebResponse)        
        securityIssue

    let tryGetHeader (headers: List<HttpHeader>) (headerName: String) =
        headers |> Seq.tryFind(fun header -> header.Name.Equals(headerName, StringComparison.OrdinalIgnoreCase))

    let getValue(regex: String, txt: String) =
        let m = Regex.Match(txt, regex, RegexOptions.Singleline)
        if m.Success then
            Some <| m.Groups.[1].Value.Trim()
        else
            None

    let isMissingStrictTransportSecurity(testRequest: TestRequest, id: Guid, name: String, addSecurityIssue: SecurityIssue -> unit) =
        let securityIssue = createSecurityIssue(testRequest, id, name)
        securityIssue.Details.Properties.Add("MissingHeader", "Strict-Transport-Security")
             
        match tryGetHeader testRequest.WebResponse.HttpResponse.Headers "Strict-Transport-Security" with
        | Some header ->
            if
                (match getValue("max-age=([0-9]+)", header.Value)  with
                | Some maxAge when int32 maxAge < 604800 -> securityIssue.Details.Properties.Add("MaxAgeTooLow", maxAge); true
                | None -> securityIssue.Details.Properties.Add("MaxAgeTooLow", "0"); true
                | _ -> false)
            then
                addSecurityIssue(securityIssue)
        | None -> addSecurityIssue(securityIssue)

    let checkHeaderPresence(testRequest: TestRequest, headerName: String,  id: Guid, name: String, addSecurityIssue: SecurityIssue -> unit) =
        let securityIssue = createSecurityIssue(testRequest, id, name)
        securityIssue.Details.Properties.Add("MissingHeader", headerName)
             
        match tryGetHeader testRequest.WebResponse.HttpResponse.Headers headerName with
        | None -> addSecurityIssue(securityIssue)
        | _ -> ()

    let isMissingContentSecurityPolicy(testRequest: TestRequest,id: Guid, name: String, addSecurityIssue: SecurityIssue -> unit) =           
        checkHeaderPresence(testRequest, "Content-Security-Policy", id, name, addSecurityIssue)

    let isMissingPublicKeyPins(testRequest: TestRequest, id: Guid, name: String, addSecurityIssue: SecurityIssue -> unit) =           
        checkHeaderPresence(testRequest, "Public-Key-Pins", id, name, addSecurityIssue)

    let isMissingXFrameOptions(testRequest: TestRequest, id: Guid, name: String, addSecurityIssue: SecurityIssue -> unit) =           
        checkHeaderPresence(testRequest, "X-Frame-Options", id, name, addSecurityIssue)

    let isMissingXXSSProtection(testRequest: TestRequest, id: Guid, name: String, addSecurityIssue: SecurityIssue -> unit) =           
        let securityIssue = createSecurityIssue(testRequest, id, name)
        securityIssue.Details.Properties.Add("MissingHeader", "X-Xss-Protection")
             
        match tryGetHeader testRequest.WebResponse.HttpResponse.Headers "X-XSS-Protection" with
        | Some header ->
            if header.Value.Trim().StartsWith("0") then
                securityIssue.Details.Properties.Add("ProtectionDisabled", "1")
                addSecurityIssue(securityIssue)
        | None -> addSecurityIssue(securityIssue)

    let isMissingXContentTypeOptions(testRequest: TestRequest, id: Guid, name: String, addSecurityIssue: SecurityIssue -> unit) =           
        checkHeaderPresence(testRequest, "X-Content-Type-Options", id, name, addSecurityIssue)
                
type StrictTransportSecurityAddOn() as this =
    inherit BaseStatelessAddOn("Strict-Transport-Security Security Header AddOn", string StrictTransportSecurityAddOn.Id, 1)
    let mutable _vulnerabilitySignaled = false

    let addVulnerability(securityIssue: SecurityIssue) =
        // this check avoid to signal unlimited vulnerabilities of a specific type for each visited page
        if not _vulnerabilitySignaled then
            _vulnerabilitySignaled <- true
            this.Context.Value.AddSecurityIssue(securityIssue)

    static member Id = Guid.Parse("0C747F70-626B-4CBA-89A4-634C15FC019E")

    default this.Scan(testRequest: TestRequest, stateController: ServiceStateController) =
        isMissingStrictTransportSecurity(testRequest, StrictTransportSecurityAddOn.Id, this.Name, addVulnerability)

type ContentSecurityPolicyAddOn() as this =
    inherit BaseStatelessAddOn("Content-Security-Policy Security Header AddOn", string ContentSecurityPolicyAddOn.Id, 1)
    let mutable _vulnerabilitySignaled = false

    let addVulnerability(securityIssue: SecurityIssue) =
        // this check avoid to signal unlimited vulnerabilities of a specific type for each visited page
        if not _vulnerabilitySignaled then
            _vulnerabilitySignaled <- true
            this.Context.Value.AddSecurityIssue(securityIssue)

    static member Id = Guid.Parse("F08C4737-212B-4AA1-BE40-8AEFC6FCFF92")

    default this.Scan(testRequest: TestRequest, stateController: ServiceStateController) =
        isMissingContentSecurityPolicy(testRequest, ContentSecurityPolicyAddOn.Id, this.Name, addVulnerability)

type PublicKeyPinsAddOn() as this =
    inherit BaseStatelessAddOn("Public-Key-Pins Security Header AddOn", string PublicKeyPinsAddOn.Id, 1)
    let mutable _vulnerabilitySignaled = false

    let addVulnerability(securityIssue: SecurityIssue) =
        // this check avoid to signal unlimited vulnerabilities of a specific type for each visited page
        if not _vulnerabilitySignaled then
            _vulnerabilitySignaled <- true
            this.Context.Value.AddSecurityIssue(securityIssue)

    static member Id = Guid.Parse("A38DE8D5-EAEC-46E0-ACF1-77050D57AC14")

    default this.Scan(testRequest: TestRequest, stateController: ServiceStateController) =
        isMissingPublicKeyPins(testRequest, PublicKeyPinsAddOn.Id, this.Name, addVulnerability)

type XFrameOptionsAddOn() as this =
    inherit BaseStatelessAddOn("X-Frame-Options Security Header AddOn", string XFrameOptionsAddOn.Id, 1)
    let mutable _vulnerabilitySignaled = false

    let addVulnerability(securityIssue: SecurityIssue) =
        // this check avoid to signal unlimited vulnerabilities of a specific type for each visited page
        if not _vulnerabilitySignaled then
            _vulnerabilitySignaled <- true
            this.Context.Value.AddSecurityIssue(securityIssue)

    static member Id = Guid.Parse("BDC297BC-6BA4-4A31-8F8A-097874FB4C7D")

    default this.Scan(testRequest: TestRequest, stateController: ServiceStateController) =
        isMissingXFrameOptions(testRequest, XFrameOptionsAddOn.Id, this.Name, addVulnerability)

type XXSSProtectionAddOn() as this =
    inherit BaseStatelessAddOn("X-XSS-Protection Security Header AddOn", string XXSSProtectionAddOn.Id, 1)
    let mutable _vulnerabilitySignaled = false

    let addVulnerability(securityIssue: SecurityIssue) =
        // this check avoid to signal unlimited vulnerabilities of a specific type for each visited page
        if not _vulnerabilitySignaled then
            _vulnerabilitySignaled <- true
            this.Context.Value.AddSecurityIssue(securityIssue)

    static member Id = Guid.Parse("4A7C1CD6-DF73-462E-AF6C-976F12B8C83C")

    default this.Scan(testRequest: TestRequest, stateController: ServiceStateController) =
        isMissingXXSSProtection(testRequest, XXSSProtectionAddOn.Id, this.Name, addVulnerability)

type XContentTypeOptionsAddOn() as this =
    inherit BaseStatelessAddOn("X-Content-Type-Options Security Header AddOn", string XContentTypeOptionsAddOn.Id, 1)
    let mutable _vulnerabilitySignaled = false

    let addVulnerability(securityIssue: SecurityIssue) =
        // this check avoid to signal unlimited vulnerabilities of a specific type for each visited page
        if not _vulnerabilitySignaled then
            _vulnerabilitySignaled <- true
            this.Context.Value.AddSecurityIssue(securityIssue)

    static member Id = Guid.Parse("7D08B694-B6BB-49EF-92A5-244BD14AF836")

    default this.Scan(testRequest: TestRequest, stateController: ServiceStateController) =
        isMissingXContentTypeOptions(testRequest, XContentTypeOptionsAddOn.Id, this.Name, addVulnerability)