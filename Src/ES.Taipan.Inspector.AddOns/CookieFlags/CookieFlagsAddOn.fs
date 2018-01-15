namespace ES.Taipan.Inspector.AddOns.CookieFlags

open System
open System.Net
open System.Threading
open System.Collections.Generic
open System.Collections.Concurrent
open System.Text.RegularExpressions
open ES.Taipan.Inspector
open ES.Taipan.Inspector.AddOns
open ES.Taipan.Infrastructure.Service
open ES.Taipan.Infrastructure.Messaging
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Fingerprinter
open ES.Fslog

[<AutoOpen>]
module private CookieFlagsChecks =
    let createSecurityIssue(testRequest: TestRequest, id: Guid, name: String, cookie: Cookie) =        
        let securityIssue = 
            new SecurityIssue(
                id, 
                Name = name,
                Uri = testRequest.WebRequest.HttpRequest.Uri, 
                EntryPoint = EntryPoint.Header
            )
        securityIssue.Details.Properties.Add("Parameter", cookie.Name)
        securityIssue.Details.Properties.Add("Synopsis", String.Format("{0} - Cookie: {1}", testRequest.WebRequest.HttpRequest.Uri.AbsolutePath, cookie.Name))
        securityIssue.Transactions.Add(testRequest.WebRequest, testRequest.WebResponse)        
        securityIssue        
                
type MissingHttpOnlyCookieFlagAddOn() =
    inherit BaseStatelessAddOn("Cookie Missing HttpOnly Flag AddOn", "A719DE80-32BF-4E53-BCB2-D138BF953853", 1)
    let _signaledCookies = new HashSet<String>()
    
    default this.Scan(testRequest: TestRequest, stateController: ServiceStateController) =
        match testRequest.WebResponse.HttpResponse.Cookies |> Seq.tryFind(fun cookie -> not cookie.HttpOnly) with
        | Some cookie ->
            if _signaledCookies.Add(cookie.Name) then
                let securityIssue = createSecurityIssue(testRequest, this.Id, "Cookie Not Marked As HttpOnly", cookie)
                this.Context.Value.AddSecurityIssue(securityIssue)
        | None -> ()

type MissingSecureCookieFlagAddOn() =
    inherit BaseStatelessAddOn("Cookie Missing Secure Flag AddOn", "FDC3E54E-98F2-4C14-A620-9E4629CAEE0B", 1)
    let _signaledCookies = new HashSet<String>()

    default this.Scan(testRequest: TestRequest, stateController: ServiceStateController) =
        if testRequest.WebRequest.HttpRequest.Uri.Scheme.Equals("https", StringComparison.Ordinal) then            
            match testRequest.WebResponse.HttpResponse.Cookies |> Seq.tryFind(fun cookie -> not cookie.Secure) with
            | Some cookie ->
                if _signaledCookies.Add(cookie.Name) then
                    let securityIssue = createSecurityIssue(testRequest, this.Id, "Cookie Not Marked As Secure", cookie)
                    this.Context.Value.AddSecurityIssue(securityIssue)
            | None -> ()
            