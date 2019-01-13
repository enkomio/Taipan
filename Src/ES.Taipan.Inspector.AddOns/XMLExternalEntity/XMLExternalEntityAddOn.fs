namespace ES.Taipan.Inspector.AddOns.XMLExternalEntity

open System
open System.Collections.Generic
open ES.Taipan.Inspector
open ES.Taipan.Inspector.AddOns
open ES.Taipan.Infrastructure.Service
open ES.Taipan.Infrastructure.Messaging
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Infrastructure.Text

// Info: https://www.honoki.net/2018/12/from-blind-xxe-to-root-level-file-read-access/
type XMLExternalEntityAddOn() as this =
    inherit BaseStatelessAddOn("XML External Entity AddOn", string XMLExternalEntityAddOn.Id, 1)

    let _analyzedPages = new HashSet<String>()

    let _logger =
        log "XMLExternalEntityAddOn"
        |> build

    let reportSecurityIssue(entryPoint: EntryPoint, webRequest: WebRequest, webResponse: WebResponse) =  
        let securityIssue = 
            new SecurityIssue(
                HttpBruteforcerAddOn.Id, 
                Name = "XML External Entity (XXE)", 
                Uri = webRequest.HttpRequest.Uri, 
                EntryPoint = EntryPoint.Header
            )

        securityIssue.Transactions.Add(webRequest, webResponse)
        this.Context.Value.AddSecurityIssue(securityIssue)    

    static member Id = Guid.Parse("77F5F5A9-EEA3-4622-BAD4-3EDBE8830E73")

    default this.Initialize(context: Context, webRequestor: IWebPageRequestor, messageBroker: IMessageBroker, logProvider: ILogProvider) =
        let initResult = base.Initialize(context, webRequestor, messageBroker, logProvider)
        logProvider.AddLogSourceToLoggers(_logger)
        // TODO load attack string template

        initResult
                        
    default this.Scan(testRequest: TestRequest, stateController: ServiceStateController) =        
        if testRequest.RequestType = TestRequestType.CrawledPage && _analyzedPages.Add(testRequest.WebRequest.HttpRequest.Uri.AbsolutePath) then
            ()