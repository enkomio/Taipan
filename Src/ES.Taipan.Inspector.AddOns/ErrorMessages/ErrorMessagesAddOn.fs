namespace ES.Taipan.Inspector.AddOns.ErrorMessages

open System
open System.Collections.Generic
open System.Text.RegularExpressions
open ES.Taipan.Inspector
open ES.Taipan.Inspector.AddOns
open ES.Taipan.Infrastructure.Service
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Crawler

type ErrorMessagesAddOn() as this =
    inherit BaseStatelessAddOn("Error Messages AddOn", string ErrorMessagesAddOn.Id, 1)       
    let _analyzedPages = new HashSet<String>()
    let _signaledLeakage = new HashSet<String>()

    let createSecurityIssue(uri: Uri, webRequest: WebRequest, webResponse: WebResponse) =
        let securityIssue = 
                new SecurityIssue(
                    ErrorMessagesAddOn.Id, 
                    Name = "Error Messages", 
                    Uri = uri, 
                    EntryPoint = EntryPoint.Other "Page Content"  
                )
        securityIssue.Transactions.Add(webRequest, webResponse)
        securityIssue                    

    let checkSymfonyException(html: String, securityIssue: SecurityIssue) =
        if Regex.IsMatch(html, "Symfony.Component.HttpKernel.Exception.NotFoundHttpException", RegexOptions.Singleline) then            
            let rxMatch = Regex.Match(html, "<a title=\"([^ ]+) line 145\" .+?>RouteCollection.php.+?</a>")
            securityIssue.Details.Properties.Add("Error", rxMatch.Groups.[0].Value.Trim())

            if rxMatch.Success then
                let fullPath = rxMatch.Groups.[1].Value.Trim()
                securityIssue.Details.Properties.Add("Symfony Full Path", fullPath)
            else
                let rxMatch = Regex.Match(html, "exception 'Symfony.Component.HttpKernel.Exception.NotFoundHttpException' in (.+?):")
                if rxMatch.Success then
                    let fullPath = rxMatch.Groups.[1].Value.Trim()
                    securityIssue.Details.Properties.Add("Symfony Full Path", fullPath)
            
            securityIssue.Note <- "Symfony exception error"                        
            this.Context.Value.AddSecurityIssue(securityIssue)

    let checkPhpErrors(html: String, securityIssue: SecurityIssue) =  
        // fopen error       
        let rxMatch = Regex.Match(html, "failed to open stream: No such file or directory in <b>(.+?)</b>", RegexOptions.Singleline)
        if rxMatch.Success then
            securityIssue.Details.Properties.Add("Error", rxMatch.Groups.[0].Value.Trim())

            let fullPath = rxMatch.Groups.[1].Value.Trim()
            securityIssue.Details.Properties.Add("Installation Full Path", fullPath)
            securityIssue.Note <- "PHP fopen error"            
            this.Context.Value.AddSecurityIssue(securityIssue) 

    let checkRubyErrors(html: String, securityIssue: SecurityIssue) =  
        if ["<h1>Template is missing</h1>"; "<p>Missing template"; "Searched in:"] |> List.forall (html.Contains) then
            
            let rxMatch = Regex.Match(html, "Searched in:(.+?)</p>", RegexOptions.Singleline)
            if rxMatch.Success then
                securityIssue.Details.Properties.Add("Error", rxMatch.Groups.[0].Value.Trim())
                let pathList = rxMatch.Groups.[1].Value.Trim()
                securityIssue.Details.Properties.Add("Ruby On Rails Path List", pathList)
            
            securityIssue.Note <- "Ruby On Rails error"            
            this.Context.Value.AddSecurityIssue(securityIssue) 

    let checkDotNetErrors(html: String, securityIssue: SecurityIssue) =  
        let errors = 
            [
                "<b> Description: </b>"; 
                "An exception occurred while processing your request. Additionally, another exception occurred while executing the custom error page for the first exception. The request has been terminated."
            ]
        if errors |> List.forall (html.Contains) then            
            securityIssue.Note <- "ASP.NET error"            
            securityIssue.Details.Properties.Add("Error", errors.[0])
            this.Context.Value.AddSecurityIssue(securityIssue) 

    let checkApacheTomcatErrors(html: String, securityIssue: SecurityIssue) =  
        let mutable isVulnerable = false
        if html.Contains("java.lang.ClassCastException") then            
            securityIssue.Note <- "Apache Tomcat error"
            securityIssue.Details.Properties.Add("Error", "java.lang.ClassCastException")
            isVulnerable <- true            

        if ["Apache Tomcat/"; "Error report"] |> List.forall (html.Contains) then            
            securityIssue.Note <- "Apache Tomcat error"
            securityIssue.Details.Properties.Add("Error", "Apache Tomcat, Error report")
            isVulnerable <- true            

        if isVulnerable then
            this.Context.Value.AddSecurityIssue(securityIssue) 
            
    let checkForGenericError(webLink: WebLink, html: String, securityIssue: SecurityIssue) =  
        if webLink.OriginalWebLink.IsNone && ["<h2>500 - Internal server error.</h2>"; "<h3>There is a problem with the resource you are looking for, and it cannot be displayed.</h3>"] |> List.forall (html.Contains) then
            securityIssue.Note <- "500 Internal server error"      
            securityIssue.Details.Properties.Add("Error", "<h3>There is a problem with the resource you are looking for, and it cannot be displayed.</h3>")      
            this.Context.Value.AddSecurityIssue(securityIssue) 

    static member Id = Guid.Parse("73EF90A2-C2A4-44AE-82DE-35349AEDFFB3")
                                        
    default this.Scan(testRequest: TestRequest, stateController: ServiceStateController) =
        if _analyzedPages.Add(testRequest.WebRequest.HttpRequest.Uri.PathAndQuery) then
            let html = testRequest.WebResponse.HttpResponse.Html            
            let securityIssue = createSecurityIssue(testRequest.WebRequest.HttpRequest.Uri, testRequest.WebRequest, testRequest.WebResponse)

            if testRequest.RequestType = TestRequestType.CrawledPage then
                let webLink = testRequest.GetData<Object>() :?> WebLink                
                checkForGenericError(webLink, html, securityIssue)

            // run specific checks
            checkSymfonyException(html, securityIssue)
            checkPhpErrors(html, securityIssue)
            checkRubyErrors(html, securityIssue)
            checkDotNetErrors(html, securityIssue)
            checkApacheTomcatErrors(html, securityIssue)