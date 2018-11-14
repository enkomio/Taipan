open System
open System.Reflection
open ES.Taipan.Crawler
open ES.Taipan.Discoverer
open ES.Taipan.Fingerprinter
open Microsoft.FSharp.Quotations
open Microsoft.FSharp.Quotations.Patterns
open Microsoft.FSharp.Quotations.DerivedPatterns
open FSharp.Quotations.Evaluator

let allTests : Expr<Uri -> unit> list = [
    
    // Discovere tests
    <@ DiscovererTests.``Non recursive discoverer of hidden resources`` @>
    <@ DiscovererTests.``Recursive discoverer of hidden resources`` @>
    <@ DiscovererTests.``Recursive discoverer of hidden resources with forbidden directories`` @>
    <@ DiscovererTests.``Recursive discoverer of hidden resources and infer extension to use for files`` @>
    <@ DiscovererTests.``Recursive discoverer of hidden resources and using blank extension`` @>
    <@ DiscovererTests.``Recursive discoverer of hidden resources identifing a forbidden resource`` @>
    <@ DiscovererTests.``Recursive discoverer of hidden resources identifing a redirect resource`` @>
    <@ DiscovererTests.``The entrypoint for the discover is a file`` @>
    <@ DiscovererTests.``Ensure that redirect to an hidden directory doesn't generate two discovery`` @>
    
    // Web Application fingerprint tests
    <@ FingerprinterTests.``Fingerprint a Joomla fake web application`` @>
    <@ FingerprinterTests.``Ensure that if the dependant application is not found neither the plugin is found`` @>
    <@ FingerprinterTests.``Fingerprint a Joomla plugin fake web application that depends on another application`` @>

    // Crawler tests
    <@ CrawlerTests.``Crawl a simple web link`` @>
    <@ CrawlerTests.``Ensure that the scope is correctly considered`` @>
    <@ CrawlerTests.``Ensure that the referer is correctly setted`` @>
    <@ CrawlerTests.``Ensure that the forbidden extension are not crawled`` @>
    <@ CrawlerTests.``Ensure that the forbidden content-type are not crawled`` @>
    <@ CrawlerTests.``Ensure that HTTP redirect are crawled`` @>
    <@ CrawlerTests.``Ensure that HTML meta redirect are crawled`` @>
    <@ CrawlerTests.``Ensure that POST requests are crawled`` @>
    <@ CrawlerTests.``Ensure that POST requests with values are crawled`` @> 
    <@ CrawlerTests.``Ensure that GET forms with values are crawled`` @>
    <@ CrawlerTests.``Find web link via query mutation`` @>
    <@ CrawlerTests.``Find web link via mutation from GET to POST`` @> 
    //<@ CrawlerTests.``Test for MaxNumOfPagesToCrawl`` @>
    <@ CrawlerTests.``Find web link without extension`` @>
    <@ CrawlerTests.``Ensure that encoded parameters are correctly managed`` @> 
    <@ CrawlerTests.``Identify a link in a comment via mutation`` @> 
    <@ CrawlerTests.``Test for MaxNumOfRequestsToTheSamePage`` @>
    <@ CrawlerTests.``Ensure that POST requests with file input are crawled`` @>
    <@ CrawlerTests.``Ensure that session is honored after login`` @>
    <@ CrawlerTests.``Parse a link created via Javascript`` @>
    <@ CrawlerTests.``Parse a form created via Javascript with pre-processing`` @>
    <@ CrawlerTests.``Crawl a Basic HTTP Authenticated page`` @>
    <@ CrawlerTests.``Crawl a Digest HTTP Authenticated page`` @>
    <@ CrawlerTests.``Crawl a Bearer HTTP Authenticated page`` @>
    <@ CrawlerTests.``Ensure that a link on another port is not followed`` @>
    <@ CrawlerTests.``Crawl an Authenticated page via pre-authenticated cookie`` @>
     
    // Inspector tests
    <@ InspectorTests.``Identify a directory listing`` @>
    <@ InspectorTests.``Identify an outdated web application`` @>
    <@ InspectorTests.``Identify internal IP info leak`` @>
    <@ InspectorTests.``Identify info leak due to an email in an HTML comments`` @>
    <@ InspectorTests.``Identify info leak due to an hyperlink in an HTML content`` @>
    <@ InspectorTests.``Identify missing security headers`` @>
    <@ InspectorTests.``Identify Strict Transport Layer with a too low maxage value`` @>
    <@ InspectorTests.``Identify X-XSS-Protection but disabled`` @>
    <@ InspectorTests.``X-XSS-Protection, Public-Key-Pins and Strict-Transport-Security are correctly setted`` @>
    <@ InspectorTests.``Identify a web application with know vulnerabilities`` @>
    <@ InspectorTests.``Ensure that the version range in the vulnerability description is satisfied`` @>
    <@ InspectorTests.``Identify Synfony error`` @>
    <@ InspectorTests.``Identify Synfony error second variant`` @>
    <@ InspectorTests.``PHP fopen error`` @>
    <@ InspectorTests.``Ruby On Rails error`` @>
    <@ InspectorTests.``ASP.NET error`` @>
    <@ InspectorTests.``500 Internal server error`` @>
    <@ InspectorTests.``RXSS in query parameter`` @>
    <@ InspectorTests.``RXSS on data parameter`` @>
    <@ InspectorTests.``RXSS in User-Agent`` @>
    <@ InspectorTests.``Identify info leak in .DS_Store file`` @>
    <@ InspectorTests.``RXSS in filename parameter`` @>
    <@ InspectorTests.``Sqli error based in name parameter`` @>
    <@ InspectorTests.``Sqli error based in name parameter with AntiCSRF protection`` @>
    <@ InspectorTests.``RXSS on data parameter and AntiCSRF protection`` @>
    <@ InspectorTests.``RXSS on a form generated via Javascript`` @>
    <@ InspectorTests.``RXSS on a form with event that encode value`` @>
    <@ InspectorTests.``Blind SQL Injection on GET parameter`` @>
    <@ InspectorTests.``Check for missing HttpOnly cookie flag`` @>
    <@ InspectorTests.``Check for Password sent over HTTP`` @>
    <@ InspectorTests.``Check for Password without Autocomplete to OFF`` @>
    <@ InspectorTests.``Exctract information from a .git folder`` @>
    <@ InspectorTests.``Identify a Stored Croos Site Scripting`` @>
    <@ InspectorTests.``Identify a session token sent via GET`` @>
    <@ InspectorTests.``RXSS on data parameter after redirect`` @>
    <@ InspectorTests.``RXSS on query parameter in redirect page`` @>
    <@ InspectorTests.``Avoid to raise a FP when encounter an email pattern with invalid TLD`` @>
    <@ InspectorTests.``RXSS on a user registration form with password and repassword check`` @>
    <@ InspectorTests.``HTTP Basic bruteforced page`` @>
    
    // Composed tests
    <@ ComposedTests.``Identify an hidden directory and discover a know web application`` @>
    <@ ComposedTests.``Identify an hidden directory and discover a know web application and its plugin`` @>
    <@ ComposedTests.``Navigate to a link and discover an hidden resource`` @>
    <@ ComposedTests.``Discover an hidden resource and navigate to a link`` @>
    <@ ComposedTests.``Crawl to a link and discover a web application`` @>
    <@ ComposedTests.``Crawl to a link discover an hidden resource and fingerprint a web application`` @>
    <@ ComposedTests.``Discover an hidden resource, crawl a link and fingerprint a web application`` @>
    <@ ComposedTests.``Crawl to a link discover an hidden resource and found a vulnerability`` @> 
    <@ ComposedTests.``Discover an hidden resource, crawl a link and discover a vulnerability via link mutation`` @>
    <@ ComposedTests.``Crawl to a link discover an hidden resource and found a vulnerability via link mutation and fingerprint application`` @>    
    <@ ComposedTests.``Navigate by using a Journey Scan and identify an RXSS on the final page`` @>
    <@ ComposedTests.``Authenticate via Web form and found an RXSS in the authenticated part`` @>

    // Miscelaneous tests
    <@ MiscTests.``Ensure that a closed port doesn't return any vulnerabilities`` @>
    <@ MiscTests.``Ensure that a not existent domain doesn't return any vulnerabilities`` @>
    
]

let runTest (grovieraUri: Uri) (testExpr: Expr<Uri -> unit>) =    
    match testExpr with
    | Lambda (_, c) -> 
        match c with
        | Call (_,name,_) -> 
            Console.WriteLine()
            Console.WriteLine()
            let msg = String.Format("****** [{0}] {1} ******", name.DeclaringType.Name, name.Name)
            Console.WriteLine(String.replicate msg.Length "*")
            Console.WriteLine(msg)
            Console.WriteLine(String.replicate msg.Length "*")
            
            let testMethod = QuotationEvaluator.CompileUntyped(testExpr) :?> (Uri -> unit)
            testMethod(grovieraUri) 
        | _ -> failwith "Wrong expression"
    | _ -> failwith "Wrong expression"    
    
[<EntryPoint>]
let main argv = 
    let grovieraUri = Utility.runGrovieraServer()
    let run = runTest grovieraUri 
    allTests |> List.iter(run)
    Utility.shutDownServer()
    0
