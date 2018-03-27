module ComposedTests

    open System
    open System.Collections.Generic
    open System.Collections.Concurrent
    open System.Threading
    open System.IO
    open System.Net
    open ES.Taipan.Infrastructure.Network
    open ES.Taipan.Application
    open ES.Taipan.Fingerprinter
    open ES.Taipan.Discoverer
    open ES.Fslog
    open ES.Fslog.Loggers
    open Utility

    let inline private get(url: String) = (url, String.Empty)
    
    let private run(scanContext: ScanContext, testResult: TestResult) =
        Utility.simulatePhp()
        Utility.runScan(scanContext)
        |> Utility.verify testResult
        Utility.stopSimulatePhp()

    let ``Identify an hidden directory and discover a know web application``(grovieraUrl: Uri) =   
        let template = Templates.``Full template``()
        template.RunCrawler <- false
        template.RunVulnerabilityScanner <- false
        template.Name <- "Fingerprint and Discoverer template"

        createWebApplications()
        let resources = ["admin/"]
        createResources(resources)

        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/composed/test1/")),
                Template = template
            )

        // run the scan
        run(scanContext, TestResult.Create([], ["admin/"], [("Joomla", ["3.4.4"])], []))

    let ``Identify an hidden directory and discover a know web application and its plugin``(grovieraUrl: Uri) =   
        let template = Templates.``Full template``()
        template.RunCrawler <- false
        template.RunVulnerabilityScanner <- false
        template.Name <- "Fingerprint and Discoverer template"
        template.WebAppFingerprinterSettings.StopAtTheFirstApplicationIdentified <- false

        createWebApplications()
        let resources = ["admin/"]
        createResources(resources)

        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/composed/test2/")),
                Template = template
            )

        // run the scan
        run(scanContext, TestResult.Create([], ["admin/"], [("Joomla", ["3.4.4"]); ("Joomla plugin", ["0.1.0"])], []))

    let ``Navigate to a link and discover an hidden resource``(grovieraUrl: Uri) =   
        let template = Templates.``Full template``()
        template.RunVulnerabilityScanner <- false
        template.RunWebAppFingerprinter <- false
        template.Name <- "Crawler and Discoverer template"

        createWebApplications()
        let resources = ["admin/"]
        createResources(resources)

        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/composed/test3/")),
                Template = template
            )

        // run the scan
        run(scanContext, TestResult.Create([get("/composed/test3/link.html"); get("/composed/test3/hdndir/page.html")], ["admin/"], [], []))

    let ``Discover an hidden resource and navigate to a link``(grovieraUrl: Uri) =   
        let template = Templates.``Full template``()
        template.RunVulnerabilityScanner <- false
        template.RunWebAppFingerprinter <- false
        template.Name <- "Crawler and Discoverer template"

        let resources = ["admin/"]
        createResources(resources)

        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/composed/test4/")),
                Template = template
            )

        // run the scan
        run(scanContext, TestResult.Create([get("/composed/test4/admin/page.html")], resources, [], []))

    let ``Crawl to a link and discover a web application``(grovieraUrl: Uri) =   
        let template = Templates.``Full template``()
        template.RunVulnerabilityScanner <- false
        template.RunResourceDiscoverer <- false
        template.Name <- "Crawler and Fingerprinter template"
        template.WebAppFingerprinterSettings.StopAtTheFirstApplicationIdentified <- false

        createWebApplications()
        
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/composed/test5/")),
                Template = template
            )

        // run the scan
        run(scanContext, TestResult.Create(
            [get("/composed/test5/link.html"); get("/composed/test5/admin/page.html")], 
            [], 
            [("Joomla", ["3.4.4"]); ("Joomla plugin", ["0.1.0"])],
            [])
        )

    let ``Crawl to a link discover an hidden resource and fingerprint a web application``(grovieraUrl: Uri) =   
        let template = Templates.``Full template``()
        template.RunVulnerabilityScanner <- false
        template.Name <- "Crawler, Discoverer and Fingerprinter template"
        template.WebAppFingerprinterSettings.StopAtTheFirstApplicationIdentified <- false

        let resources = ["admin/"]
        createResources(resources)
        createWebApplications()
        
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/composed/test6/")),
                Template = template
            )

        // run the scan
        run(scanContext, TestResult.Create(
            [get("/composed/test6/link.html"); get("/composed/test6/foo/page.html")], 
            resources, 
            [("Joomla", ["3.4.4"]); ("Joomla plugin", ["0.1.0"])],
            [])
        )

    let ``Discover an hidden resource, crawl a link and fingerprint a web application``(grovieraUrl: Uri) =   
        let template = Templates.``Full template``()
        template.RunVulnerabilityScanner <- false
        template.Name <- "Crawler, Discoverer and Fingerprinter template"
        template.WebAppFingerprinterSettings.StopAtTheFirstApplicationIdentified <- false

        let resources = ["admin/"]
        createResources(resources)
        createWebApplications()
        
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/composed/test7/")),
                Template = template
            )

        // run the scan
        run(scanContext, TestResult.Create(
            [get("/composed/test7/admin/foo/page.html")], 
            resources, 
            [("Joomla", ["3.4.4"]); ("Joomla plugin", ["0.1.0"])],
            [])
        )

    let ``Crawl to a link discover an hidden resource and found a vulnerability``(grovieraUrl: Uri) =   
        let template = Templates.``Full template``()
        template.RunWebAppFingerprinter <- false
        template.Name <- "Crawler, Discoverer and Inspector template"

        let resources = ["admin/"]
        createResources(resources)
        createWebApplications()
        
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/composed/test8/")),
                Template = template
            )
        activatePlugin(scanContext, "FDE5F6AD-C468-4ED4-AD95-BFC393D7F1AC")

        // run the scan
        run(scanContext, TestResult.Create(
            [get("/composed/test8/link.html"); get("/composed/test8/foo/page.html")], 
            resources, 
            [],
            [("Directory Listing", "/composed/test8/foo/admin/")])
        )

    let ``Discover an hidden resource, crawl a link and discover a vulnerability via link mutation``(grovieraUrl: Uri) =   
        let template = Templates.``Full template``()
        template.RunWebAppFingerprinter <- false
        template.Name <- "Crawler, Discoverer and Inspector template"

        let resources = ["admin/"]
        createResources(resources)
        createWebApplications()
        
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/composed/test9/")),
                Template = template
            )
        activatePlugin(scanContext, "FDE5F6AD-C468-4ED4-AD95-BFC393D7F1AC")

        // run the scan
        run(scanContext, TestResult.Create(
            [get("/composed/test9/admin/foo/page.html"); get("/composed/test9/admin/foo/")], 
            resources, 
            [],
            [("Directory Listing", "/composed/test9/admin/foo/")])
        )

    let ``Crawl to a link discover an hidden resource and found a vulnerability via link mutation and fingerprint application``(grovieraUrl: Uri) =   
        let template = Templates.``Full template``()
        template.WebAppFingerprinterSettings.StopAtTheFirstApplicationIdentified <- false
        
        let resources = ["admin/"]
        createResources(resources)
        createWebApplications()
        
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/composed/test10/")),
                Template = template
            )
        activatePlugins(scanContext, ["FDE5F6AD-C468-4ED4-AD95-BFC393D7F1AC"; "C1B47585-5961-42B8-945E-1367B9CD251C"])

        // run the scan
        run(scanContext, TestResult.Create(
            [get("/composed/test10/foo/page.html"); get("/composed/test10/foo/admin/dirlisting/"); get("/composed/test10/foo/admin/dirlisting/page.html")], 
            resources, 
            [("Joomla", ["3.4.4"]); ("Joomla plugin", ["0.1.0"])],
            [("Directory Listing", "/composed/test10/foo/admin/dirlisting/"); ("Outdated Application", "/composed/test10/foo/admin/")])
        )

    let ``Navigate by using a Journey Scan and identify an RXSS on the final page``(grovieraUrl: Uri) =   
        let scanContext = 
            new ScanContext(
                 StartRequest = new WebRequest(new Uri(grovieraUrl, "/composed/test11/")),
                Template = Templates.``Full template``()
            )

        let template = scanContext.Template
        template.RunWebAppFingerprinter <- false
        template.RunResourceDiscoverer <- false
       
        activatePlugin(scanContext, "B2D7CBCF-B458-4C33-B3EE-44606E06E949")
        InspectorTests.writeXssData([
            ("<SCRIPT>alert('XSS');</SCRIPT>", ["<SCRIPT>alert('XSS');</SCRIPT>"])
        ])

        // define the Journey path, it will navigate until the page that display the page that we want to scan.
        // Intermediate navigation page will not be scanned!
        let journey = scanContext.Template.HttpRequestorSettings.Journey
        let path = journey.CreatePath()

        let transaction1 = path.CreateTransaction()
        transaction1.Index <- 0
        transaction1.TemplateRequest.Method <- "GET"
        transaction1.TemplateRequest.Uri <- (new Uri(grovieraUrl, "/composed/test11/start")).AbsoluteUri

        let transaction2 = path.CreateTransaction()
        transaction2.Index <- 1
        transaction2.AddParameter("code", "31337", "Data", true)
        transaction2.TemplateRequest.Method <- "POST"
        transaction2.TemplateRequest.Data <- "code=31337"
        transaction2.TemplateRequest.Uri <- (new Uri(grovieraUrl, "/composed/test11/validate")).AbsoluteUri
        
        // run the scan
        Utility.runScan(scanContext) 
        |> Utility.verifyInspector [
            ("Reflected Cross Site Scripting", "/composed/test11/final");
            ("Reflected Cross Site Scripting", "/composed/test11/validate")
        ]

    let ``Authenticate via Web form and found an RXSS in the authenticated part``(grovieraUrl: Uri) =   
        let scanContext = 
            new ScanContext(
                 StartRequest = new WebRequest(new Uri(grovieraUrl, "/composed/test12/")),
                Template = Templates.``Full template``()
            )

        let template = scanContext.Template
        template.RunWebAppFingerprinter <- false
        template.RunResourceDiscoverer <- false
       
        activatePlugin(scanContext, "B2D7CBCF-B458-4C33-B3EE-44606E06E949")
        InspectorTests.writeXssData([
            ("<SCRIPT>alert('XSS');</SCRIPT>", ["<SCRIPT>alert('XSS');</SCRIPT>"])
        ])

        // set authentication login/logout patterns
        let authInfo = new AuthenticationInfo(Enabled = true, Type = AuthenticationType.WebForm)
        authInfo.LoginPattern.Add("Logout")
        authInfo.LogoutPattern.Add("authenticate")
        scanContext.Template.HttpRequestorSettings.Authentication <- authInfo

        // define the authentication Journey path
        let journey = scanContext.Template.HttpRequestorSettings.Journey        
        let path = journey.CreatePath()
        
        let transaction1 = path.CreateTransaction()
        transaction1.Index <- 1
        transaction1.AddParameter("username", "admin", "Data", true)
        transaction1.AddParameter("password", "qwerty", "Data", true)
        transaction1.AddParameter("submit", String.Empty, "Data", true)
        transaction1.TemplateRequest.Method <- "POST"
        transaction1.TemplateRequest.Data <- "username=admin&password=qwerty&submit="
        transaction1.TemplateRequest.Uri <- (new Uri(grovieraUrl, "/composed/test12/login")).AbsoluteUri
        
        // run the scan
        Utility.runScan(scanContext) 
        |> Utility.verifyInspector [
            ("Reflected Cross Site Scripting", "/composed/test12/setname")
        ]