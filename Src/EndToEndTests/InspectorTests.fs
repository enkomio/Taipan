module InspectorTests

    open System
    open System.Collections.Generic
    open System.Collections.Concurrent
    open System.Threading
    open System.IO
    open System.Net
    open ES.Taipan.Infrastructure.Network
    open ES.Taipan.Application
    open ES.Taipan.Inspector
    open ES.Fslog
    open ES.Fslog.Loggers
        
    let ``Identify a directory listing``(grovieraUrl: Uri) =   
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/inspector/test1/dirlisting/")),
                Template = Templates.``Website inspector``()
            )
        activatePlugin(scanContext, "FDE5F6AD-C468-4ED4-AD95-BFC393D7F1AC")

        // run the scan
        Utility.runScan(scanContext) 
        |> Utility.verifyInspector [("Directory Listing", "/inspector/test1/dirlisting/")]

    let ``Identify an outdated web application``(grovieraUrl: Uri) =   
        createWebApplications()
        
        let template = Templates.``Full template``()
        template.RunResourceDiscoverer <- false

        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/inspector/test2/")),
                Template = template
            )
        activatePlugin(scanContext, "C1B47585-5961-42B8-945E-1367B9CD251C")

        // run the scan
        Utility.runScan(scanContext) 
        |> Utility.verifyInspector [("Outdated Application", "/inspector/test2/")]

    let ``Identify internal IP info leak``(grovieraUrl: Uri) =   
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/inspector/test3/")),
                Template = Templates.``Website inspector``()
            )
        activatePlugin(scanContext, "AFA1E309-2AC4-4504-86BD-35216950CEFA")

        // run the scan
        Utility.runScan(scanContext) 
        |> Utility.verifyInspector [("Information Leakage", "/inspector/test3/")]

    let ``Identify info leak due to an email in an HTML content``(grovieraUrl: Uri) =   
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/inspector/test4/")),
                Template = Templates.``Website inspector``()
            )
        activatePlugin(scanContext, "AFA1E309-2AC4-4504-86BD-35216950CEFA")

        // run the scan
        Utility.runScan(scanContext) 
        |> Utility.verifyInspector [("Information Leakage", "/inspector/test4/")]

    let ``Identify info leak due to an hyperlink in an HTML content``(grovieraUrl: Uri) =   
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/inspector/test5/")),
                Template = Templates.``Full template``()
            )
        scanContext.Template.RunResourceDiscoverer <- false
        scanContext.Template.RunWebAppFingerprinter <- false
        activatePlugin(scanContext, "AFA1E309-2AC4-4504-86BD-35216950CEFA")

        // run the scan
        Utility.runScan(scanContext) 
        |> Utility.verifyInspector [("Information Leakage", "/inspector/test5/")]

    let ``Identify missing security headers``(grovieraUrl: Uri) =   
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/inspector/test6/")),
                Template = Templates.``Full template``()
            )
        scanContext.Template.RunResourceDiscoverer <- false
        scanContext.Template.RunWebAppFingerprinter <- false

        // run the scan
        Utility.runScan(scanContext) 
        |> Utility.verifyInspector [
            ("Missing Strict-Transport-Security", "/inspector/test6/")
            ("Missing Content-Security-Policy", "/inspector/test6/")
            ("Missing Public-Key-Pins", "/inspector/test6/")
            ("Missing X-Frame-Options", "/inspector/test6/")
            ("Missing X-XSS-Protection", "/inspector/test6/")
            ("Missing X-Content-Type-Options", "/inspector/test6/")
        ]

    let ``Identify Strinc Transport Layer with a too low maxage value``(grovieraUrl: Uri) =   
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/inspector/test7/")),
                Template = Templates.``Full template``()
            )
        scanContext.Template.RunResourceDiscoverer <- false
        scanContext.Template.RunWebAppFingerprinter <- false

        // run the scan
        Utility.runScan(scanContext) 
        |> Utility.verifyInspector [
            ("Missing Strict-Transport-Security", "/inspector/test7/")
            ("Missing Content-Security-Policy", "/inspector/test7/")
            ("Missing Public-Key-Pins", "/inspector/test7/")
            ("Missing X-Frame-Options", "/inspector/test7/")
            ("Missing X-XSS-Protection", "/inspector/test7/")
            ("Missing X-Content-Type-Options", "/inspector/test7/")
        ]

    let ``Identify X-XSS-Protection but disabled``(grovieraUrl: Uri) =   
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/inspector/test8/")),
                Template = Templates.``Full template``()
            )
        scanContext.Template.RunResourceDiscoverer <- false
        scanContext.Template.RunWebAppFingerprinter <- false

        // run the scan
        Utility.runScan(scanContext) 
        |> Utility.verifyInspector [
            ("Missing Strict-Transport-Security", "/inspector/test8/")
            ("Missing Content-Security-Policy", "/inspector/test8/")
            ("Missing Public-Key-Pins", "/inspector/test8/")
            ("Missing X-Frame-Options", "/inspector/test8/")
            ("Missing X-XSS-Protection", "/inspector/test8/")
            ("Missing X-Content-Type-Options", "/inspector/test8/")
        ]

    let ``X-XSS-Protection, Public-Key-Pins and Strict-Transport-Security are correctly setted``(grovieraUrl: Uri) =   
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/inspector/test9/")),
                Template = Templates.``Full template``()
            )
        scanContext.Template.RunResourceDiscoverer <- false
        scanContext.Template.RunWebAppFingerprinter <- false

        // run the scan
        Utility.runScan(scanContext) 
        |> Utility.verifyInspector [            
            ("Missing Content-Security-Policy", "/inspector/test9/")            
            ("Missing X-Frame-Options", "/inspector/test9/")
            ("Missing X-Content-Type-Options", "/inspector/test9/")
        ]

    let ``Identify a web application with know vulnerabilities``(grovieraUrl: Uri) =   
        createWebApplications()
        createWebApplicationVulnerabilities()
        
        let template = Templates.``Full template``()
        template.RunResourceDiscoverer <- false

        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/inspector/test10/")),
                Template = template
            )
        activatePlugin(scanContext, "864BA3EF-E9E2-4B18-AE7F-4530CEBCCBF6")

        // run the scan
        Utility.runScan(scanContext) 
        |> Utility.verifyInspector [("Vulnerable Web Application", "/inspector/test10/")]

    let ``Ensure that the version range in the vulnerability description is satisfied``(grovieraUrl: Uri) =   
        createWebApplications()
        createWebApplicationVulnerabilities()
        
        let template = Templates.``Full template``()
        template.RunResourceDiscoverer <- false

        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/inspector/test11/")),
                Template = template
            )
        activatePlugin(scanContext, "864BA3EF-E9E2-4B18-AE7F-4530CEBCCBF6")

        // run the scan
        Utility.runScan(scanContext) 
        |> Utility.verifyInspector []


    let private errorTests(grovieraUrl: Uri, testPath: String) =
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, testPath)),
                Template = Templates.``Website inspector``()
            )
        activatePlugin(scanContext, "73EF90A2-C2A4-44AE-82DE-35349AEDFFB3")

        // run the scan
        Utility.runScan(scanContext) 
        |> Utility.verifyInspector [("Error Messages", testPath)]

    let ``Identify Synfony error``(grovieraUrl: Uri) =  errorTests(grovieraUrl, "/inspector/test12/")
    let ``Identify Synfony error second variant``(grovieraUrl: Uri) =  errorTests(grovieraUrl, "/inspector/test13/")
    let ``PHP fopen error``(grovieraUrl: Uri) =  errorTests(grovieraUrl, "/inspector/test14/")
    let ``Ruby On Rails error``(grovieraUrl: Uri) =  errorTests(grovieraUrl, "/inspector/test15/")
    let ``ASP.NET error``(grovieraUrl: Uri) =  errorTests(grovieraUrl, "/inspector/test16/")
    let ``500 Internal server error``(grovieraUrl: Uri) =  errorTests(grovieraUrl, "/inspector/test17/")

    let writeXssData(data: (String * String list) list) =
        let addOn = new ES.Taipan.Inspector.AddOns.ReflectedCrossSiteScripting.ReflectedCrossSiteScriptingAddOn()
        let context = new ES.Taipan.Inspector.Context(ES.Taipan.Inspector.FilesystemAddOnStorage(addOn), fun _ -> ())
        context.AddOnStorage.SaveProperty<(String * String list) list>("Payloads", data)

    let writeSqliData(data: (String * String list) list) =
        let addOn = new ES.Taipan.Inspector.AddOns.SqlInjection.SqlInjectionAddOn()
        let context = new ES.Taipan.Inspector.Context(ES.Taipan.Inspector.FilesystemAddOnStorage(addOn), fun _ -> ())
        context.AddOnStorage.SaveProperty<(String * String list) list>("Errors", data)

    let ``RXSS in query parameter``(grovieraUrl: Uri) =
        let scanContext = 
            new ScanContext(
                 StartRequest = new WebRequest(new Uri(grovieraUrl, "/inspector/test18/vuln.php?a=b")),
                Template = Templates.``Website inspector``()
            )
        activatePlugin(scanContext, "B2D7CBCF-B458-4C33-B3EE-44606E06E949")
        writeXssData([
            ("<SCRIPT>alert('XSS');</SCRIPT>", ["<SCRIPT>alert('XSS');</SCRIPT>"; "<IMG SRC=\"javascript:alert('XSS');\">"])
        ])

        // run the scan
        Utility.runScan(scanContext) 
        |> Utility.verifyInspector [("Reflected Cross Site Scripting", "/inspector/test18/vuln.php")]

    let ``RXSS on data parameter``(grovieraUrl: Uri) =
        let scanContext = 
            new ScanContext(
                 StartRequest = new WebRequest(new Uri(grovieraUrl, "/inspector/test19/")),
                Template = Templates.``Website inspector``()
            )
        
        activatePlugin(scanContext, "B2D7CBCF-B458-4C33-B3EE-44606E06E949")
        writeXssData([
            ("<SCRIPT>alert('XSS');</SCRIPT>", ["<SCRIPT>alert('XSS');</SCRIPT>"; "<IMG SRC=\"javascript:alert('XSS');\">"])
        ])

        // run the scan
        Utility.runScan(scanContext) 
        |> Utility.verifyInspector [("Reflected Cross Site Scripting", "/inspector/test19/vuln.php")]

    let ``RXSS in User-Agent``(grovieraUrl: Uri) =
        let scanContext = 
            new ScanContext(
                 StartRequest = new WebRequest(new Uri(grovieraUrl, "/inspector/test20/vuln.php")),
                Template = Templates.``Website inspector``()
            )
        scanContext.StartRequest.HttpRequest.Headers.Add(new HttpHeader(Name = "User-Agent", Value = "foo"))

        activatePlugin(scanContext, "B2D7CBCF-B458-4C33-B3EE-44606E06E949")
        writeXssData([
            ("<SCRIPT>alert('XSS');</SCRIPT>", ["<SCRIPT>alert('XSS');</SCRIPT>"; "<IMG SRC=\"javascript:alert('XSS');\">"])
        ])

        // run the scan
        Utility.runScan(scanContext) 
        |> Utility.verifyInspector [("Reflected Cross Site Scripting", "/inspector/test20/vuln.php")]

    let ``Identify info leak in .DS_Store file``(grovieraUrl: Uri) =   
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/inspector/test21/.DS_Store")),
                Template = Templates.``Website inspector``()
            )
        activatePlugin(scanContext, "AFA1E309-2AC4-4504-86BD-35216950CEFA")

        // run the scan
        Utility.runScan(scanContext) 
        |> Utility.verifyInspector [("Information Leakage", "/inspector/test21/.DS_Store")]

    let ``RXSS in filename parameter``(grovieraUrl: Uri) =
        let scanContext = 
            new ScanContext(
                 StartRequest = new WebRequest(new Uri(grovieraUrl, "/inspector/test22/")),
                Template = Templates.``Website inspector``()
            )

        // enable crawling to compose the url
        scanContext.Template.RunCrawler <- true
        scanContext.Template.CrawlerSettings.Scope <- ES.Taipan.Crawler.NavigationScope.EnteredPathAndBelow

        activatePlugin(scanContext, "B2D7CBCF-B458-4C33-B3EE-44606E06E949")
        writeXssData([
            ("<SCRIPT>alert('XSS');</SCRIPT>", ["<SCRIPT>alert('XSS');</SCRIPT>"; "<IMG SRC=\"javascript:alert('XSS');\">"])
        ])

        // run the scan
        Utility.runScan(scanContext) 
        |> Utility.verifyInspector [("Reflected Cross Site Scripting", "/inspector/test22/upload.php")]

    let ``Sqli error based in name parameter``(grovieraUrl: Uri) =
        let scanContext = 
            new ScanContext(
                 StartRequest = new WebRequest(new Uri(grovieraUrl, "/inspector/test23/")),
                Template = Templates.``Website inspector``()
            )

        // enable crawling to compose the url
        scanContext.Template.RunCrawler <- true
        scanContext.Template.CrawlerSettings.Scope <- ES.Taipan.Crawler.NavigationScope.EnteredPathAndBelow

        activatePlugin(scanContext, "7B55A85D-3CA6-492D-8D07-7B35A12CCEF3")
        writeSqliData(sqliDatabaseErrors)

        // run the scan
        Utility.runScan(scanContext) 
        |> Utility.verifyInspector [("SQL Injection Error Based", "/inspector/test23/show.php")]

    let ``Sqli error based in name parameter with AntiCSRF protection``(grovieraUrl: Uri) =
        let scanContext = 
            new ScanContext(
                 StartRequest = new WebRequest(new Uri(grovieraUrl, "/inspector/test24/")),
                Template = Templates.``Website inspector``()
            )

        // enable crawling to compose the url
        scanContext.Template.RunCrawler <- true
        scanContext.Template.CrawlerSettings.Scope <- ES.Taipan.Crawler.NavigationScope.EnteredPathAndBelow

        activatePlugin(scanContext, "7B55A85D-3CA6-492D-8D07-7B35A12CCEF3")
        writeSqliData(sqliDatabaseErrors)

        // run the scan
        Utility.runScan(scanContext) 
        |> Utility.verifyInspector [("SQL Injection Error Based", "/inspector/test24/show.php")]

    let ``RXSS on data parameter and AntiCSRF protection``(grovieraUrl: Uri) =
        let scanContext = 
            new ScanContext(
                 StartRequest = new WebRequest(new Uri(grovieraUrl, "/inspector/test25/")),
                Template = Templates.``Website inspector``()
            )

        // enable crawling to compose the url
        scanContext.Template.RunCrawler <- true
        scanContext.Template.CrawlerSettings.Scope <- ES.Taipan.Crawler.NavigationScope.EnteredPathAndBelow

        activatePlugin(scanContext, "B2D7CBCF-B458-4C33-B3EE-44606E06E949")
        writeXssData([
            ("<SCRIPT>alert('XSS');</SCRIPT>", ["<SCRIPT>alert('XSS');</SCRIPT>"; "<IMG SRC=\"javascript:alert('XSS');\">"])
        ])

        // run the scan
        Utility.runScan(scanContext) 
        |> Utility.verifyInspector [
            ("Reflected Cross Site Scripting", "/inspector/test25/vuln.php") // username
            ("Reflected Cross Site Scripting", "/inspector/test25/vuln.php") // password
        ]

    let ``RXSS on a form generated via Javascript``(grovieraUrl: Uri) =
        let scanContext = 
            new ScanContext(
                 StartRequest = new WebRequest(new Uri(grovieraUrl, "/inspector/test26/")),
                Template = Templates.``Website inspector``()
            )

        // enable crawling to compose the url
        scanContext.Template.RunCrawler <- true
        scanContext.Template.CrawlerSettings.Scope <- ES.Taipan.Crawler.NavigationScope.EnteredPathAndBelow

        // enable Javascript engine
        scanContext.Template.CrawlerSettings.ActivateAllAddOns <- true
        scanContext.Template.HttpRequestorSettings.UseJavascriptEngineForRequest <- true

        activatePlugin(scanContext, "B2D7CBCF-B458-4C33-B3EE-44606E06E949")
        writeXssData([
            ("<SCRIPT>alert('XSS');</SCRIPT>", ["<SCRIPT>alert('XSS');</SCRIPT>"; "<IMG SRC=\"javascript:alert('XSS');\">"])
        ])

        // run the scan
        Utility.runScan(scanContext) 
        |> Utility.verifyInspector [
            ("Reflected Cross Site Scripting", "/inspector/test26/submit.php")
        ]

    let ``RXSS on a form with event that encode value``(grovieraUrl: Uri) =
        let scanContext = 
            new ScanContext(
                 StartRequest = new WebRequest(new Uri(grovieraUrl, "/inspector/test27/")),
                Template = Templates.``Website inspector``()
            )

        // enable crawling to compose the url
        scanContext.Template.RunCrawler <- true
        scanContext.Template.CrawlerSettings.Scope <- ES.Taipan.Crawler.NavigationScope.EnteredPathAndBelow
        scanContext.Template.CrawlerSettings.MutateWebLinks <- false

        // enable Javascript engine
        scanContext.Template.CrawlerSettings.ActivateAllAddOns <- true
        scanContext.Template.HttpRequestorSettings.UseJavascriptEngineForRequest <- true

        activatePlugin(scanContext, "B2D7CBCF-B458-4C33-B3EE-44606E06E949")
        writeXssData([
            ("<SCRIPT>alert('XSS');</SCRIPT>", ["<SCRIPT>alert('XSS');</SCRIPT>"; "<IMG SRC=\"javascript:alert('XSS');\">"])
        ])

        // run the scan
        Utility.runScan(scanContext) 
        |> Utility.verifyInspector [
            ("Reflected Cross Site Scripting", "/inspector/test27/submit.php")
        ]

    let ``Blind SQL Injection on GET parameter``(grovieraUrl: Uri) =
        let scanContext = 
            new ScanContext(
                 StartRequest = new WebRequest(new Uri(grovieraUrl, "/inspector/test28/")),
                Template = Templates.``Website inspector``()
            )

        // enable crawling to compose the url
        scanContext.Template.RunCrawler <- true
        scanContext.Template.CrawlerSettings.Scope <- ES.Taipan.Crawler.NavigationScope.EnteredPathAndBelow
        scanContext.Template.CrawlerSettings.MutateWebLinks <- false

        // enable Javascript engine
        scanContext.Template.CrawlerSettings.ActivateAllAddOns <- true

        activatePlugin(scanContext, "1DF114E2-FE1E-44CF-8CB2-612B7CFF62B1")

        // enable crawling to compose the url
        scanContext.Template.RunCrawler <- true
        scanContext.Template.CrawlerSettings.Scope <- ES.Taipan.Crawler.NavigationScope.EnteredPathAndBelow

        // run the scan
        Utility.runScan(scanContext) 
        |> Utility.verifyInspector [("Blind SQL Injection", "/inspector/test28/show.php")]


    let ``Check for missing HttpOnly cookie flag``(grovieraUrl: Uri) =
        let scanContext = 
            new ScanContext(
                 StartRequest = new WebRequest(new Uri(grovieraUrl, "/inspector/test29/")),
                Template = Templates.``Website inspector``()
            )

        // enable crawling to compose the url
        scanContext.Template.RunCrawler <- true
        scanContext.Template.CrawlerSettings.Scope <- ES.Taipan.Crawler.NavigationScope.EnteredPathAndBelow
        scanContext.Template.CrawlerSettings.MutateWebLinks <- false

        // enable Javascript engine
        scanContext.Template.CrawlerSettings.ActivateAllAddOns <- true

        activatePlugin(scanContext, "A719DE80-32BF-4E53-BCB2-D138BF953853")
        
        // run the scan
        Utility.runScan(scanContext) 
        |> Utility.verifyInspector [("Cookie Not Marked As HttpOnly", "/inspector/test29/")]

    let ``Check for Password sent over HTTP``(grovieraUrl: Uri) =
        let scanContext = 
            new ScanContext(
                 StartRequest = new WebRequest(new Uri(grovieraUrl, "/inspector/test30/")),
                Template = Templates.``Website inspector``()
            )

        // enable crawling to compose the url
        scanContext.Template.RunCrawler <- true
        scanContext.Template.CrawlerSettings.Scope <- ES.Taipan.Crawler.NavigationScope.EnteredPathAndBelow
        scanContext.Template.CrawlerSettings.MutateWebLinks <- false

        // enable Javascript engine
        scanContext.Template.CrawlerSettings.ActivateAllAddOns <- true

        activatePlugin(scanContext, "5B4B319D-E0D8-4FBF-83B3-C8E71BA65D35")
        
        // run the scan
        Utility.runScan(scanContext) 
        |> Utility.verifyInspector [("Sensitive Information Sent Via Unencrypted Channels", "/inspector/test30/")]

    let ``Check for Password without Autocomplete to OFF``(grovieraUrl: Uri) =
        let scanContext = 
            new ScanContext(
                 StartRequest = new WebRequest(new Uri(grovieraUrl, "/inspector/test31/")),
                Template = Templates.``Website inspector``()
            )

        // enable crawling to compose the url
        scanContext.Template.RunCrawler <- true
        scanContext.Template.CrawlerSettings.Scope <- ES.Taipan.Crawler.NavigationScope.EnteredPathAndBelow
        scanContext.Template.CrawlerSettings.MutateWebLinks <- false

        // enable Javascript engine
        scanContext.Template.CrawlerSettings.ActivateAllAddOns <- true

        activatePlugin(scanContext, "85EF16CC-3682-4CDC-A2F5-A5FD889474FF")
        
        // run the scan
        Utility.runScan(scanContext) 
        |> Utility.verifyInspector [("Password Field With Autocomplete Enabled", "/inspector/test31/")]

    let ``Exctract information from a .git folder``(grovieraUrl: Uri) =
        let scanContext = 
            new ScanContext(
                 StartRequest = new WebRequest(new Uri(grovieraUrl, "/inspector/test32/")),
                Template = Templates.``Website inspector``()
            )

        // enable crawling to compose the url
        scanContext.Template.RunCrawler <- true
        scanContext.Template.CrawlerSettings.Scope <- ES.Taipan.Crawler.NavigationScope.EnteredPathAndBelow
        scanContext.Template.CrawlerSettings.MutateWebLinks <- false
        
        activatePlugin(scanContext, "46DAC261-3B13-4123-9AAF-22DFAF9B5E19")
        
        // run the scan
        Utility.runScan(scanContext) 
        |> Utility.verifyInspector [("GIT Information and Source Code Disclosure", "/inspector/test32/.git/")]

    let ``Identify a Stored Croos Site Scripting``(grovieraUrl: Uri) =
        let scanContext = 
            new ScanContext(
                 StartRequest = new WebRequest(new Uri(grovieraUrl, "/inspector/test33/")),
                Template = Templates.``Website inspector``()
            )

        // enable re-crawling
        scanContext.Template.CrawlerSettings.ReCrawlPages <- true
                
        activatePlugin(scanContext, "5B9F1F2F-4A91-48A9-8615-2EA25E73E5B3")
        
        // run the scan
        Utility.runScan(scanContext) 
        |> Utility.verifyInspector [("Stored Cross Site Scripting", "/inspector/test33/")]