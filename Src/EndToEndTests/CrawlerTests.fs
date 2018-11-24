module CrawlerTests

    open System
    open System.Collections.Generic
    open System.Collections.Concurrent
    open System.Threading
    open System.IO
    open System.Net
    open ES.Taipan.Infrastructure.Network
    open ES.Taipan.Application
    open ES.Taipan.Crawler
    open ES.Fslog
    open ES.Fslog.Loggers

    let inline private get(url: String) = (url, String.Empty)
    
    let ``Crawl a simple web link``(grovieraUrl: Uri) =   
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/crawler/test1/")),
                Template = Templates.``Website crawling``()
            )

        // run the scan
        Utility.runScan(scanContext)
        |> Utility.verifyCrawler [get("/crawler/test1/simplelink.html")]


    let ``Ensure that the scope is correctly considered``(grovieraUrl: Uri) =   
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/crawler/test2/")),
                Template = Templates.``Website crawling``()
            )
        scanContext.Template.CrawlerSettings.Scope <- NavigationScope.EnteredPathAndBelow

        // run the scan
        Utility.runScan(scanContext)
        |> Utility.verifyCrawler [get("/crawler/test2/dir/index.html")]

    let ``Ensure that the referer is correctly setted``(grovieraUrl: Uri) =   
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/crawler/test3/")),
                Template = Templates.``Website crawling``()
            )

        // run the scan
        Utility.runScan(scanContext)
        |> Utility.verifyCrawlerWithCallback [get("/crawler/test3/page.htm")] (fun (webLink, _)-> 
            let referer = new Uri(HttpUtility.getHeader("Referer", webLink.Request.HttpRequest.Headers).Value)
            referer.AbsolutePath.Equals("/crawler/test3/", StringComparison.Ordinal))

    let ``Ensure that the forbidden extension are not crawled``(grovieraUrl: Uri) =   
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/crawler/test4/")),
                Template = Templates.``Website crawling``()
            )

        // run the scan
        Utility.runScan(scanContext)
        |> Utility.verifyCrawler []

    let ``Ensure that the forbidden content-type are not crawled``(grovieraUrl: Uri) =   
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/crawler/test5/")),
                Template = Templates.``Website crawling``()
            )
        scanContext.Template.CrawlerSettings.ContentTypeToFilter.Add("text/html")

        // run the scan
        Utility.runScan(scanContext)
        |> Utility.verifyCrawler []

    let ``Ensure that HTTP redirect are crawled``(grovieraUrl: Uri) =   
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/crawler/test6/")),
                Template = Templates.``Website crawling``()
            )

        // run the scan
        Utility.runScan(scanContext)
        |> Utility.verifyCrawler [get("/crawler/test6/redirect.html"); get("/crawler/test6/page.html")]

    let ``Ensure that HTML meta redirect are crawled``(grovieraUrl: Uri) =   
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/crawler/test7/")),
                Template = Templates.``Website crawling``()
            )

        // run the scan
        Utility.runScan(scanContext)
        |> Utility.verifyCrawler [get("/crawler/test7/redirect.html"); get("/crawler/test7/page.html")]

    let ``Ensure that POST requests are crawled``(grovieraUrl: Uri) =   
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/crawler/test8/")),
                Template = Templates.``Website crawling``()
            )

        // run the scan
        Utility.runScan(scanContext)
        |> Utility.verifyCrawler [get("/crawler/test8/form.html"); ("/crawler/test8/form.php", "name")]

    let ``Ensure that POST requests with values are crawled``(grovieraUrl: Uri) =   
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/crawler/test9/")),
                Template = Templates.``Website crawling``()
            )

        // run the scan
        Utility.runScan(scanContext)
        |> Utility.verifyCrawler [get("/crawler/test9/form.html"); ("/crawler/test9/form.php", "username=foo&password=bar&invia=login")]

    let ``Ensure that GET forms with values are crawled``(grovieraUrl: Uri) =   
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/crawler/test10/")),
                Template = Templates.``Website crawling``()
            )
        scanContext.Template.CrawlerSettings.MutateWebLinks <- false

        // run the scan
        Utility.runScan(scanContext)
        |> Utility.verifyCrawler [get("/crawler/test10/form.html"); get("/crawler/test10/form.php?username=foo&password=bar&invia=login")]

    let ``Find web link via query mutation``(grovieraUrl: Uri) =   
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/crawler/test11/")),
                Template = Templates.``Website crawling``()
            )

        // enable mutation
        scanContext.Template.CrawlerSettings.MutateWebLinks <- true

        // run the scan
        Utility.runScan(scanContext)
        |> Utility.verifyCrawler [get("/crawler/test11/page.php"); get("/crawler/test11/page.php?foo=bar")]

    let ``Find web link via mutation from GET to POST``(grovieraUrl: Uri) =   
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/crawler/test12/")),
                Template = Templates.``Website crawling``()
            )

        // enable mutation
        scanContext.Template.CrawlerSettings.MutateWebLinks <- true

        // run the scan
        Utility.runScan(scanContext)
        |> Utility.verifyCrawlerWithCallback [get("/crawler/test12/page.php")] (fun (wl, _) -> wl.Request.HttpRequest.Method = HttpMethods.Post)

    let ``Test for MaxNumOfPagesToCrawl``(grovieraUrl: Uri) =   
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/crawler/test13/")),
                Template = Templates.``Website crawling``()
            )
        
        scanContext.Template.CrawlerSettings.MutateWebLinks <- false
        scanContext.Template.CrawlerSettings.MaxNumberOfPagesToCrawl <- 7
        scanContext.Template.CrawlerSettings.HasLinkNavigationLimit <- true

        // run the scan
        Utility.runScan(scanContext)
        |> Utility.verifyCrawler [
            get("/crawler/test13/loop1.php")
            get("/crawler/test13/loop2.php")
            get("/crawler/test13/loop3.php")
            get("/crawler/test13/loop4.php")
            get("/crawler/test13/loop5.php")
        ]

    let ``Find web link without extension``(grovieraUrl: Uri) =   
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/crawler/test14/")),
                Template = Templates.``Website crawling``()
            )
        scanContext.Template.CrawlerSettings.CrawlPageWithoutExtension <- true

        // run the scan
        Utility.runScan(scanContext)
        |> Utility.verifyCrawler [get("/crawler/test14/page")]

    let ``Ensure that encoded parameters are correctly managed``(grovieraUrl: Uri) =   
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/crawler/test15/")),
                Template = Templates.``Website crawling``()
            )
        scanContext.Template.CrawlerSettings.CrawlPageWithoutExtension <- true

        // run the scan
        Utility.runScan(scanContext)
        |> Utility.verifyCrawler [get("/crawler/test15/page.html"); ("/crawler/test15/form.php?value=404%3bhttp%3a%2f%2fwww.example.it%3a80%2fit%2f&aaa=bbb", "__VIEWSTATE=%2FwEPDwULLTEzMTkwODEyMzEPZBYCZg9kFgQCAQ9kFgICGg9kFg%26cc%3Ddd%3C45")]

    let ``Identify a link in a comment via mutation``(grovieraUrl: Uri) =   
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/crawler/test16/")),
                Template = Templates.``Website crawling``()
            )

        scanContext.Template.CrawlerSettings.CrawlPageWithoutExtension <- true
        scanContext.Template.CrawlerSettings.MutateWebLinks <- true

        // run the scan
        Utility.runScan(scanContext)
        |> Utility.verifyCrawler [get("/crawler/test16/hidden.html")]

    let ``Test for MaxNumOfRequestsToTheSamePage``(grovieraUrl: Uri) =   
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/crawler/test17/")),
                Template = Templates.``Website crawling``()
            )
        scanContext.Template.CrawlerSettings.MaxNumberOfPagesToCrawl <- 100
        scanContext.Template.CrawlerSettings.MaxNumOfRequestsToTheSamePage <- 6
        scanContext.Template.CrawlerSettings.HasLinkNavigationLimit <- true
        scanContext.Template.CrawlerSettings.MutateWebLinks <- false

        // run the scan
        Utility.runScan(scanContext)
        |> Utility.verifyCrawler [
            get("/crawler/test17/loop.php?param=0")
            get("/crawler/test17/loop.php?param=1")
            get("/crawler/test17/loop.php?param=2")
            get("/crawler/test17/loop.php?param=3")
            get("/crawler/test17/loop.php?param=4")
            get("/crawler/test17/loop.php?param=5")
        ]

    let ``Ensure that POST requests with file input are crawled``(grovieraUrl: Uri) =   
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/crawler/test18/")),
                Template = Templates.``Website crawling``()
            )

        // run the scan
        Utility.runScan(scanContext)
        |> Utility.verifyCrawler [("/crawler/test18/upload.php", String.Empty)]

    let ``Ensure that session is honored after login``(grovieraUrl: Uri) =   
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/crawler/test19/")),
                Template = Templates.``Website crawling``()
            )
        scanContext.Template.CrawlerSettings.DefaultParameters.Add({Name = "user"; Value = "toor"; Path = "/crawler/test19/login"})
        scanContext.Template.CrawlerSettings.DefaultParameters.Add({Name = "password"; Value = "root"; Path = "/crawler/test19/login"})

        // run the scan
        Utility.runScan(scanContext)
        |> Utility.verifyCrawler [("/crawler/test19/dashboard", String.Empty)]

    let ``Parse a link created via Javascript``(grovieraUrl: Uri) =   
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/crawler/test20/")),
                Template = Templates.``Website crawling``()
            )

        // add Javascript AddOn
        scanContext.Template.CrawlerSettings.AddOnIdsToActivate.Add(ES.Taipan.Crawler.WebScrapers.JavascriptScraper.AddOnId)

        // run the scan
        Utility.runScan(scanContext)
        |> Utility.verifyCrawler [("/crawler/test20/a.php", String.Empty)]

    let ``Parse a form created via Javascript with pre-processing``(grovieraUrl: Uri) =   
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/crawler/test21/")),
                Template = Templates.``Website crawling``()
            )
        scanContext.Template.CrawlerSettings.MutateWebLinks <- false

        // add Javascript AddOn
        scanContext.Template.CrawlerSettings.AddOnIdsToActivate.Add(ES.Taipan.Crawler.WebScrapers.JavascriptScraper.AddOnId)
        scanContext.Template.HttpRequestorSettings.UseJavascriptEngineForRequest <- true

        // run the scan
        Utility.runScan(scanContext)
        |> Utility.verifyCrawler [("/crawler/test21/dashboard.php", String.Empty)]

    let ``Crawl a Basic HTTP Authenticated page``(grovieraUrl: Uri) =   
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/crawler/test22/")),
                Template = Templates.``Website crawling``()
            )

        // set authentication
        scanContext.Template.HttpRequestorSettings.Authentication <- 
            new AuthenticationInfo(
                Enabled = true,
                Type = AuthenticationType.HttpBasic,
                Username = "admin",
                Password = "admin"
            )
    
        // run the scan
        Utility.runScan(scanContext)
        |> Utility.verifyCrawler [get("/crawler/test22/authok")]

    let ``Crawl a Digest HTTP Authenticated page``(grovieraUrl: Uri) =   
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/crawler/test23/")),
                Template = Templates.``Website crawling``()
            )

        // set authentication
        scanContext.Template.HttpRequestorSettings.Authentication <- 
            new AuthenticationInfo(
                Enabled = true,
                Type = AuthenticationType.HttpDigest,
                Username = "admin",
                Password = "qwerty"
            )

        // run the scan
        Utility.runScan(scanContext)
        |> Utility.verifyCrawler [get("/crawler/test23/authok")]

    let ``Crawl a Bearer HTTP Authenticated page``(grovieraUrl: Uri) =   
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/crawler/test24/")),
                Template = Templates.``Website crawling``()
            )

        // set authentication
        scanContext.Template.HttpRequestorSettings.Authentication <- 
            new AuthenticationInfo(
                Enabled = true, 
                Type = AuthenticationType.Bearer,
                Token = "1234567890abcdefgh"
            )

        // run the scan
        Utility.runScan(scanContext)
        |> Utility.verifyCrawler [get("/crawler/test24/secretlink_post_auth")]

    let ``Ensure that a link on another port is not followed``(grovieraUrl: Uri) =
        // run anothe instance on the alternative port
        Utility.runGrovieraServerOnPort(grovieraUrl.Port + 1) |> ignore

        // now run the real instance
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/crawler/test25/")),
                Template = Templates.``Website crawling``()
            )

        // enable redirect
        scanContext.Template.HttpRequestorSettings.AllowAutoRedirect <- true
        
        // run the scan
        try
            Utility.runScan(scanContext)
            |> Utility.verifyCrawler [get("/crawler/test25/nooo")]
            raise (new ApplicationException())
        with e -> 
            if not(e.Message.ToLower().Contains("some page wasn't found"))
            then reraise()

    let ``Crawl an Authenticated page via pre-authenticated cookie``(grovieraUrl: Uri) =   
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/crawler/test26/")),
                Template = Templates.``Website crawling``()
            )

        // set authenticated cookie
        scanContext.Template.HttpRequestorSettings.AdditionalCookies.Add("authcookie", "123456qwerty")

        // run the scan
        Utility.runScan(scanContext)
        |> Utility.verifyCrawler [("/crawler/test26/dashboard", "Welcome authenticated user enjoy your awesome Dashboard")]