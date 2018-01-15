module DiscovererTests

    open System
    open System.Collections.Generic
    open System.Collections.Concurrent
    open System.Threading
    open System.IO
    open System.Net
    open ES.Taipan.Infrastructure.Network
    open ES.Taipan.Application
    open ES.Taipan.Discoverer
    open ES.Fslog
    open ES.Fslog.Loggers
    
    let ``Non recursive discoverer of hidden resources``(grovieraUrl: Uri) =   
        let resources = ["admin/"; "test.php"]
        createResources(resources)
        let template = Templates.``Website discovery``()
        template.ResourceDiscovererSettings.BeRecursive <- false
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/discoverer/test1/")),
                Template = template
            )
                                    
        // run the scan
        Utility.runScan(scanContext)
        |> Utility.verifyDiscoverer resources

    let ``Recursive discoverer of hidden resources``(grovieraUrl: Uri) =   
        let resources = ["recursive/"; "test.php"; "guest/"]
        createResources(resources)
        let template = Templates.``Website discovery``()
        template.ResourceDiscovererSettings.BeRecursive <- true
        template.ResourceDiscovererSettings.RecursiveDepth <- 5
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/discoverer/test2/")),
                Template = template
            )

        // run the scan
        Utility.runScan(scanContext)
        |> Utility.verifyDiscoverer resources
       
    let ``Recursive discoverer of hidden resources with forbidden directories``(grovieraUrl: Uri) =  
        let resources = ["forbidden/"; "admin/"; "guest/"]
        createResources(resources)
        let template =  Templates.``Website discovery``()
        template.ResourceDiscovererSettings.BeRecursive <- true
        template.ResourceDiscovererSettings.RecursiveDepth <- 5
        template.ResourceDiscovererSettings.ForbiddenDirectories.AddRange(["forbidden"])

        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/discoverer/test3/")),
                Template = template
            )
                                    
        // run the scan
        Utility.runScan(scanContext)
        |> Utility.verifyDiscoverer ["admin/"; "forbidden/"]
        
    let ``Recursive discoverer of hidden resources and infer extension to use for files``(grovieraUrl: Uri) =   
        let resources = ["admin/"; "guest.php"; "guest.%EXT%"]
        createResources(resources)
        let template = Templates.``Website discovery``()
        template.ResourceDiscovererSettings.BeRecursive <- true
        template.ResourceDiscovererSettings.RecursiveDepth <- 5
        template.ResourceDiscovererSettings.Extensions.Add(".foo") |> ignore

        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/discoverer/test4/")),
                Template = template
            )
                                    
        // run the scan
        Utility.runScan(scanContext)
        |> Utility.verifyDiscoverer ["admin/"; "guest.foo"]

    let ``Recursive discoverer of hidden resources and using blank extension``(grovieraUrl: Uri) =   
        let resources = ["admin/"; "guest.php"]
        createResources(resources)
        let template = Templates.``Website discovery``()
        template.ResourceDiscovererSettings.BeRecursive <- true
        template.ResourceDiscovererSettings.RecursiveDepth <- 5
        template.ResourceDiscovererSettings.UseBlankExtension <- true

        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/discoverer/test5/")),
                Template = template
            )
                                    
        // run the scan
        Utility.runScan(scanContext)
        |> Utility.verifyDiscoverer ["admin/"; "guest"]

    let ``Recursive discoverer of hidden resources identifing a forbidden resource``(grovieraUrl: Uri) =   
        let resources = ["admin/"; "guest.php"; "secret"]
        createResources(resources)
        let template = Templates.``Website discovery``()
        template.ResourceDiscovererSettings.BeRecursive <- true
        template.ResourceDiscovererSettings.RecursiveDepth <- 5
        template.ResourceDiscovererSettings.UseBlankExtension <- true

        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/discoverer/test6/")),
                Template = template
            )
                                    
        // run the scan
        Utility.runScan(scanContext)
        |> Utility.verifyDiscoverer ["admin/"; "secret"]

    let ``Recursive discoverer of hidden resources identifing a redirect resource``(grovieraUrl: Uri) =   
        let resources = ["admin/"; "guest.php"; "redirect"]
        createResources(resources)
        let template = Templates.``Website discovery``()
        template.ResourceDiscovererSettings.BeRecursive <- true
        template.ResourceDiscovererSettings.RecursiveDepth <- 5
        template.ResourceDiscovererSettings.UseBlankExtension <- true

        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/discoverer/test7/")),
                Template = template
            )
                                    
        // run the scan
        Utility.runScan(scanContext)
        |> Utility.verifyDiscoverer ["guest"; "redirect"]

    let ``The entrypoint for the discover is a file``(grovieraUrl: Uri) =   
        let resources = ["admin/"; "test.php"]
        createResources(resources)
        let template = Templates.``Website discovery``()
        template.ResourceDiscovererSettings.BeRecursive <- false
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/discoverer/test8/index.php")),
                Template = template
            )
                                    
        // run the scan
        Utility.runScan(scanContext)
        |> Utility.verifyDiscoverer resources

    let ``Ensure that redirect to an hidden directory doesn't generate two discovery``(grovieraUrl: Uri) =   
        let resources = ["admin"; "admin"; "admin"; "admin"; "admin/"; "admin"; "admin"; ]
        createResources(resources)
        let template = Templates.``Website discovery``()
        template.ResourceDiscovererSettings.BeRecursive <- false
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/discoverer/test9/")),
                Template = template
            )
                                    
        // run the scan
        Utility.runScan(scanContext)
        |> Utility.verifyDiscoverer ["admin"]