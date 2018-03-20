module MiscTests

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

    let ``Ensure that a closed port doesn't return any vulnerabilities``(grovieraUrl: Uri) =   
        let template = Templates.``Full template``()
        template.VulnerabilityScannerSettings.ActivateAllAddOns <- true
        
        let resources = ["admin/"]
        createResources(resources)
        createWebApplications()

        let fakeUrl = new UriBuilder(grovieraUrl, Port = grovieraUrl.Port + 1)

        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(fakeUrl.Uri),
                Template = template
            )

        // run the scan
        run(scanContext, TestResult.Create([], [], [], []))

    let ``Ensure that a not existent domain doesn't return any vulnerabilities``(grovieraUrl: Uri) =   
        let template = Templates.``Full template``()
        template.VulnerabilityScannerSettings.ActivateAllAddOns <- true
        
        let resources = ["admin/"]
        createResources(resources)
        createWebApplications()

        let fakeUrl = new Uri("http://www." + Guid.NewGuid().ToString("N") + ".com/index.php")

        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(fakeUrl),
                Template = template
            )

        // run the scan
        run(scanContext, TestResult.Create([], [], [], []))