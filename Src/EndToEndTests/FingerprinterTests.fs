module FingerprinterTests

    open System
    open System.Collections.Generic
    open System.Collections.Concurrent
    open System.Threading
    open System.IO
    open System.Net
    open ES.Taipan.Infrastructure.Network
    open ES.Taipan.Application
    open ES.Taipan.Fingerprinter
    open ES.Fslog
    open ES.Fslog.Loggers
    
    let private run(scanContext: ScanContext, resToCheck: (String * String list) list) =
        Utility.simulatePhp()
        Utility.runScan(scanContext)
        |> Utility.verifyFingerprint resToCheck
        Utility.stopSimulatePhp()

    let ``Fingerprint a Joomla fake web application``(grovieraUrl: Uri) =   
        createWebApplications()
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/fingerprinter/test1/")),
                Template = Templates.``Website fingerprinting``()
            )

        // run the scan
        run(scanContext, [("Joomla", ["3.4.4"])])

    let ``Ensure that if the dependant application is not found neither the plugin is found``(grovieraUrl: Uri) =   
        createWebApplications()
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/fingerprinter/test2/")),
                Template = Templates.``Website fingerprinting``()
            )

        // run the scan
        run(scanContext, [])

    let ``Fingerprint a Joomla plugin fake web application that depends on another application``(grovieraUrl: Uri) =   
        createWebApplications()
        let scanContext = 
            new ScanContext(
                StartRequest = new WebRequest(new Uri(grovieraUrl, "/fingerprinter/test3/")),
                Template = Templates.``Website fingerprinting``()
            )

        scanContext.Template.WebAppFingerprinterSettings.StopAtTheFirstApplicationIdentified <- false

        // run the scan
        run(scanContext, [("Joomla", ["3.4.4"]); ("Joomla plugin", ["0.1.0"])])