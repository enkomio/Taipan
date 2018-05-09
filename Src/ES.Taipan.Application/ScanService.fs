namespace ES.Taipan.Application

open System
open System.Threading
open System.IO
open System.Collections.Generic
open System.Collections.Concurrent
open ES.Fslog
open ES.Fslog.Loggers
    
type ScanService(logProvider: ILogProvider) =
    let _savedScanResults = new ConcurrentDictionary<Guid, ScanResult>()
    let mutable _currentScanResult : ScanResult option = None
    let mutable _thread : Thread option = None

    let _log =
        log "ScanService"
        |> info "ScanAborted" "Scan aborted!"
        |> build

    member this.StartScan(scan: Scan) =
        scan.Start()
        Thread.Sleep(500)
        
    member this.GetCurrenScanStatus() =
        _currentScanResult

    member this.GetScanStatus(queryId: Guid) =
        if _savedScanResults.ContainsKey(queryId) 
        then Some(_savedScanResults.[queryId] :> Object)
        else None

    member this.GetScanMetrics(scan: Scan) =
        scan.GetServiceMetrics()

    member this.GetCurrenScanMetrics() =
        match _currentScanResult with
        | Some scanResult -> this.GetScanMetrics(scanResult.Scan)
        | None -> List.empty

    member this.AbortCurrentScan() =
        match _thread with
        | Some thread -> thread.Abort()
        | None -> ()

    member this.FreeScan(queryId: Guid) =
        _savedScanResults.TryRemove(queryId) |> ignore

    member this.GetScanResult(scanContext: ScanContext, queryId: Guid, scanLogProvider: ILogProvider) =
        use scan = new Scan(scanContext, scanLogProvider) 
        let scanResult = new ScanResult(scan)
        
        // add scan result in list
        _savedScanResults.[queryId] <- scanResult
               
        // save the created value as the current one, this is useful when launched as command line,
        // since only on scan at the time can be launched
        _currentScanResult <- Some scanResult

        // run the scan in a new thread
        let currentThread = new Thread(new ThreadStart(fun _ -> 
            this.StartScan(scan)              
            scan.WaitForcompletation()
        ))
        _thread <- Some currentThread

        try
            currentThread.Start()
            currentThread.Join()
        with 
            | :? ThreadInterruptedException
            | :? ThreadStateException -> 
                _log?ScanAborted()

        scanResult