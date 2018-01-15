namespace ES.Taipan.Crawler

open System
open System.Reflection
open System.IO
open System.Collections.Generic
open System.ComponentModel.Composition
open System.ComponentModel.Composition.Hosting
open ES.Fslog

type internal FilesystemAddOnManagerLogger() =
    inherit LogSource("FilesystemAddOnManagerLogger")

    [<Log(1, Message = "Loaded crawler addOn: {0}", Level = LogLevel.Verbose)>]
    member this.LoadedAddOn(addOn: ICrawlerAddOn) = 
        this.WriteLog(1, [|addOn.Name|])

type FilesystemAddOnManager(logProvider: ILogProvider) = 
    
    [<ImportMany(AllowRecomposition=true)>]
    let mutable _addOns: IEnumerable<ICrawlerAddOn> = Seq.empty
    let _loadedAddOns = new List<ICrawlerAddOn>()
    let _logger = new FilesystemAddOnManagerLogger()

    do logProvider.AddLogSourceToLoggers(_logger)

    let loadAddOn(addOn: ICrawlerAddOn) =
        _loadedAddOns.Add(addOn)
        _logger.LoadedAddOn(addOn)

    member this.LoadAddOns() =
        try                        
            _addOns <- Seq.empty
            _loadedAddOns.Clear()
             
            // load all scrapers     
            let catalog = new DirectoryCatalog(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "ES.Taipan.Crawler.*.dll")
           
            // compose parts
            let container = new CompositionContainer(catalog)          
            container.ComposeParts(this)
                        
            _addOns
            |> Seq.iter loadAddOn
        with 
            | _ as e -> 
                reraise()

    member this.GetAddOns() =
        _loadedAddOns
        |> Seq.toList

    interface ICrawlerAddOnManager with
        member this.LoadAddOns() =
            this.LoadAddOns()

        member this.GetAddOns() =
            this.GetAddOns()