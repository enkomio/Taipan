module internal Logging

open System
open System.Text.RegularExpressions
open System.IO
open System.Reflection
open ES.Fslog
open ES.Fslog.TextFormatters
open ES.Fslog.Loggers
open ES.Taipan.Application

let logFile(domain: String, profileName: String) =
    let cleanProfileName = Regex.Replace(profileName.Replace(' ', '_'), "[^a-zA-Z0-9._]", String.Empty)
    let now = DateTime.Now.ToString("yyyyMMdd_hhmmss")
    String.Format("{0}_{1}_{2}_{3}.log", domain, cleanProfileName, now, Guid.NewGuid().ToString("N"))

// loggers
type internal ProgramLogger() =
    inherit LogSource("Program")
    
    [<Log(1, Message = "Scan log file: {0}", Level = LogLevel.Informational)>]
    member this.ScanCompleted(logFile: String) = 
        this.WriteLog(1, [|logFile|])
        
    [<Log(2, Message = "Commands: [P] Pause [S] Stop [R] Resume", Level = LogLevel.Informational)>]
    member this.ScanCommands() = 
        this.WriteLog(2, [||])

    [<Log(3, Message = "Scan result report: {0}", Level = LogLevel.Informational)>]
    member this.ReportSaved(report: String) = 
        this.WriteLog(3, [|report|])
         
type ConsoleLogFormatter() = 
    let getLevelStr(logLevel: LogLevel) =
        match logLevel with
        | LogLevel.Critical      -> "CRIT"
        | LogLevel.Error         -> "ERRO"
        | LogLevel.Warning       -> "WARN"
        | LogLevel.Informational -> "INFO"
        | LogLevel.Verbose       -> "TRAC"
        | _ -> failwith "getLevelStr"
    
    member this.FormatMessage(logEvent: LogEvent) =
        String.Format("[{0}] {1}", getLevelStr(logEvent.Level), logEvent.Message)            

    interface ITextFormatter with
        member this.FormatMessage(logEvent: LogEvent) =
            this.FormatMessage(logEvent)

let path = FileInfo(Assembly.GetExecutingAssembly().Location).Directory.FullName
Directory.CreateDirectory(Path.Combine(path, "Logs")) |> ignore

let programLogger = new ProgramLogger()

let configureLoggers(domainName: String, profileName: String, isVerbose: Boolean) =
    let domain = (new Uri(domainName)).Host
    let logProvider = new LogProvider()    
    let logLevel = if isVerbose then LogLevel.Verbose else LogLevel.Informational
    let logfile = logFile(domain, profileName)
    logProvider.AddLogger(new ConsoleLogger(logLevel, new ConsoleLogFormatter()))
    logProvider.AddLogger(new FileLogger(logLevel, Path.Combine(path, "Logs", logfile)))
    logProvider.AddLogSourceToLoggers(programLogger)
    (logProvider, logfile)