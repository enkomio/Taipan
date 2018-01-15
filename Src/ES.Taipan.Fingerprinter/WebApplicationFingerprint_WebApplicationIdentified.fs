namespace ES.Taipan.Fingerprinter

open System
open System.Globalization
open System.Linq
open System.Collections.Generic
open ES.Taipan.Infrastructure.Network
open System.Xml.Linq
open System.Linq
open ES.Fslog
open ES.Taipan.Infrastructure.Service

type WebApplicationIdentified(webApplicationFingerprint: WebApplicationFingerprint, fingerprintRequest: FingerprintRequest) =
    member val WebApplicationFingerprint = webApplicationFingerprint with get
    member val IdentifiedVersions = new Dictionary<WebApplicationVersionFingerprint, FingerprintResult>() with get
    member val Request = fingerprintRequest with get
    member val Server : WebServerFingerprint option = None with get, set

    override this.ToString() =
        this.WebApplicationFingerprint.ToString()

and WebApplicationFingerprint(logProvider: ILogProvider) = 
    static let x str = XName.Get str
    let _logger = new WebApplicationFingerprintLogger()
    
    do logProvider.AddLogSourceToLoggers(_logger)
    new() = new WebApplicationFingerprint(new LogProvider())

    member val Id = Guid.NewGuid() with get, set
    member val Name = String.Empty with get, set
    member val BaseSignatures = new List<BaseSignature>() with get
    member val ScriptSignatures = new List<BaseSignature>() with get
    member val Versions : ICollection<WebApplicationVersionFingerprint> = upcast new List<WebApplicationVersionFingerprint>() with get
    member val AcceptanceRate = 0.01 with get, set
    member val DependantWebApplications = new List<DependantWebApplication>() with get
    member val Metrics : ServiceMetrics option = None with get, set

    member this.Fingeprint(webPageRequestor: IWebPageRequestor, fingerprintRequest: FingerprintRequest, serviceStateController: ServiceStateController) =
        seq {
            if this.BaseSignatures.Count > 0 && not serviceStateController.IsStopped then
                _logger.TestForWebApplication(this.Name, fingerprintRequest.Request.Uri.ToString())
                let fingStrategy = new FingerprintingStrategy(webPageRequestor, serviceStateController)
                let result = fingStrategy.Calculate(fingerprintRequest.Request.Uri.AbsoluteUri, this.BaseSignatures)
                
                // fillup metrics
                if this.Metrics.IsSome then 
                    let signatureNames =
                        result.MatchedSignatures
                        |> Seq.map(fun s -> s.Signature.Value.ToString())
                        |> fun sl -> String.Join(",", sl)
                    this.Metrics.Value.AddMetric("Last matched signature", this.Name + " " + signatureNames)
        
                if result.IsHighThan(this.AcceptanceRate) then                
                    _logger.WebApplicationSeemsToExists(this.Name, result)

                    // verify which application version is installed
                    for version in this.Versions do
                        if version.Signatures.Count > 0 && not serviceStateController.IsStopped then
                            serviceStateController.WaitIfPauseRequested()

                            this.Metrics.Value.AddMetric("Last tested version for ", this.Name + " " + version.Version)

                            _logger.TestForWebApplicationVersion(this.Name, version.Version, fingerprintRequest.Request.Uri.AbsoluteUri)
                            let (found, result) = version.Fingeprint(webPageRequestor, fingerprintRequest, fingStrategy)
                            if found then
                                let dependsOn = 
                                    let apps = this.DependantWebApplications |> Seq.map(fun wa -> wa.ApplicationName)
                                    if this.DependantWebApplications.Any() then String.Format(" (dependency: {0})", String.Join(",", apps))
                                    else String.Empty
                                _logger.WebApplicationVersionFound(this.Name, dependsOn, version.Version, result.Rate, fingerprintRequest.Request.Uri.AbsoluteUri)
                                yield (version, result)
                else
                    _logger.WebApplicationNotFound(this.Name, result.Rate)
        }            

    member this.AcquireFromXml(xmlContent: String) =          
        let doc = XDocument.Parse(xmlContent)
        let root = doc.Element(x"WebApplication")

        this.Id <- Guid.Parse(root.Element(x"Id").Value)
        this.Name <- root.Element(x"Name").Value
        this.AcceptanceRate <- Double.Parse(root.Element(x"AcceptanceRate").Value, CultureInfo.InvariantCulture)

        // add the dependant web applications
        root.Element(x"DependantWebApplications").Elements(x"WebAppName")
        |> Seq.map (fun xelem -> new DependantWebApplication(ApplicationName = xelem.Value))
        |> Seq.iter this.DependantWebApplications.Add

    override this.ToString() =
        String.Format("{0} AcceptRate={1} #DepApp={2} #Version={3}", this.Name, this.AcceptanceRate, this.DependantWebApplications.Count, this.Versions.Count)


