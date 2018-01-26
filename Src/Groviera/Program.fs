namespace ES.Groviera

open System
open System.Net
open System.Text
open System.Threading
open System.Threading.Tasks
open Suave
open Suave.Writers
open Suave.Filters
open Suave.Successful
open Suave.Operators
open Suave.RequestErrors
open DiscovererPages
open FingerprinterPages
open ComposedPages
open CrawlerPages
open InspectorPages

module Program =
    let private _shutdownToken = new CancellationTokenSource()
    let private _simulatePhp = ref false

    let logReq (ctx: HttpContext) =
        async {                           
            let ip = ctx.connection.socketBinding
            let httpMethod = ctx.request.``method``
            let path = ctx.request.url.PathAndQuery

            let data = 
                let tmpData = " - Data: " + Encoding.Default.GetString(ctx.request.rawForm)
                match httpMethod with
                | (HttpMethod.POST) -> tmpData           
                | _  -> String.Empty
            
            Console.WriteLine(String.Format("{0} - {1} {2}{3} => {4}", ip, httpMethod, path, data, ctx.response.status.code))
            return (Some ctx)
        }

    let postReq (ctx: HttpContext) =
        async {                           
            if !_simulatePhp then
                let! ctx = addHeader "X-Powered-By" "PHP" ctx
                return Some ctx.Value
            else
                return (Some ctx)
        }

    let index (ctx: HttpContext) =
        okContent "<h1>Welcome to Groviera Web Scanner Evaluation Tool</h1>
        <p>This project was created in order to test for the goodness of a web application security scanner</p>

        <p>Here is a list of the current implemtned tests:</p>
        <ul>
            <li><a href='/crawler/'>Crawler</a></li>
            <li><a href='/discoverer/'>Hidden resorce discoverer</a></li>
            <li><a href='/fingerprinter/'>Web application fingerprinter</a></li>
            <li><a href='/inspector/'>Web application inspector</a></li>
            <li><a href='/composed/'>Misc tests</a></li>            
        </ul>
        " ctx

    let shutDownServer() =
        _shutdownToken.Cancel()

    let simulatePhpEnabledWebServer() =
        _simulatePhp := true

    let stopSimulatePhpEnabledWebServer() =
        _simulatePhp := false

    let notFound(r: String) =
        NOT_FOUND r

    [<EntryPoint>]
    let main argv = 
        let (host, port) =
                if argv.Length > 0 then argv.[0], Int32.Parse(argv.[1])
                else ("127.0.0.1", 80)

        Console.WriteLine("Running Groviera on {0}:{1}", host, port)
        Console.WriteLine("To run on different ip/port, pass as argument <binding ip> <binding port>")

        let routes = 
            choose [ 
                path "/" >=> index >=> postReq >=> logReq
                getDiscovererRoutes() >=> postReq >=> logReq
                getFingerprinterRoutes() >=> postReq >=> logReq
                getCrawlerRoutes() >=> postReq >=> logReq
                getComposedRoutes() >=> postReq >=> logReq
                getInspectorRoutes() >=> postReq >=> logReq
                pathScan "/%s" notFound >=> postReq >=> logReq
            ]
        
        let cfg = { 
            defaultConfig with
                bindings = [HttpBinding.create HTTP (IPAddress.Parse host) (uint16 port)]
                cancellationToken = _shutdownToken.Token
        }

        startWebServer cfg routes
        0
