namespace ES.Taipan.Inspector.AddOns.HttpBruteforcer

open System
open System.Collections.Generic
open ES.Taipan.Inspector
open ES.Taipan.Inspector.AddOns
open ES.Taipan.Infrastructure.Service
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Infrastructure.Messaging
open ES.Fslog
open System.Collections.Concurrent
open ES.Taipan.Infrastructure.Threading
open ES.Taipan.Infrastructure.Text

type HttpBruteforcerAddOn() as this =
    inherit BaseStatelessAddOn("Http Bruteforcer AddOn", string HttpBruteforcerAddOn.Id, 1)
    let _numOfConcurrentTasks = 5
    let _analyzedPages = new HashSet<String>()
    let _testRequests = new BlockingCollection<TestRequest>()

    let mutable _taskManager: TaskManager option = None
    let mutable _usernames = new List<String>()
    let mutable _passwords = new List<String>()
    let mutable _combinations = new List<String * String>()

    let reportSecurityIssue(username: String, password: String, webRequest: WebRequest, webResponse: WebResponse) =  
        let securityIssue = 
            new SecurityIssue(
                HttpBruteforcerAddOn.Id, 
                Name = "Weak HTTP Basic Credentials", 
                Uri = webRequest.HttpRequest.Uri, 
                EntryPoint = EntryPoint.Header,
                Note = String.Format("Account {0}:{1}", username, password)
            )

        securityIssue.Transactions.Add(webRequest, webResponse)
        securityIssue.Details.Properties.Add("Username", username)
        securityIssue.Details.Properties.Add("Password", password)

        this.Context.Value.AddSecurityIssue(securityIssue)
        
    let authenticationRequired(statusCode: System.Net.HttpStatusCode) =
        [System.Net.HttpStatusCode.Unauthorized; System.Net.HttpStatusCode.Forbidden]
        |> List.contains statusCode

    let sendRequest(webRequest: WebRequest) =
        webRequest.HttpRequest.AllowAutoRedirect <- Some false
        this.WebRequestor.Value.RequestWebPage(webRequest)

    let addAuthorizationHeader(username: String, password: String, request: HttpRequest) =
        let token = String.Format("{0}:{1}", username, password)
        let authHeader = new HttpHeader(Name="Authorization", Value=String.Format("Basic {0}", toAsciiBase64(token)))
        request.Headers.Add(authHeader)

    let testUsernameAndPassword(username: String, password: String, testRequest: TestRequest, serviceStateController: ServiceStateController) =
        if not serviceStateController.IsStopped then
            serviceStateController.WaitIfPauseRequested()

            // create the probe request and send it
            let probeRequest = new ProbeRequest(testRequest)
            let webRequest = new WebRequest(probeRequest.BuildHttpRequest(true))
            addAuthorizationHeader(username, password, webRequest.HttpRequest)
            probeRequest.WebResponse <- Some <| sendRequest(webRequest)

            // verify test
            let accountBruteforced =
                match probeRequest.WebResponse with
                | Some webResponse when box(webResponse.HttpResponse) <> null -> 
                    let statusCode = int32 webResponse.HttpResponse.StatusCode
                    statusCode >= 200 && statusCode < 400
                | _ -> false

            // send vulnerability if bruteforced
            if accountBruteforced then
                reportSecurityIssue(username, password, webRequest, probeRequest.WebResponse.Value)

            accountBruteforced
        else
            false

    let bruteforceUriWithUsernameAndPassword(testRequest: TestRequest, serviceStateController: ServiceStateController) =
        _usernames
        |> Seq.iter(fun username ->
            _passwords
            |> Seq.iter(fun password -> testUsernameAndPassword(username, password, testRequest, serviceStateController) |> ignore)
        )

    let bruteforceUriWithCombinations(testRequest: TestRequest, serviceStateController: ServiceStateController) =
        _combinations
        |> Seq.exists(fun (username, password) -> testUsernameAndPassword(username, password, testRequest, serviceStateController))

    let bruteforceWoker(serviceStateController: ServiceStateController) =
        for testRequest in _testRequests.GetConsumingEnumerable() do
            if not <| bruteforceUriWithCombinations(testRequest, serviceStateController) then
                bruteforceUriWithUsernameAndPassword(testRequest, serviceStateController)

    let getTaskManager(serviceStateController: ServiceStateController) =
        match _taskManager with
        | None -> 
            _taskManager <- Some <| new TaskManager(serviceStateController, true, false, ConcurrentLimit = _numOfConcurrentTasks)
            _taskManager.Value
        | Some tm -> 
            tm
            
    let runAllWorkers(taskManager: TaskManager) =         
        for i=0 to _numOfConcurrentTasks do
            taskManager.RunTask(fun serviceStateController -> 
                bruteforceWoker(serviceStateController)
            ) |> ignore

    let bruteforcePage(testRequest: TestRequest, taskManager: TaskManager) =        
        if taskManager.Count() = 0 then
            // no worker running, instantiace all workers
            runAllWorkers(taskManager)
        _testRequests.Add(testRequest)        

    static member Id = Guid.Parse("73BC0C5B-F9BF-4453-98C0-56BBE9EE1361")

    default this.Initialize(context: Context, webRequestor: IWebPageRequestor, messageBroker: IMessageBroker, logProvider: ILogProvider) =
        let initResult = base.Initialize(context, webRequestor, messageBroker, logProvider)
        _usernames <- defaultArg (this.Context.Value.AddOnStorage.ReadProperty<List<String>>("Usernames")) (new List<String>())
        _passwords <- defaultArg (this.Context.Value.AddOnStorage.ReadProperty<List<String>>("Passwords")) (new List<String>())
        _combinations <- defaultArg (this.Context.Value.AddOnStorage.ReadProperty<List<String * String>>("Combinations")) (new List<String * String>())
        initResult

    override this.RunToCompletation(stateController: ServiceStateController) =
        _testRequests.CompleteAdding()
        let taskManager = getTaskManager(stateController)
        while not <| taskManager.AreAllTaskCompleted() do
            Async.Sleep(1000) |> Async.RunSynchronously
                        
    default this.Scan(testRequest: TestRequest, stateController: ServiceStateController) =        
        if 
            testRequest.RequestType = TestRequestType.CrawledPage &&
            authenticationRequired(testRequest.WebResponse.HttpResponse.StatusCode) &&
            _analyzedPages.Add(testRequest.WebRequest.HttpRequest.Uri.AbsolutePath) 
        then
            let taskManager = getTaskManager(stateController)
            bruteforcePage(testRequest, taskManager)