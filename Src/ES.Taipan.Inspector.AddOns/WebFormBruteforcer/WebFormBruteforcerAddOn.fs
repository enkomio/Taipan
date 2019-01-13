namespace ES.Taipan.Inspector.AddOns.WebFormBruteforcer

open System
open System.Collections.Generic
open ES.Taipan.Inspector
open ES.Taipan.Inspector.AddOns
open ES.Taipan.Infrastructure.Service
open ES.Taipan.Infrastructure.Text
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Infrastructure.Messaging
open ES.Fslog
open System.Collections.Concurrent
open ES.Taipan.Infrastructure.Threading
open ES.Taipan.Infrastructure.Text
open ES.Taipan.Crawler
open DiffLib
open System.Threading.Tasks
open System.Linq
open System.Threading

type WebFormBruteforcerAddOn() as this =
    inherit BaseStatelessAddOn("Web Form Bruteforcer AddOn", string WebFormBruteforcerAddOn.Id, 1)    
    let _progressIndexes = new Dictionary<String, String * Int32 * Int32 * Int32>()

    let _numOfConcurrentTasks = 10
    let _analyzedPages = new HashSet<String>()
    let _scanLock = new Object()
    let _testRequests = new BlockingCollection<TestRequest>()

    let mutable _taskManager: TaskManager option = None
    let mutable _usernames = List.empty<String>
    let mutable _passwords = List.empty<String>
    let mutable _combinations = List.empty<String * String>

    let _logger =
        log "WebFormBruteforcerAddOn"
        |> info "BruteforceUsername" "Start to identify password for username: {0}"
        |> info "BruteforceOnlyPasswords" "No suitable username input field found, bruteforce only password fields"
        |> info "UpdateStatus" "Bruteforce of {0}, username {1} at {2}% [{3}/{4}]"
        |> info "TestForCombination" "Test for username/password combination on directory: {0}"
        |> build

    let reportSecurityIssue(username: String, password: String, webRequest: WebRequest, webResponse: WebResponse) =  
        let securityIssue = 
            new SecurityIssue(
                WebFormBruteforcerAddOn.Id, 
                Name = "Weak Web Form Credentials", 
                Uri = webRequest.HttpRequest.Uri, 
                EntryPoint = EntryPoint.Header,
                Note = String.Format("Account {0}:{1}", username, password)
            )

        securityIssue.Transactions.Add(webRequest, webResponse)
        securityIssue.Details.Properties.Add("Username", username)
        securityIssue.Details.Properties.Add("Password", password)
        this.Context.Value.AddSecurityIssue(securityIssue)

    let initLogStatus(index: String, username: String, totalReq: Int32) =
        lock _progressIndexes (fun _ -> _progressIndexes.[index] <- (username, 0, totalReq, 0))

    let logStatus(index: String, forcePrint: Boolean) =
        lock _progressIndexes (fun _ ->
            if _progressIndexes.ContainsKey(index) then
                let (username, currentIndex, totalCount, lastPercentage) = _progressIndexes.[index]
                let percentage = System.Math.Round((float currentIndex / float totalCount) * 100.) |> int32
                _progressIndexes.[index] <- (username, currentIndex+1, totalCount, lastPercentage)
                
                if forcePrint || lastPercentage < percentage && percentage % 5 = 0 then
                    _progressIndexes.[index] <- (username, currentIndex, totalCount, percentage)    
                    _logger?UpdateStatus(index, username, percentage, currentIndex, totalCount)
        )       

    let testUsernameAndPassword(testRequest: TestRequest, usernameInputs: String list, passwordInputs: String list, username: String, password: String, resultVerifier: WebResponse -> Boolean, serviceStateController: ServiceStateController)=
        let mutable isVulnerable = false
        if not serviceStateController.IsStopped then
            serviceStateController.WaitIfPauseRequested()
            let (sentWebRequest, receivedWebResponse) = 
                BruteforceHelper.sendProbe(
                    testRequest, 
                    usernameInputs, 
                    passwordInputs, 
                    username, 
                    password,
                    this.WebRequestor.Value
                )

            // verify test
            if resultVerifier(receivedWebResponse) then                
                reportSecurityIssue(username, password, sentWebRequest, receivedWebResponse)
                isVulnerable <- true        
        isVulnerable
            
    let bruteforceUriWithCombinations(testRequest: TestRequest, usernameInputs: String list, passwordInputs: String list, resultVerifier: WebResponse -> Boolean, serviceStateController: ServiceStateController) =        
        if not usernameInputs.IsEmpty then
            _logger?TestForCombination(testRequest.WebRequest.HttpRequest.Uri.AbsolutePath)
            _combinations
            |> List.exists(fun (username, password) -> 
                testUsernameAndPassword(
                    testRequest, 
                    usernameInputs, 
                    passwordInputs, 
                    username, 
                    password, 
                    resultVerifier,
                    serviceStateController
                )
            )
        else
            false

    let getTaskManager(serviceStateController: ServiceStateController) =
        match _taskManager with
        | None -> 
            _taskManager <- Some <| new TaskManager(serviceStateController, true, false, _numOfConcurrentTasks)
            _taskManager.Value
        | Some tm -> tm

    let bruteforcePasswordList(testRequest: TestRequest, username: String, usernameInputs: String list, passwordInputs: String list, resultVerifier: WebResponse -> Boolean, serviceStateController: ServiceStateController) =        
        // add all password and set the queue to completed
        let queue = new BlockingCollection<String>()        
        _passwords |> List.iter(queue.Add)
        queue.CompleteAdding()

        // run in parallels all the instantiated workers
        let tasks = new List<Task>()
        let taskManager = getTaskManager(serviceStateController)
        let passwordFound = ref 0
        for _ in Enumerable.Range(0, 10) do
            if not serviceStateController.IsStopped then
                serviceStateController.WaitIfPauseRequested()

                // run the parallel task
                taskManager.RunTask(fun serviceStateController -> 
                    for password in queue.GetConsumingEnumerable() do
                        if not serviceStateController.IsStopped then
                            serviceStateController.WaitIfPauseRequested()

                            // check if the password was already found for this username
                            if Interlocked.CompareExchange(passwordFound, 1, 1) = 0 then

                                // bruteforce password
                                logStatus(testRequest.WebRequest.HttpRequest.Uri.AbsolutePath, false)
                                let pwdFoundTmp = 
                                    testUsernameAndPassword(
                                        testRequest, 
                                        usernameInputs, 
                                        passwordInputs, 
                                        username, 
                                        password, 
                                        resultVerifier,
                                        serviceStateController
                                    )
                            
                                if pwdFoundTmp then
                                    // password found set exit flag
                                    Interlocked.Increment(passwordFound) |> ignore
                , true) |> tasks.Add

        // wait for all task completed        
        let counter = ref 0
        while not(Task.WaitAll(tasks |> Seq.toArray, 1000)) do
            incr counter

    let bruteforceUriWithUsernameAndPassword(testRequest: TestRequest, usernameInputs: String list, passwordInputs: String list, resultVerifier: WebResponse -> Boolean, serviceStateController: ServiceStateController) =
        if not usernameInputs.IsEmpty then
            // if the username list to use is empty just add an 
            // empty username to check for password only auth
            if _usernames |> List.isEmpty
            then [String.Empty]
            else _usernames
            |> List.iter(fun username ->
                _logger?BruteforceUsername(username)
                initLogStatus(testRequest.WebRequest.HttpRequest.Uri.AbsolutePath, username, _passwords.Length)
                bruteforcePasswordList(
                    testRequest,
                    username, 
                    usernameInputs, 
                    passwordInputs, 
                    resultVerifier,
                    serviceStateController
                )              
            )
            logStatus(testRequest.WebRequest.HttpRequest.Uri.AbsolutePath, true)
        else
            // No username in form so I'll just bruteforce password input.
            // I'm sure there are password inputs otherwise I'll not be at this code point
            _logger?BruteforceOnlyPasswords()
            initLogStatus(testRequest.WebRequest.HttpRequest.Uri.AbsolutePath, "N/A", _passwords.Length)
            bruteforcePasswordList(
                testRequest,
                "N/A", 
                usernameInputs, 
                passwordInputs, 
                resultVerifier,
                serviceStateController
            )    
            logStatus(testRequest.WebRequest.HttpRequest.Uri.AbsolutePath, true)

    let resultVerifier(falseResponse: WebResponse) (testResponse: WebResponse) =
        if falseResponse.HttpResponse.StatusCode = testResponse.HttpResponse.StatusCode then        
            if HttpUtility.isRedirect(falseResponse.HttpResponse.StatusCode) then                
                // if it is a relocation, check if the destinations are different. If they are different 
                // then a login has been successfully executed
                let templateLocation = HttpUtility.tryGetHeader("Location", falseResponse.HttpResponse.Headers)
                let testLocation = HttpUtility.tryGetHeader("Location", testResponse.HttpResponse.Headers)

                match (templateLocation, testLocation) with
                | (Some templateLocation, Some testLocation) -> 
                    not <| templateLocation.Value.Equals(testLocation.Value, StringComparison.OrdinalIgnoreCase)
                | _ -> 
                    // one of the two response doesn't have Location header, pass found (may cause FPs)
                    true
            else
                // check change on HTML page
                let ratio = TextUtility.computeDifferenceRatio(falseResponse.HttpResponse.Html, testResponse.HttpResponse.Html)
                ratio < 0.80
        else
            true

    let bruteforceWoker(serviceStateController: ServiceStateController) =
        for testRequest in _testRequests.GetConsumingEnumerable() do
            let (usernameInputs, passwordInputs) = BruteforceHelper.getUsernameandPasswordInputs(testRequest)

            // send a not valid username and password to identify form behaviour            
            let (_, webResponse) = 
                BruteforceHelper.sendProbe(
                    testRequest, 
                    usernameInputs, 
                    passwordInputs, 
                    Guid.NewGuid().ToString("N"), 
                    Guid.NewGuid().ToString("N"),
                    this.WebRequestor.Value
                )

            // run the bruteforce
            let bruteforceWithCombinationResult = 
                bruteforceUriWithCombinations(
                    testRequest, 
                    usernameInputs, 
                    passwordInputs, 
                    resultVerifier webResponse,
                    serviceStateController
                )

            if not bruteforceWithCombinationResult && not _passwords.IsEmpty then
                // combination didn't give any result, try an exhaustive approach
                bruteforceUriWithUsernameAndPassword(
                    testRequest, 
                    usernameInputs, 
                    passwordInputs, 
                    resultVerifier webResponse,
                    serviceStateController
                )    
            
    let runAllWorkers(taskManager: TaskManager) =         
        for i=0 to _numOfConcurrentTasks-1 do
            taskManager.RunTask(fun serviceStateController -> 
                bruteforceWoker(serviceStateController)
            , true) |> ignore

    let bruteforcePage(testRequest: TestRequest, taskManager: TaskManager) =        
        if taskManager.Count() = 0 then
            // no worker running, instantiace all workers
            runAllWorkers(taskManager)
        _testRequests.Add(testRequest)

    let completePasswordList() =
        // all the usernames also as passowrd and the empty string
        _passwords <- String.Empty::_usernames@_passwords |> List.distinct

    let hasWebFormAuthentication(testRequest: TestRequest) =
        if testRequest.RequestType = TestRequestType.CrawledPage then
            let webLink = testRequest.GetData<WebLink>()
            let inputs = RegexUtility.getAllHtmlTagsWithName(webLink.ParsedHtmlCode, "input")
            inputs 
            |> Seq.exists(fun input -> 
                RegexUtility
                    .getHtmlInputValue(input, "type")
                    .Equals("password", StringComparison.OrdinalIgnoreCase)
            )
        else
            false

    static member Id = Guid.Parse("65B5E32A-D952-4A51-93FC-B1A97B590886")
    override this.IsBackgroundService with get() = true

    default this.Initialize(context: Context, webRequestor: IWebPageRequestor, messageBroker: IMessageBroker, logProvider: ILogProvider) =
        let initResult = base.Initialize(context, webRequestor, messageBroker, logProvider)
        logProvider.AddLogSourceToLoggers(_logger)

        webRequestor.HttpRequestor.Settings.AllowAutoRedirect <- false
        _usernames <- defaultArg (this.Context.Value.AddOnStorage.ReadProperty<List<String>>("Usernames")) (new List<String>()) |> Seq.distinct |> Seq.toList
        _passwords <- defaultArg (this.Context.Value.AddOnStorage.ReadProperty<List<String>>("Passwords")) (new List<String>()) |> Seq.distinct |> Seq.toList
        _combinations <- defaultArg (this.Context.Value.AddOnStorage.ReadProperty<List<String * String>>("Combinations")) (new List<String * String>()) |> Seq.distinct |> Seq.toList
        completePasswordList()
        initResult

    override this.RunToCompletation(stateController: ServiceStateController) =
        _testRequests.CompleteAdding()
        let taskManager = getTaskManager(stateController)
        while not <| taskManager.AreAllTaskCompleted() do
            Async.Sleep(1000) |> Async.RunSynchronously
                        
    default this.Scan(testRequest: TestRequest, stateController: ServiceStateController) =        
        if hasWebFormAuthentication(testRequest) then
            lock _scanLock (fun _ ->
                if _analyzedPages.Add(testRequest.WebRequest.HttpRequest.Uri.AbsolutePath) then
                    let taskManager = getTaskManager(stateController)
                    bruteforcePage(testRequest, taskManager)
            )
            