namespace ES.Taipan.Fingerprinter

// source: http://www.fssnip.net/3K
open System
open System.Threading
open System.Collections.Concurrent
open System.Collections.Generic
open System.IO
open System.Net
open System.Text.RegularExpressions
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Infrastructure.Text

module internal SimpleCrawler =

    type Message =
        | Done
        | Mailbox of MailboxProcessor<Message>
        | Stop
        | Url of string option

    // Gates the number of crawling agents.
    [<Literal>]
    let Gate = 5

    // Extracts links from HTML.
    let extractLinks originatingUrl html = [
        for x in Regex.Matches(html, "href=(\"|')(.+?)(\"|')", RegexOptions.Singleline ||| RegexOptions.IgnorePatternWhitespace) do
            match WebUtility.getAbsoluteUriStringValueSameHost(originatingUrl, x.Groups.[2].Value.Trim()) with
            | Some url -> yield url
            | _ -> ()
    ]
    
    let crawl startUrl limit (httpRequestor: IHttpRequestor) =
        // Concurrent queue for saving collected urls.
        let q = ConcurrentQueue<string>()
    
        // Holds crawled URLs.
        let set = HashSet<string>()

        let wait = new ManualResetEventSlim()

        let domain = (new Uri(startUrl)).Host
        let isSameDomain(link: String) =
            if Uri.IsWellFormedUriString(link, UriKind.Absolute) then
                let newDomain = (new Uri(link)).Host
                domain = newDomain 
            else
                true

        let supervisor =
            MailboxProcessor.Start(fun x ->
                let rec loop run =
                    async {
                        let! msg = x.Receive()
                        match msg with
                        | Mailbox(mailbox) -> 
                            let count = set.Count
                            if count < limit - 1 && run then 
                                let url = q.TryDequeue()
                                match url with
                                | true, str -> if not (set.Contains str) then
                                                    let set'= set.Add str
                                                    mailbox.Post <| Url(Some str)
                                                    return! loop run
                                                else
                                                    mailbox.Post <| Url None
                                                    return! loop run

                                | _ -> mailbox.Post <| Url None
                                       return! loop run
                            else
                                mailbox.Post Stop
                                return! loop run
                        | Stop -> return! loop false
                        | _ -> 
                            (x :> IDisposable).Dispose()
                            wait.Set()
                    }
                loop true)

    
        let urlCollector =
            MailboxProcessor.Start(fun y ->
                let rec loop count =
                    async {
                        let! msg = y.TryReceive(6000)
                        match msg with
                        | Some message ->
                            match message with
                            | Url u ->
                                match u with
                                | Some url -> q.Enqueue url
                                              return! loop count
                                | None -> return! loop count
                            | _ ->
                                match count with
                                | Gate -> supervisor.Post Done
                                          (y :> IDisposable).Dispose()
                                | _ -> return! loop (count + 1)
                        | None -> supervisor.Post Stop
                                  return! loop count
                    }
                loop 1)
    
        /// Initializes a crawling agent.
        let webPages = new Dictionary<String, HttpResponse>()
        let crawler id =
            MailboxProcessor.Start(fun inbox ->
                let rec loop() =
                    async {
                        let! msg = inbox.Receive()
                        match msg with
                        | Url x ->
                            match x with
                            | Some url -> 
                                    match httpRequestor.SendRequest(new HttpRequest(url)) with
                                    | Some httpResponse ->
                                        let html = httpResponse.Html
                                        let links = extractLinks url html
                                        for link in links do
                                            if (isSameDomain(link) || url.Equals(startUrl, StringComparison.OrdinalIgnoreCase)) && not(webPages.ContainsKey(link)) then                                        
                                                webPages.Add(link, httpResponse)
                                                urlCollector.Post <| Url (Some link)                                        
                                    | _ -> ()
                            | None -> ()
                            
                            supervisor.Post(Mailbox(inbox))
                            return! loop()

                        | _ -> urlCollector.Post Done
                               (inbox :> IDisposable).Dispose()
                        }
                loop())

        // Spawn the crawlers.
        let crawlers = 
            [
                for i in 1 .. Gate do
                    yield crawler i
            ]
    
        // Post the first messages.
        crawlers.Head.Post <| Url (Some startUrl)
        crawlers.Tail |> List.iter (fun ag -> ag.Post <| Url None)
        wait.Wait()

        webPages