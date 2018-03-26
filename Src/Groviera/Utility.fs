namespace ES.Groviera

open System
open System.Collections.Generic
open System.Text
open Suave
open Suave.Filters
open Suave.Successful
open Suave.Writers
open Suave.Operators
open Suave.RequestErrors
open Suave.Authentication
open Suave.Cookie
open System.Data.SQLite

[<AutoOpen>]
module Utility =
    let sqlite = new SQLiteConnection("Data Source=:memory:;Version=3;New=True;")
    let session = new Dictionary<String, Object>()
    let private _memDb = new Dictionary<String, String>()

    let addValueToMemDb(name: String, value: String) =
        lock _memDb (fun _ ->
            _memDb.[name] <- value
            Console.WriteLine("Added {0} with value {1} to mem DB", name, value)
        )

    let removeValueFromMemDb(key: String) =
        lock _memDb (fun _ ->
            if _memDb.ContainsKey(key) then
                _memDb.Remove(key) |> ignore
        )

    let getValueFromMemDb(name: String) =
        lock _memDb (fun _ ->
            if _memDb.ContainsKey(name) then
                Some _memDb.[name]
            else
                None
        )

    let getAllMemDbValues() =
        lock _memDb (fun _ ->
            _memDb.Values |> Seq.readonly
        )
    
    let connectDb() =
        // create db
        sqlite.Open()
        let exec(cmd: String) =            
            use command = new SQLiteCommand(cmd, sqlite)
            command.ExecuteNonQuery() |> ignore

        [
            "create table users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)"
            "insert into users (username,password,email) values ('John', 'ne0', 'ne0@euery.com')"
            "insert into users (username,password,email) values ('deadc0de', 'letmein', 'deadc0de@euery.com')"    
            "create table ua (id INTEGER PRIMARY KEY, useragent TEXT, description TEXT);"
            "insert into ua (useragent,description) values ('Mozilla/5.0 (Windows NT 6.1; rv:7.0.1) Gecko/20100101 Firefox/7.0.1', 'Firefox')"
            "insert into ua (useragent,description) values ('Mozilla/5.0 (Windows NT 6.1; WOW64; rv:13.0) Gecko/20100101 Firefox/13.0.1', 'Firefox')"
            "insert into ua (useragent,description) values ('Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)', 'Internet Explorer')"
            "insert into ua (useragent,description) values ('Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.57 Safari/536.11', 'Chrome')"
        ]
        |> List.iter exec

    let sql(cmd: String) =
        if sqlite.State = Data.ConnectionState.Closed then
            connectDb()
            
        use command = new SQLiteCommand(cmd, sqlite)
        use reader = command.ExecuteReader()
        let result = new List<Dictionary<String, String>>()
        while reader.Read() do
            let row = new Dictionary<String, String>()            
            for name in reader.GetValues() do
                if name <> null then
                    row.Add(name, reader.[name].ToString())
            if row.Count > 0 then
                result.Add(row)
        result                

    let test (desc: String) (ctx: HttpContext) =
        OK ("""<html>
    <head><title>Groviera Web App - Test case</title></head>
    <body>    
	<h3>""" + desc + """</h3>
    </body>
</html>""") ctx

    let ok (ctx: HttpContext) =        
        OK "This content was found" ctx

    let okHeader (name: String, value: String) (ctx: HttpContext) =
        let newCtx =
            {ctx with
                response = 
                    {ctx.response with
                        headers = (name, value)::ctx.response.headers
                    }
            }

        OK "This content was found"  newCtx

    let okHeaders (headers: (String * String) list) (ctx: HttpContext) =
        let mutable newCtx = ctx

        headers
        |> List.iter(fun (name, value) ->
            newCtx <-
                {newCtx with
                    response = 
                        {newCtx.response with
                            headers = (name, value)::newCtx.response.headers
                        }
                }
        )

        OK "This content was found"  newCtx

    let login (contentOk: String) (ctx: HttpContext) =
        let data = Encoding.ASCII.GetString(ctx.request.rawForm)
        if data.Contains("root") && data.Contains("toor") then
            let sessionId = Guid.NewGuid().ToString()
            session.Add(sessionId, true)

            let newCtx =
                ctx 
                |> setCookie (HttpCookie.createKV "Session" sessionId)
                |> (Async.RunSynchronously >> Option.get)

            OK contentOk newCtx
        else
            OK "Login failed, try again" ctx

    let sessionContent (content: String) (ctx: HttpContext) =
        match ctx.request.cookies |> Seq.tryFind(fun kv -> kv.Key.Equals("Session", StringComparison.OrdinalIgnoreCase)) with
        | Some sessCookie when session.ContainsKey(sessCookie.Value.value) -> OK content ctx
        | _ -> OK "You are not authentictaed, please authenticate first" ctx

    let okContent (content: String) (ctx: HttpContext) =        
        OK content ctx

    let private _loopIndex = ref 0
    let resetInfiniteLoop (content: String) (ctx: HttpContext) = 
        if ctx.request.url.PathAndQuery.Equals("/crawler/test17/") then
            _loopIndex := 0
        OK content ctx

    let infiniteLoop (formatString: String) (ctx: HttpContext) = 
        if ctx.request.url.PathAndQuery.Contains("loop.php?param=" + (!_loopIndex).ToString()) then
            incr _loopIndex   

        if ctx.request.url.Query.Contains("foo=bar") || ctx.request.url.Query.Contains("param=") then
            let content = String.Format(formatString, !_loopIndex)  
            OK content ctx
        else
            NOT_FOUND String.Empty ctx

    let okReplyQuery (ctx: HttpContext) =        
        let content = "Query: " + ctx.request.url.ToString()
        OK content ctx

    let okReplyData (ctx: HttpContext) =        
        let reqData = Encoding.UTF8.GetString(ctx.request.rawForm)       
        let content = "Data: " + reqData
        OK content ctx

    let okReplyHeaders (ctx: HttpContext) =
        let res =
            ctx.request.headers
            |> List.map(fun (n,v) -> v)
        let s = String.Join("<br/>", res)
        let content = "Headers: " + s
        OK content ctx

    let okIfData(data: String) (html: String) (ctx: HttpContext) =
        let reqData = Encoding.UTF8.GetString(ctx.request.rawForm)       
        if reqData.Contains(data) then
            OK html  ctx
        else
            NOT_FOUND "NotFound" ctx

    let okIfQuery(data: String) (html: String) (ctx: HttpContext) =
        let reqData = ctx.request.url.Query       
        if reqData.Equals(data, StringComparison.Ordinal) then
            OK html  ctx
        else
            NOT_FOUND "NotFound" ctx

    let okCaseContent(dataToCheck: String) (ok: String) (ko: String) (ctx: HttpContext) =
        let reqData = ctx.request.url.ToString()       
        if reqData.Contains(dataToCheck) then
            OK ok ctx
        else
            OK ko ctx

    let return401 (ctx: HttpContext) =
        UNAUTHORIZED "Request unhautorized" ctx

    let return302 (redirect: String) (ctx: HttpContext) =
        Redirection.redirect redirect ctx