namespace ES.Groviera

open System
open System.IO
open System.IO.Compression
open System.Reflection
open System.Collections.Generic
open Suave
open Suave.Filters
open Suave.Successful
open Suave.ServerErrors
open Suave.Authentication
open Suave.Files
open Suave.Writers
open Suave.Operators
open Suave.Cookie
open Suave.RequestErrors
open Suave.Authentication
open ES.Groviera.Utility
open System.Data.SQLite

module InspectorPages =
    open System.Text
    open System.Text

    let mutable private _test24Token = new List<String>()
    let mutable private _test25Token = new List<String>()
    let _baseDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)  

    do
        // unzip .git file   
        let gitDir = Path.Combine(_baseDir, ".git")
        if Directory.Exists(gitDir) then
            Directory.Delete(gitDir, true)
        let gitFile = Path.Combine(_baseDir, ".git.zip")                
        ZipFile.ExtractToDirectory(gitFile, _baseDir)
    
    let index (ctx: HttpContext) =
        OK """<html>
  <head><title>Groviera Web App - Inspector tests</title></head>
  <body>
    This section is used in order to test for goodness of the Inspector component.</br>
	<h3>Follow a series of test cases:</h3>
	<ul>
		<li>TEST1: <a href="/inspector/test1/dirlisting/">/inspector/test1/dirlisting/</a>/</li>
        <li>TEST2: <a href="/inspector/test2/">/inspector/test2/</a> - Identify an outdated web application</li>
        <li>TEST3: <a href="/inspector/test3/">/inspector/test3/</a></li>
        <li>TEST4: <a href="/inspector/test4/">/inspector/test4/</a></li>
        <li>TEST5: <a href="/inspector/test5/">/inspector/test5/</a></li>
        <li>TEST6: <a href="/inspector/test6/">/inspector/test6/</a></li>
        <li>TEST7: <a href="/inspector/test7/">/inspector/test7/</a></li>
        <li>TEST8: <a href="/inspector/test8/">/inspector/test8/</a></li>
        <li>TEST9: <a href="/inspector/test9/">/inspector/test9/</a></li>
        <li>TEST10: <a href="/inspector/test10/">/inspector/test10/</a> - Test for the existence of a web application with known vulnerabilities</li>
        <li>TEST11: <a href="/inspector/test11/">/inspector/test11/</a> - Ensure that the vulnerable version range is satisfied</li>
        <li>TEST12: <a href="/inspector/test12/">/inspector/test12/</a> Symfony exception</li>
        <li>TEST13: <a href="/inspector/test13/">/inspector/test13/</a> Symfony exception second variant</li>
        <li>TEST14: <a href="/inspector/test14/">/inspector/test14/</a> PHP fopen error</li>
        <li>TEST15: <a href="/inspector/test15/">/inspector/test15/</a> Ruby On Rails error</li>
        <li>TEST16: <a href="/inspector/test16/">/inspector/test16/</a> ASP.NET error</li>
        <li>TEST17: <a href="/inspector/test17/">/inspector/test17/</a> 500 Internal Server Error</li>
        <li>TEST18: <a href="/inspector/test18/">/inspector/test18/</a> RXSS on query parameter</li>
        <li>TEST19: <a href="/inspector/test19/">/inspector/test19/</a> RXSS on data parameter</li>
        <li>TEST20: <a href="/inspector/test20/">/inspector/test20/</a> RXSS on http header</li>
        <li>TEST21: <a href="/inspector/test21/">/inspector/test21/</a> Info leak in .DS_Store file content</li>
        <li>TEST22: <a href="/inspector/test22/">/inspector/test22/</a> RXSS in file parameter attribute</li>
        <li>TEST23: <a href="/inspector/test23/">/inspector/test23/</a> SQL Injection error based, evil character MySQL comment</li>
        <li>TEST24: <a href="/inspector/test24/">/inspector/test24/</a> SQL Injection error based, evil character MySQL comment, AntiCSRF protection implemented</li>
        <li>TEST25: <a href="/inspector/test25/">/inspector/test25/</a> RXSS on data parameter AntiCSRF protection implemented</li>
        <li>TEST26: <a href="/inspector/test26/">/inspector/test26/</a> RXSS on a form generated via Javascript</li>
        <li>TEST27: <a href="/inspector/test27/">/inspector/test27/</a> RXSS on a form with onsubmit event that modyf value</li>
        <li>TEST28: <a href="/inspector/test28/">/inspector/test28/</a> Blind SQL Injection on GET parameter</li>
        <li>TEST29: <a href="/inspector/test29/">/inspector/test29/</a> Missing flags in cookie</li>
        <li>TEST30: <a href="/inspector/test30/">/inspector/test30/</a> Password sent over HTTP</li>
        <li>TEST31: <a href="/inspector/test31/">/inspector/test31/</a> Password witha utocomplete enabled</li>
        <li>TEST32: <a href="/inspector/test32/">/inspector/test32/</a> Extract information from a .git directory</li>
        <li>TEST33: <a href="/inspector/test33/">/inspector/test33/</a> Stored Cross Site Scripting</li>
        <li>TEST34: <a href="/inspector/test34/">/inspector/test34/</a> Web Application Session ID Passed In URL</li>
        <li>TEST35: <a href="/inspector/test35/">/inspector/test35/</a> RXSS on data parameter after redirect</li>
        <li>TEST36: <a href="/inspector/test36/">/inspector/test36/</a> RXSS on redirect html content</li>
        <li>TEST37: <a href="/inspector/test37/">/inspector/test37/</a> Regression: Avoid a FP when found an email with invalid TLD</li>
        <li>TEST38: <a href="/inspector/test38/">/inspector/test38/</a> RXSS on a password type parameter which implements check on password and retype password</li>
	</ul><br/>
  </body>
</html>""" ctx

    let getInspectorRoutes() = 
        choose [       
            GET >=> choose [
                path "/inspector/" >=> index
                path "/inspector/test1/dirlisting/" >=> test "Identify a directory listing: <h1>Index of /kubuntu/releases</h1>"
                path "/inspector/test2/" >=> test "Identify an outdated web application. In this directory is installed Joomla 3.4.4"                

                path "/inspector/test2/htaccess.txt" >=> ok
                path "/inspector/test2/joomla344version.html" >=> okContent "Joomla version 3.4.4"

                path "/inspector/test3/" >=> okContent "This is my internal network IP: 10.68.66.92"

                path "/inspector/test4/" >=> okContent "This is an email in comment <!-- This is a leaked email: my-email@enkomio.com and this is a test for invalid TLD: login-banner@2x.png -->"

                path "/inspector/test5/" >=> okContent "This is an hidden link in comment <!-- This is a link to an hidden resources: <a href='/inspector/test5/hidden'>Link</a> -->"
                path "/inspector/test5/hidden" >=> ok

                path "/inspector/test6/" >=> okContent "No security headers at all. Neither on <a href='/inspector/test6/page.html'>this page</a>"
                path "/inspector/test6/page.html" >=> okContent "No security headers here, ensure that vulnerability is triggered only one time"

                path "/inspector/test7/" >=> okHeader("Strict-Transport-Security", "max-age=1000")

                path "/inspector/test8/" >=> okHeader("X-XSS-Protection", " 0; mode=block")

                path "/inspector/test9/" >=> okHeaders[("X-XSS-Protection", "1; mode=block"); ("Strict-Transport-Security", "max-age=1004800"); ("Public-Key-Pins", "pin-sha256='isi41AizREkLvvft0IRW4u3XMFR2Yg7bvrF7padyCJg='; max-age=10")]

                path "/inspector/test10/" >=> ok
                path "/inspector/test10/htaccess.txt" >=> ok
                path "/inspector/test10/joomla344version.html" >=> okContent "Joomla version 3.4.4"

                path "/inspector/test11/" >=> ok
                path "/inspector/test11/htaccess.txt" >=> ok
                path "/inspector/test11/joomla203version.html" >=> okContent "Joomla version 2.0.3"

                path "/inspector/test12/" >=> okContent "Exception error: exception 'Symfony\Component\HttpKernel\Exception\NotFoundHttpException' in /var/www/newproject/vendor/laravel/framework/src/Illuminate/Routing/RouteCollection.php:148"
                path "/inspector/test13/" >=> okContent @"<a title=""Symfony\Component\HttpKernel\Exception\NotFoundHttpException line 145"" foo>RouteCollection.php bar</a>"
                path "/inspector/test14/" >=> okContent @"failed to open stream: No such file or directory in <b>/some/directory/foo/</b>"
                path "/inspector/test15/" >=> okContent @"<h1>Template is missing</h1>
<p>Missing template home/bot_action, application/bot_action with {:handlers=&gt;[:erb, :builder], :formats=&gt;[:html], :locale=&gt;[:en, :en]}. Searched in:
  * &quot;/home/user/apppp/app/views&quot;
  * &quot;/usr/local/rvm/gems/ruby-2.3.0/gems/devise-2.2.8/app/views&quot;
</p>"
                path "/inspector/test16/" >=> okContent @"<h2> <i>Runtime Error</i> </h2></span>  <font face=""Arial, Helvetica, Geneva, SunSans-Regular, sans-serif "">  <b> Description: </b>An exception occurred while processing your request. Additionally, another exception occurred while executing the custom error page for the first exception. The request has been terminated."
                path "/inspector/test17/" >=> okContent @"<h2>500 - Internal server error.</h2> <h3>There is a problem with the resource you are looking for, and it cannot be displayed.</h3> </fieldset></div> </div>"

                path "/inspector/test18/" >=> okContent "<a href='/inspector/test18/vuln.php?a=b'>Vulnerable page</a>"
                path "/inspector/test18/vuln.php" >=> okReplyQuery       
                
                path "/inspector/test19/" >=> okContent "<form action='/inspector/test19/vuln.php' method='POST'>Username: <input type='text' name='username'><br/><input type='submit' value='invia'></form>"       
                
                  
                path "/inspector/test20/vuln.php" >=> okReplyHeaders

                path "/inspector/test21/.DS_Store" >=> okContent 
                    (System.Text.Encoding.UTF8.GetString(
                        [|
                            0x00uy; 0x00uy; 0x00uy; 0x00uy; 0x00uy; 0x00uy; 0x00uy; 0x00uy; 0x00uy; 0x00uy; 0x00uy; 0x10uy; 0x01uy; 0x00uy; 0x00uy; 0x0Euy;
                            0x1Fuy; 0xBAuy; 0x0Euy; 0x00uy; 0xB4uy; 0x09uy; 0xCDuy; 0x21uy; 0xB8uy; 0x01uy; 0x4Cuy; 0xCDuy; 0x21uy; 0x54uy; 0x68uy; 0x69uy;
                            0x73uy; 0x20uy; 0x70uy; 0x72uy; 0x6Fuy; 0x67uy; 0x72uy; 0x61uy; 0x6Duy; 0x20uy; 0x63uy; 0x61uy; 0x6Euy; 0x6Euy; 0x6Fuy; 0x74uy;
                            0x20uy; 0x62uy; 0x65uy; 0x20uy; 0x72uy; 0x75uy; 0x6Euy; 0x20uy; 0x69uy; 0x6Euy; 0x20uy; 0x44uy; 0x4Fuy; 0x53uy; 0x20uy; 0x6Duy;
                            0x6Fuy; 0x64uy; 0x65uy; 0x2Euy; 0x0Duy; 0x0Duy; 0x0Auy; 0x69uy; 0x6Euy; 0x64uy; 0x65uy; 0x78uy; 0x2Euy; 0x70uy; 0x68uy; 0x70uy;
                            0xB9uy; 0x46uy; 0x07uy; 0xC3uy; 0xD8uy; 0x28uy; 0x54uy; 0xC3uy; 0xD8uy; 0x28uy; 0x54uy; 0xC3uy; 0xD8uy; 0x28uy; 0x54uy; 0x5Duy;
                            0x78uy; 0xEFuy; 0x54uy; 0xC2uy; 0xD8uy; 0x28uy; 0x54uy; 0xCEuy; 0x8Auy; 0xF7uy; 0x54uy; 0xC1uy; 0xD8uy; 0x28uy; 0x54uy
                        |]))
                path "/inspector/test21/index.php" >=> ok

                path "/inspector/test22/" >=> okContent """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>upload</title>
</head>
<body>
<form action="/inspector/test22/upload.php" method="POST" enctype="multipart/form-data">
  <p><input type="text" name="text1" value="text default">
  <p><input type="text" name="text2" value="a&#x03C9;b">
  <p><input type="file " name="file1">
  <p><input type=" file" name="file2">
  <p><input type="file" name="file3">
  <p><button type="submit">Submit</button>
</form>
</body>
</html>
                """    

                path "/inspector/test23/" >=> okContent "<a href='/inspector/test23/show.php?name=John'>Check this page</a>"
                path "/inspector/test23/show.php" >=> fun (ctx: HttpContext) ->
                    let username = 
                        match ctx.request.queryParam "name" with
                        | Choice1Of2 v -> v
                        | _ -> String.Empty
                
                    try
                        let result = sql("select * from users where username='" + username + "'")
                        if result.Count > 0 then
                            OK "The user that you are searching for is very coool" ctx
                        else
                            OK "Sorry no username with the one specified" ctx
                    with :? SQLiteException as sqlEx ->
                        INTERNAL_ERROR sqlEx.Message ctx
                                
                path "/inspector/test24/" >=> fun (ctx: HttpContext) -> 
                    let test24Token = Guid.NewGuid().ToString()
                    _test24Token.Add(test24Token)
                    OK(String.Format("""Welcome to the SQL Inject test via POST with AntiCSRF protection >:-)
                <br>Please specify the username that you want to search for:
    <html>
    <body>
    <form action="/inspector/test24/show.php" method="POST">
      <p>Name: <input type="text" name="name">
      <input type="hidden" name="token" value="{0}"
      <p><button type="submit">Submit</button>
    </form>
    </body>
    </html>""", test24Token)) ctx

                path "/inspector/test25/" >=> fun (ctx: HttpContext) ->
                    let test25Token = Guid.NewGuid().ToString()
                    _test25Token.Add(test25Token)
                    OK(String.Format("""Welcome to the RXSS test via POST with AntiCSRF protection >:-)            
    <html>
    <body>
    <form action='/inspector/test25/vuln.php' method='POST'>
      Username: <input type='text' name='username'><br/>
      Password: <input type='password' name='password'><br/>
      <input type="hidden" name="token" value="{0}"
      <p><button type="submit">Submit</button>
    </form>
    </body>
    </html>""", test25Token)) ctx

                path "/inspector/test26/" >=> okContent """<html><body>
    <script>
    var f = document.createElement("form");
    f.setAttribute('method',"get");
    f.setAttribute('action',atob('L2luc3BlY3Rvci90ZXN0MjYvc3VibWl0LnBocA=='));

    var i = document.createElement("input");
    i.setAttribute('type',"text");
    i.setAttribute('name',"username");

    var s = document.createElement("input");
    s.setAttribute('type',"submit");
    s.setAttribute('value',"Submit");

    f.appendChild(i);
    f.appendChild(s);

    document.getElementsByTagName('body')[0].appendChild(f);
    </script>
    </body></html>
                """
                path "/inspector/test26/submit.php" >=> fun (ctx: HttpContext) ->
                    match ctx.request.queryParam "username" with
                    | Choice1Of2 v -> OK ("Welcome back: " + v) ctx
                    | _ -> NOT_FOUND "Username not setted" ctx     

                path "/inspector/test27/" >=> okContent """<html><body>
    <script>
    function encrypt()
    {
        var x = btoa(document.forms["test"]["username"].value);
        document.forms["test"]["username"].value = x;
        return true;
    }
    </script>

    <form action='/inspector/test27/submit.php' method='POST' id='test' onsubmit='return encrypt();'>
      Username: <input type='text' name='username'><br/>
      <p><button type="submit">Submit</button>
    </form>

    </body></html>
                """       

                path "/inspector/test28/" >=> okContent "<a href='/inspector/test28/show.php?name=someusername'>Check this page vulnerable to Blind SQL Injection, you have to specify John as a valid username :)</a>"
                path "/inspector/test28/show.php" >=> fun (ctx: HttpContext) ->
                    let username = 
                        match ctx.request.queryParam "name" with
                        | Choice1Of2 v -> v
                        | _ -> String.Empty
                
                    try
                        let result = sql("select * from users where username='" + username + "'")
                        if result.Count > 0 then
                            OK "The user that you are searching for is very coool" ctx
                        else
                            OK "Sorry no username with the one specified" ctx
                    with :? SQLiteException as sqlEx ->
                        OK "Sorry no username with the one specified" ctx

                path "/inspector/test29/" >=> fun (ctx: HttpContext) ->
                    let newCtx =
                        ctx 
                        |> setCookie {HttpCookie.createKV "test29"  (Guid.NewGuid().ToString()) with httpOnly = false; secure = false}
                        |> (Async.RunSynchronously >> Option.get)

                    OK "Recevi this cookie without any secure/HttpOnly flags" newCtx

                path "/inspector/test30/" >=> okContent """
                     Form with password in clear text
                     <form action="/inspector/test30/go.php" method="GET">
                        Username: <input type="text" name="username"><br>
                        Password: <input type="password" name="password">
                        <input type="submit" value="Send">
                     </form>
                """
                path "/inspector/test30/go.php" >=> okContent "Thanks for login :)"

                path "/inspector/test31/" >=> okContent """
                     Form with password with autocomplete to ON
                     <form action="/inspector/test31/go.php" method="GET">
                        Username: <input type="text" name="username"><br>
                        Password: <input type="password" name="password" AUTOCOMPLETE="ON">
                        <input type="submit" value="Send">
                     </form>
                """
                path "/inspector/test31/go.php" >=> okContent "Thanks for login :)"

                path "/inspector/test32/" >=> okContent ".git Test. Navigate to <a href='.git/'>This .git directory</a> to start to crawling."
                pathScan "/inspector/test32/.git/%s" (fun res ->                 
                    if String.IsNullOrWhiteSpace(res) then
                        FORBIDDEN "Directory Listing Forbidden"
                    else                    
                        let filePath = Path.Combine(_baseDir, ".git", res)
                        if File.Exists(filePath) then                        
                            fun (ctx: HttpContext) -> async {
                                let newCtx = 
                                    {ctx with
                                        response = 
                                            {ctx.response with 
                                                status = HttpCode.HTTP_200.status
                                                content = HttpContent.Bytes(File.ReadAllBytes(filePath))
                                                headers = ("Content-Type", "application/octet-stream")::ctx.response.headers
                                            }
                                    }
                                return Some newCtx 
                            }
                        else
                            NOT_FOUND "file not found"
                )

                path "/inspector/test33/" >=> fun (ctx: HttpContext) ->
                    let allValues = String.Join("<br>", getAllMemDbValues())
                    let html1 = """
                         <h1>Stored Cross Site Scripting test</h1>
                         <form action="/inspector/test33/store.php" method="POST">
                            Value to save: <input type="text" name="value"><br>
                            <input type="submit" value="Send">
                         </form>
                         <hr>
                         <h2>All stored values:</h2>
                    """

                    OK (html1 + allValues) ctx

                path "/inspector/test34/" >=> fun (ctx: HttpContext) ->
                    let html = """
                         <h1>Web Application Session ID Passed In URL test</h1>
                         <form action="/inspector/test34/store.php" method="GET">
                            Value to save: <input type="text" name="value"><br>
                            <input type="submit" value="Send">
                         </form>
                    """

                    OK html ctx

                path "/inspector/test34/store.php" >=> fun (ctx: HttpContext) ->   
                    Redirection.redirect("/inspector/test34/?JSESSIONID=" + Guid.NewGuid().ToString("N")) ctx

                path "/inspector/test35/" >=> fun (ctx: HttpContext) -> 
                    let html =                        
                        match getValueFromMemDb("/inspector/test35/name") with
                        | Some v -> 
                            removeValueFromMemDb("/inspector/test35/name")
                            String.Format("<h1>Hello {0}!!</h1><br>Refresh the page to insert another name!", v)
                        | None ->
                            """
                            <h1>Welcome user! </h1>
                            <form method="POST" action="/inspector/test35/setname">
                            <table>
                                <tr><td>What's your name:</td><td><input type="text" name="name"></td></tr>
                                <tr><td><input type="submit"></td><td></td></tr>
                            </table>
                            </form>
                            """

                    OK html ctx

                path "/inspector/test36/" >=> fun (ctx: HttpContext) -> 
                    OK """
                    <h1>Welcome user! </h1>
                    <form method="GET" action="/inspector/test36/setname">
                    <table>
                        <tr><td>What's your name:</td><td><input type="text" name="name"></td></tr>
                        <tr><td><input type="submit"></td><td></td></tr>
                    </table>
                    </form>
                    """ ctx

                path "/inspector/test36/setname" >=> fun (ctx: HttpContext) ->
                    let name = 
                        match ctx.request.queryParam "name" with
                        | Choice1Of2 v -> v
                        | _ -> String.Empty

                    let html = Encoding.UTF8.GetBytes(String.Format("Hey {0}, you will be redirected to the dashboard!", name))
                    let redirectWithCustomContent =                         
                        Writers.setHeader "Location" "/inspector/test36/"
                        >=> Writers.addHeader "Content-Type" "text/html; charset=utf-8"
                        >=> Response.response HTTP_302 html
                    
                    redirectWithCustomContent ctx

                path "/inspector/test37/" >=> 
                    okContent """
                    This is an example of email False Positive                     
                    <div class="header-logo">
                      <a href="index.html"><img src="images/logo.png" data-ot-retina="images/logo@2x.png" alt=""></a>
                    </div>
                    """

                path "/inspector/test38/" >=> okContent """
                    <html><body>
                    <h1>RXSS on password field for user registration. Both password inputs must have the same value</h1>
                    <form action="/inspector/test38/register.php" method="POST">
                      <p>Username: <input type="text" name="username">
                      <p>Password: <input type="password" name="password1">
                      <p>Retype password: <input type="password" name="password2">
                      <p><button type="submit">Submit</button>
                    </form>
                    </body></html>
                """ 
            ]
        
            // *************************
            // *** -= POST routes =- ***
            // *************************
            POST >=> choose [
                path "/inspector/test19/vuln.php" >=> okReplyData
                path "/inspector/test22/upload.php" >=> okReplyData 
                path "/inspector/test24/show.php" >=> fun (ctx: HttpContext) ->
                    let username = 
                        match ctx.request.formData "name" with
                        | Choice1Of2 v -> v
                        | _ -> String.Empty

                    let token = 
                        match ctx.request.formData "token" with
                        | Choice1Of2 v -> v
                        | _ -> String.Empty

                    if _test24Token.Contains(token) then
                        try
                            _test24Token.Remove(token) |> ignore
                            let result = sql("select * from users where username='" + username + "'")
                            if result.Count > 0 then
                                OK "The user that you are searching for is very coool" ctx
                            else
                                OK "Sorry no username with the one specified" ctx
                        with :? SQLiteException as sqlEx ->
                            INTERNAL_ERROR sqlEx.Message ctx  
                    else
                        OK (String.Format("Sorry but the Token that you specified is invalid! {0}", token)) ctx

                path "/inspector/test25/vuln.php" >=> fun (ctx: HttpContext) ->
                    let token = 
                        match ctx.request.formData "token" with
                        | Choice1Of2 v -> v
                        | _ -> String.Empty

                    if _test25Token.Contains(token) then
                        _test25Token.Remove(token) |> ignore
                        okReplyData ctx
                    else
                        OK "Sorry but the Token that you specified is invalid!" ctx

                path "/inspector/test27/submit.php" >=> fun (ctx: HttpContext) ->
                    match ctx.request.formData "username" with
                    | Choice1Of2 v -> 
                        if String.IsNullOrWhiteSpace(v) then
                            NOT_FOUND "Username not setted" ctx     
                        else
                            try
                                let cleanValue = System.Text.Encoding.ASCII.GetString(Convert.FromBase64String(v))
                                OK ("Welcome back: " + cleanValue) ctx
                            with _ -> 
                                NOT_FOUND "Username not setted" ctx     
                    | _ -> NOT_FOUND "Username not setted" ctx     

                path "/inspector/test33/store.php" >=> fun (ctx: HttpContext) ->
                    let value = 
                        match ctx.request.formData "value" with
                        | Choice1Of2 v -> v
                        | _ -> String.Empty

                    if not <| String.IsNullOrWhiteSpace(value) then                        
                        addValueToMemDb(Guid.NewGuid().ToString(), value)
                        OK "Value inserted correctly! <a href='/inspector/test33/'>Go back</a>" ctx
                    else
                        OK "Sorry but the value is invalid, please specify a value! <a href='/inspector/test33/'>Go back</a>" ctx

                path "/inspector/test35/setname" >=>fun (ctx: HttpContext) ->
                    let name = 
                        match ctx.request.formData "name" with
                        | Choice1Of2 v -> v
                        | _ -> String.Empty

                    addValueToMemDb("/inspector/test35/name", name)
                    Redirection.redirect "/inspector/test35/" ctx

                path "/inspector/test38/register.php" >=> fun (ctx: HttpContext) ->
                    let username = 
                        match ctx.request.formData "username" with
                        | Choice1Of2 v -> v
                        | _ -> String.Empty

                    let password1 = 
                        match ctx.request.formData "password1" with
                        | Choice1Of2 v -> v
                        | _ -> "bla"

                    let password2 = 
                        match ctx.request.formData "password2" with
                        | Choice1Of2 v -> v
                        | _ -> "foo"

                    if password1.Equals(password2) then
                        let data = String.Join(", ", [username; password1])
                        OK ("Thanks for subscription, find below your details: " + data) ctx
                    else
                        OK "Sorry but the password that you inserted are not equals" ctx
            ]
        ]   

