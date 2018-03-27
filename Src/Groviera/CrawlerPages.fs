namespace ES.Groviera

open System
open System.Text
open Suave
open Suave.Filters
open Suave.Successful
open Suave.Writers
open Suave.Operators
open Suave.RequestErrors
open Suave.Authentication
open ES.Groviera.Utility
open ES.Taipan.Infrastructure.Text

module internal AuthHelper =
    let username = "admin"
    let password = "qwerty"
    let realm = "admin@localhost.local"
    let qop = "auth,auth-int"
    let nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093"
    let opaque = "5ccc069c403ebaf9f0171e9517f40e41"

    let private createChallenge() =
        String.Format(
            "Digest realm=\"{0}\",qop=\"{1}\",nonce=\"{2}\",opaque=\"{3}\"",
            realm,
            qop,
            nonce,
            opaque
        )

    let private verifyClientRequest(token: String, ctx: HttpContext) =
        let indexOfSpace = token.IndexOf(' ')
        let (encType, enc) = (token.Substring(0, indexOfSpace).Trim(), token.Substring(indexOfSpace+1).Trim())
        if encType.Equals("Digest", StringComparison.OrdinalIgnoreCase) then
            let items = 
                enc.Split(',') 
                |> Seq.map(fun v -> v.Split('='))
                |> Seq.map(fun va -> (va.[0].Trim(), va.[1].Trim([|'"'|]).Trim()))                
                |> Map.ofSeq

            let ha1 = toCleanTextMd5(String.Format("{0}:{1}:{2}", username, realm, password))
            let ha2 = toCleanTextMd5(String.Format("{0}:{1}", ctx.request.method.ToString(), ctx.request.url.AbsolutePath))
            let response = toCleanTextMd5(String.Format("{0}:{1}:{2}:{3}:{4}:{5}", ha1, items.["nonce"], items.["nc"], items.["cnonce"], items.["qop"], ha2))

            let clientResponse = items.["response"]
            response.Equals(clientResponse, StringComparison.OrdinalIgnoreCase)
        else
            false

    let authorizeDigest webpart (ctx: HttpContext) =   
        match ctx.request.header "authorization" with
        | Choice1Of2 token when verifyClientRequest(token, ctx) -> 
            webpart ctx
        | _ -> 
            let challengeDigest =                         
                Writers.addHeader "WWW-Authenticate" (createChallenge())
                >=> Response.response HTTP_401 (Encoding.Default.GetBytes(HTTP_401.message))
            
            //challenge webpart
            challengeDigest ctx

module CrawlerPages =
    let index (ctx: HttpContext) =
        OK """<html>
  <head><title>Groviera Web App - Web Crawler tests</title></head>
  <body>
    This section is used in order to test for goodness of the web crawler component.</br>
	<h3>Follow a series of test cases:</h3>
	<ul>
		<li>TEST1: <a href="/crawler/test1/">/crawler/test1/</li>
        <li>TEST2: <a href="/crawler/test2/">/crawler/test2/</li>
        <li>TEST3: <a href="/crawler/test3/">/crawler/test3/</li>
        <li>TEST4: <a href="/crawler/test4/">/crawler/test4/</a></li>
        <li>TEST5: <a href="/crawler/test5/">/crawler/test5/</a></li>
        <li>TEST6: <a href="/crawler/test6/">/crawler/test6/</a></li>
        <li>TEST7: <a href="/crawler/test7/">/crawler/test7/</a></li>
        <li>TEST8: <a href="/crawler/test8/">/crawler/test8/</a></li>
        <li>TEST9: <a href="/crawler/test9/">/crawler/test9/</a></li>
        <li>TEST10: <a href="/crawler/test10/">/crawler/test10/</a></li>
        <li>TEST11: <a href="/crawler/test11/">/crawler/test11/</a></li>
        <li>TEST12: <a href="/crawler/test12/">/crawler/test12/</a></li>
        <li>TEST13: go to: /crawler/test13/ this page will create an unfinite number of pages</li>
        <li>TEST14: <a href="/crawler/test14/">/crawler/test14/</a></li>
        <li>TEST15: <a href="/crawler/test15/">/crawler/test15/</a></li>
        <li>TEST16: <a href="/crawler/test16/">/crawler/test16/</a></li>
        <li>TEST17: <a href="/crawler/test17/">/crawler/test17/</a></li>
        <li>TEST18: <a href="/crawler/test18/">/crawler/test18/</a></li>
        <li>TEST19: <a href="/crawler/test19/">/crawler/test19/</a></li>
        <li>TEST20: <a href="/crawler/test20/">/crawler/test20/</a> Dynamic a tag</li>
        <li>TEST21: <a href="/crawler/test21/">/crawler/test21/</a> Dynamic form</li>        
        <li>TEST22: <a href="/crawler/test22/">/crawler/test22/</a>HTTP Basic authentication</li>
        <li>TEST23: <a href="/crawler/test23/">/crawler/test23/</a>HTTP Digest authentication</li>
        <li>TEST24: <a href="/crawler/test24/">/crawler/test24/</a>Bearer authentication with token value: 1234567890abcdefgh</li>
	</ul><br/>
  </body>
</html>""" ctx

    let getCrawlerRoutes() = 
        choose [       
            GET >=> choose [
                path "/crawler/" >=> index

                path "/crawler/test1/" >=> test "Crawl a <a href='/crawler/test1/simplelink.html'>simple link</a>"
                path "/crawler/test1/simplelink.html" >=> ok

                path "/crawler/test2/" >=> test "Ensure scope is honored. Link: <a href='/crawler/uazzaualla/page.html'>This link shouldn't be followed</a>. But <a href='/crawler/test2/dir/index.html'>this</a> yes."
                path "/crawler/uazzaualla/page.html" >=> ok
                path "/crawler/test2/dir/index.html" >=> ok

                path "/crawler/test3/" >=> test "Ensure referer is correctly included: <a href='/crawler/test3/page.htm'>simple link</a>"
                path "/crawler/test3/page.htm" >=> ok

                path "/crawler/test4/" >=> test "Ensure that forbidden extension are not crawled: <a href='/crawler/test4/page.png'>simple link</a>"
                path "/crawler/test4/page.png" >=> ok

                path "/crawler/test5/" >=> test "Ensure that forbidden content-type are not crawled: <a href='/crawler/test5/page.html'>simple link</a>"
                path "/crawler/test5/page.html" >=> ok

                path "/crawler/test6/" >=> test "Ensure that HTTP redirect are crawled: <a href='/crawler/test6/redirect.html'>simple link</a>"
                path "/crawler/test6/redirect.html" >=> return302 "/crawler/test6/page.html"
                path "/crawler/test6/page.html" >=> ok

                path "/crawler/test7/" >=> test "Ensure that HTML meta tag redirect are crawled: <a href='/crawler/test7/redirect.html'>simple link</a>"
                path "/crawler/test7/redirect.html" >=> okContent "<meta HTTP-EQUIV='REFRESH' content='0; url=/crawler/test7/page.html'>"
                path "/crawler/test7/page.html" >=> ok

                path "/crawler/test8/" >=> test "Ensure that POST form are submitted: <a href='/crawler/test8/form.html'>simple link</a>"
                path "/crawler/test8/form.html" >=> okContent "Form: <form action='/crawler/test8/form.php' method='POST'><input type='text' name='name'></form>"

                path "/crawler/test9/" >=> test "Ensure that POST form with value are submitted: <a href='/crawler/test9/form.html'>simple link</a>"
                path "/crawler/test9/form.html" >=> okContent "Form: <form action='/crawler/test9/form.php' method='POST'>
                <input type='text' name='username' value='foo'><input type='password' name='password' value='bar'><input type='submit' name='invia' value='login'></form>"

                path "/crawler/test10/" >=> test "Ensure that GET form with value are submitted: <a href='/crawler/test10/form.html'>simple link</a>"
                path "/crawler/test10/form.html" >=> okContent "Form: <form action='/crawler/test10/form.php' method='GET'>
                <input type='text' name='username' value='foo'><input type='password' name='password' value='bar'><input type='submit' name='invia' value='login'></form>"
                path "/crawler/test10/form.php" >=> okIfQuery "?username=foo&password=bar&invia=login" String.Empty

                path "/crawler/test11/" >=> test "Find link via GET mutation: <a href='/crawler/test11/page.php?foo=bar'>simple link</a>"                
                path "/crawler/test11/page.php" >=> ok                

                path "/crawler/test12/" >=> test "Find link via mutation from GET to POST: <a href='/crawler/test12/page.php?foo=bar'>simple link</a>"                
                path "/crawler/test12/page.php" >=> okIfQuery "?foo=bar" String.Empty

                path "/crawler/test13/" >=> test "Test for infinite crawling: <a href='/crawler/test13/loop1.php'>simple link</a>"                
                pathScan "/crawler/test13/loop%d.php" (fun i -> okContent(String.Format("Another link: <a href='/crawler/test13/loop{0}.php'>simple link</a>", i + 1)))

                path "/crawler/test14/" >=> test "Ensure that crawl page without extension is honored: <a href='/crawler/test14/page'>simple link no extension</a>"
                path "/crawler/test14/page" >=> ok

                path "/crawler/test15/" >=> test "Ensure that encoded parameter values are correctly managed: <a href='/crawler/test15/page.html'>simple link</a>"
                path "/crawler/test15/page.html" >=> okContent "<form action='/crawler/test15/form.php?value=404%3bhttp%3a%2f%2fwww.example.it%3a80%2fit%2f&amp;aaa=bbb' method='post' id='form1'>
			        <input type='hidden' name='__VIEWSTATE' value='/wEPDwULLTEzMTkwODEyMzEPZBYCZg9kFgQCAQ9kFgICGg9kFg&amp;cc=dd&lt;45'>						
			        <input type='submit' value='send'>
		        </form>"

                path "/crawler/test16/" >=> test "There is a link in a comment. <!-- This is a link to an hidden resources: <a href='/crawler/test16/hidden.html'>Link</a> --> Go away!!!"
                path "/crawler/test16/hidden.html" >=> okContent "You found an hidden link"

                path "/crawler/test17/" >=> resetInfiniteLoop "Test MaxNumOfRequestsToTheSamePage settings. <a href='/crawler/test17/loop.php?foo=bar'>Loop</a>"
                path "/crawler/test17/loop.php" >=> infiniteLoop "Ecco un nuovo parametro: <a href='/crawler/test17/loop.php?param={0}'>Loop</a>"

                path "/crawler/test18/" >=> test "Test file upload, crawl a <a href='/crawler/test18/upload.html'>upload</a>"
                path "/crawler/test18/upload.html" >=> okContent """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>upload</title>
</head>
<body>
<form action="/crawler/test18/upload.php" method="post" enctype="multipart/form-data">
  <p><input type="text" name="text1" value="text default">
  <p><input type="text" name="text2" value="a&#x03C9;b">
  <p><input type="file " name="file1">
  <p><input type=" file" name="file2">
  <p><input type="file" name="file3">
  <p><button type="submit">Submit</button>
</form>
</body>
</html>"""

                path "/crawler/test19/" >=> test "Test a session crawling after <a href='/crawler/test19/login'>login here</a>"
                path "/crawler/test19/login" >=> okContent """<!DOCTYPE html>
<html lang="en">
Login with: root:toor
<form action="/crawler/test19/login" method="post">
  <p><input type="text" name="user" value="foo">
  <p><input type="password" name="password" value="bar">
  <p><button type="submit">Login</button>
</form>
</body>
</html>
"""
                path "/crawler/test19/dashboard" >=> sessionContent "Yes this is a post authentication page!"


                path "/crawler/test20/" >=> okContent """<html><body>

                <script src="http://ajax.googleapis.com/ajax/libs/jquery/1.7/jquery.js"></script> 
    <script src="http://malsup.github.com/jquery.form.js"></script> 
<script>
document.write("<a hre" + "f='/crawler/test" + (18+(2*1)).toString() + "/a.php'>link</a>");
</script>
</body></html>"""
                path "/crawler/test20/a.php" >=> ok

                                
                path "/crawler/test21/" >=> okContent """<html><body>
<script src='/crawler/test21/validate.js'></script>
<script>
var f = document.createElement("form");
f.setAttribute('method',"post");
f.setAttribute('name',"dynamicForm");
f.setAttribute('id',"test");
f.setAttribute('action',"/crawler/test21/submit.php");

var i = document.createElement("input");
i.setAttribute('type',"text");
i.setAttribute('name',"username");

var h = document.createElement("input");
h.setAttribute('type',"hidden");
h.setAttribute('name',"token");
h.setAttribute('value',"token_1234");

var s = document.createElement("input");
s.setAttribute('type',"submit");
s.setAttribute('value',"Submit");

f.appendChild(i);
f.appendChild(h);
f.appendChild(s);

f.onsubmit = function() {
    var i = document.createElement("input");
    i.setAttribute('type',"password");
    i.setAttribute('name',"password");
    i.setAttribute('value',"secret");
    this.appendChild(i);
    return validateForm();
};

document.getElementsByTagName('body')[0].appendChild(f);
</script>
</body></html>"""
                path "/crawler/test21/validate.js" >=> okContent """
function validateForm() {
    try {
        console.log('validate form');
        var pwd = document.forms["dynamicForm"]["password"].value;
        var tkn = document.forms["dynamicForm"]["token"].value;

        if (pwd == null || pwd == "" || tkn != "token_1234") { 
            return false;
        }
        else {
            // send password as base64
            var epwd = btoa(pwd);
            document.forms["dynamicForm"]["password"].value = epwd;

            var username = document.forms["dynamicForm"]["username"].value;
            if (username == "") {
                document.forms["dynamicForm"]["username"].value = "no value";
            }
            return true;
        }
    }
    catch(e) {
        return false;
    }
}"""
                path "/crawler/test21/dashboard.php" >=> ok

                // Test 22
                path "/crawler/test22/" >=> Authentication.authenticateBasic (fun (user,pwd) -> user = "admin" && pwd = "admin")  (okContent "<a href='/crawler/test22/authok'>New link</a>")
                path "/crawler/test22/authok" >=> Authentication.authenticateBasic (fun (user,pwd) -> user = "admin" && pwd = "admin")  ok

                // Test 23
                path "/crawler/test23/" >=> AuthHelper.authorizeDigest (okContent "<a href='/crawler/test23/authok'>New link</a>")
                path "/crawler/test23/authok" >=> AuthHelper.authorizeDigest ok

                // Test 23
                path "/crawler/test24/" >=> fun (ctx: HttpContext) ->
                    match ctx.request.header "authorization" with
                    | Choice1Of2 headerValue ->
                        let items = headerValue.Split(' ')
                        let (authType, token) = (items.[0].Trim(), items.[1].Trim())
                        if authType.Equals("Bearer", StringComparison.OrdinalIgnoreCase) && token.Equals("1234567890abcdefgh", StringComparison.OrdinalIgnoreCase) then
                            OK "<a href='/crawler/test24/secretlink_post_auth'>New link</a>" ctx
                        else
                            let bearerAuth =                         
                                Writers.addHeader "WWW-Authenticate" ("Bearer realm=\"" + AuthHelper.realm + "\"")
                                >=> Response.response HTTP_401 (Encoding.Default.GetBytes(HTTP_401.message))
                            bearerAuth ctx
                    | _ ->
                        let bearerAuth =                         
                            Writers.addHeader "WWW-Authenticate" ("Bearer realm=\"" + AuthHelper.realm + "\"")
                            >=> Response.response HTTP_401 (Encoding.Default.GetBytes(HTTP_401.message))
                        bearerAuth ctx
                path "/crawler/test24/secretlink_post_auth" >=> ok
            ]

            POST >=> choose [
                path "/crawler/test8/form.php" >=> okIfData "name" String.Empty
                path "/crawler/test9/form.php" >=> okIfData "username=foo&password=bar&invia=login" String.Empty
                path "/crawler/test12/page.php" >=> okIfData "foo=bar" String.Empty
                path "/crawler/test15/form.php" >=> ok
                path "/crawler/test18/upload.php" >=> ok
                path "/crawler/test19/login" >=> login "Login successful, see logged resource <a href='/crawler/test19/dashboard'>here</a>"
                path "/crawler/test21/submit.php" >=> fun (ctx: HttpContext) ->
                    let username = 
                        match ctx.request.formData "username" with
                        | Choice1Of2 v -> v
                        | _ -> String.Empty

                    let tkn = 
                        match ctx.request.formData "token" with
                        | Choice1Of2 v -> v
                        | _ -> String.Empty

                    let pwd = 
                        match ctx.request.formData "password" with
                        | Choice1Of2 v -> v
                        | _ -> String.Empty
                                            
                    if pwd = Convert.ToBase64String(Encoding.Default.GetBytes("secret")) && tkn = "token_1234" then
                        if username = "" then
                            NOT_FOUND "NotFound" ctx
                        else                
                            OK "Secret is correct, go to <a href='/crawler/test21/dashboard.php'>next link</a>" ctx
                    else
                        NOT_FOUND "NotFound" ctx
            ]
        ]   

