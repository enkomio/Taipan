namespace ES.Groviera

open System
open Suave
open Suave.Filters
open Suave.Successful
open Suave.Writers
open Suave.Operators
open Suave.RequestErrors
open Suave.Authentication
open ES.Groviera.Utility

module FingerprinterPages =
    let index (ctx: HttpContext) =
        OK """<html>
  <head><title>Groviera Web App - Web Application Fingerprinter tests</title></head>
  <body>
    This section is used in order to test for goodness of the web application fingerprinter component.</br>
	<h3>Follow a series of test cases:</h3>
	<ul>
		<li>TEST1: <a href="/fingerprinter/test1/">/fingerprinter/test1/</a></li>
        <li>TEST2: <a href="/fingerprinter/test2/">/fingerprinter/test2/</a></li>
        <li>TEST3: <a href="/fingerprinter/test3/">/fingerprinter/test3/</a></li>
	</ul><br/>
  </body>
</html>""" ctx

    let getFingerprinterRoutes() = 
        choose [       
            GET >=> choose [
                path "/fingerprinter/" >=> index
                path "/fingerprinter/test1/" >=> test "Fingerprint a simple web application"
                path "/fingerprinter/test2/" >=> test "Ensure that if a dependant application is not found, neither the main application is found (in other word ensure the plugin is found only if the core application is found)"
                path "/fingerprinter/test3/" >=> test "Fingerprint a web application and its plugin"
                
                path "/fingerprinter/test1/htaccess.txt" >=> ok
                path "/fingerprinter/test1/joomla344version.html" >=> okContent "Joomla version 3.4.4"

                path "/fingerprinter/test2/plugin/dir/foo.html" >=> ok
                path "/fingerprinter/test2/plugin/dir/plugin.php" >=> okContent "Joomla awesome plugin version 0.1.0"

                path "/fingerprinter/test3/htaccess.txt" >=> ok
                path "/fingerprinter/test3/joomla344version.html" >=> okContent "Joomla version 3.4.4"
                path "/fingerprinter/test3/plugin/dir/foo.html" >=> ok
                path "/fingerprinter/test3/plugin/dir/plugin.php" >=> okContent "Joomla awesome plugin version 0.1.0"
            ]
        ]   

