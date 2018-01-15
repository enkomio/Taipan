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

module DiscovererPages =
    let index (ctx: HttpContext) =
        OK """<html>
  <head><title>Groviera Web App - Discoverer tests</title></head>
  <body>
    This section is used in order to test for goodness of the Hidden resources discoverer component.</br>
	<h3>Follow a series of test cases:</h3>
	<ul>
		<li>TEST1: <a href="/discoverer/test1/">/discoverer/test1/</a></li>
        <li>TEST2: <a href="/discoverer/test2/">/discoverer/test2/</a></li>
        <li>TEST3: <a href="/discoverer/test3/">/discoverer/test3/</a></li>
        <li>TEST4: <a href="/discoverer/test4/">/discoverer/test4/</a></li>
        <li>TEST5: <a href="/discoverer/test5/">/discoverer/test5/</a></li>
        <li>TEST6: <a href="/discoverer/test6/">/discoverer/test6/</a></li>
        <li>TEST7: <a href="/discoverer/test7/">/discoverer/test7/</a></li>
        <li>TEST8: <a href="/discoverer/test8/">/discoverer/test8/</a></li>
        <li>TEST9: <a href="/discoverer/test9/">/discoverer/test9/</a></li>
	</ul><br/>
  </body>
</html>""" ctx

    let getDiscovererRoutes() = 
        let mutable test9Redirect = false

        choose [       
            GET >=> choose [
                path "/discoverer/" >=> index
                path "/discoverer/test1/" >=> test "Simple discovery"
                path "/discoverer/test2/" >=> test "Recursive discovery"
                path "/discoverer/test3/" >=> test "Recursive discovery with forbidden directory"
                path "/discoverer/test4/" >=> test "Recursive discovery with added extension"
                path "/discoverer/test5/" >=> test "Recursive discovery with blank extension"
                path "/discoverer/test6/" >=> test "Identify a forbidden request"
                path "/discoverer/test7/" >=> test "Identify a redirect request"
                path "/discoverer/test8/" >=> test "Ensure that if a page is passed to the discoverer, the directory is considered for the discovery."
                path "/discoverer/test9/" >=> test "Ensure that if a redirect to a directory is found, the identified resource is only the directory and not both"
                
                path "/discoverer/test1/admin/" >=> ok
                path "/discoverer/test1/test.php" >=> ok

                path "/discoverer/test2/recursive/" >=> ok
                path "/discoverer/test2/recursive/guest/" >=> ok
                path "/discoverer/test2/recursive/guest/test.php" >=> ok

                path "/discoverer/test3/admin/" >=> ok
                path "/discoverer/test3/forbidden/" >=> ok
                path "/discoverer/test3/forbidden/guest/" >=> ok

                path "/discoverer/test4/admin/" >=> ok
                path "/discoverer/test4/admin/guest.foo" >=> ok

                path "/discoverer/test5/admin/" >=> ok
                path "/discoverer/test5/admin/guest" >=> ok

                path "/discoverer/test6/admin/" >=> ok
                path "/discoverer/test6/admin/secret" >=> return401

                path "/discoverer/test7/guest" >=> return302 "/discoverer/test7/guest/"
                path "/discoverer/test7/guest/" >=> ok
                path "/discoverer/test7/guest/redirect" >=> return302 "/discoverer/test7/guest/found"
                path "/discoverer/test7/guest/found" >=> ok

                path "/discoverer/test8/index.php" >=> ok
                path "/discoverer/test8/admin/" >=> ok
                path "/discoverer/test8/test.php" >=> ok
                                
                path "/discoverer/test9/admin" >=> return302 "/discoverer/test9/admin/"
                path "/discoverer/test9/admin/" >=> ok
            ]
        ]   

