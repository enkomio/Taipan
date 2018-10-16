// --------------------------------------------------------------------------------------
// Script used to create vulnerability AddOns data
// --------------------------------------------------------------------------------------
#r @"packages/FAKE/tools/FakeLib.dll"
#r @"packages/FSharpLog/lib/ES.FsLog.dll"
#r @"build/Taipan/ES.Taipan.Infrastructure.dll"
#r @"build/Taipan/ES.Taipan.Inspector.dll"
#r @"build/Taipan/ES.Taipan.Inspector.AddOns.dll"

open System
open System.Collections.Generic
open System.IO
open Fake
open ES.Taipan.Inspector

module Writer =
    let writeAddOnData<'T>(addOn: IVulnerabilityScannerAddOn, data: 'T, propertyName: String, buildDir: String) =
        let context = new Context(new FilesystemAddOnStorage(addOn, Path.Combine(buildDir, "Taipan")), fun _ -> ())
        context.AddOnStorage.SaveProperty(propertyName, data)

let writeXssData(buildDir: String) =
    let xssData = new Dictionary<String, List<String>>()
    [
        // attack vector | list of payloads to search in the html    
        ("<img src=x onerror=document.write('<h1>-= TEXT XSS =-</h1>')>", ["<h1>-= TEXT XSS =-</h1>"])
        ("<SCRIPT>document.write('<h1>-= TEXT XSS =-</h1>');</SCRIPT>", ["<h1>-= TEXT XSS =-</h1>"])
        ("<SCRIPT>alert('XSS');</SCRIPT>", ["<SCRIPT>alert('XSS');</SCRIPT>"])
        ("<IMG SRC=JaVaScRiPt:alert('XSS')>", ["<IMG SRC=JaVaScRiPt:alert('XSS')>"])
        ("<IMG SRC=javascript:alert(&quot;XSS&quot;)>", ["<IMG SRC=javascript:alert('XSS')>"])
        ("<IMG SRC=`javascript:alert(1)`>", ["<IMG SRC=`javascript:alert(1)`>"])
        ("<IMG SRC=\"jav   ascript:alert('XSS');\">", ["<IMG SRC=\"javascript:alert('XSS');\">"])
        ("';!--\"<XSS>=javascript:&{()}", ["';!--\"<XSS>=javascript:&{()}"])
        ("<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>", ["javascript:alert('XSS')"])
        ("<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>", ["javascript:alert('XSS')"])
        ("%25%33%63%25%34%39%25%34%64%25%34%37%25%32%30%25%35%33%25%35%32%25%34%33%25%33%64%25%34%61%25%36%31%25%35%36%25%36%31%25%35%33%25%36%33%25%35%32%25%36%39%25%35%30%25%37%34%25%33%61%25%36%31%25%36%63%25%36%35%25%37%32%25%37%34%25%32%38%25%32%37%25%35%38%25%35%33%25%35%33%25%32%37%25%32%39%25%33%65", ["javascript:alert('XSS')"])
    ]
    |> List.iter(fun (a, b) -> xssData.Add(a, new List<String>(b)))

    [
        new ES.Taipan.Inspector.AddOns.ReflectedCrossSiteScripting.ReflectedCrossSiteScriptingAddOn() :> ES.Taipan.Inspector.AddOns.BaseStatelessAddOn
        new ES.Taipan.Inspector.AddOns.StoredCrossSiteScripting.StoredCrossSiteScriptingAddOn() :> ES.Taipan.Inspector.AddOns.BaseStatelessAddOn
    ] 
    |> List.iter(fun addOnId -> Writer.writeAddOnData(addOnId, xssData, "Payloads", buildDir))  
    
let writeSqliData(buildDir: String) =
    // write sql injection errors, credit: sqlmap project
    let sqliAddOn = new ES.Taipan.Inspector.AddOns.SqlInjection.SqlInjectionAddOn()
    let sqliErrors = new Dictionary<String, List<String>>()
    [
        ("MySQL", [
            @"SQL syntax.*MySQL";
            @"Warning.*mysql_.*";
            @"MySqlException \(0x";
            @"valid MySQL result";
            @"check the manual that corresponds to your (MySQL|MariaDB) server version";
            @"MySqlClient\.";
            @"com\.mysql\.jdbc\.exceptions";
            @"Uncaught Error: Call to a member function";
        ]);

        ("PostgreSQL", [
            @"PostgreSQL.*ERROR";
            @"Warning.*\Wpg_.*";
            @"valid PostgreSQL result";
            @"Npgsql\.";
            @"PG::SyntaxError:";
            @"org\.postgresql\.util\.PSQLException";
            @"ERROR:\s\ssyntax error at or near ";
        ]);

        ("Microsoft SQL Server", [
            @"Driver.* SQL[\-_ ]*Server";
            @"OLE DB.* SQL Server";
            @"\bSQL Server[^&lt;&quot;]+Driver";
            @"Warning.*(mssql|sqlsrv)_";
            @"\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}";
            @"System\.Data\.SqlClient\.SqlException";
            @"(?s)Exception.*\WRoadhouse\.Cms\.";
            @"Microsoft SQL Native Client error '[0-9a-fA-F]{8}";
            @"com\.microsoft\.sqlserver\.jdbc\.SQLServerException";
            @"ODBC SQL Server Driver";
            @"SQLServer JDBC Driver";
            @"macromedia\.jdbc\.sqlserver";
            @"com\.jnetdirect\.jsql";
        ]);

        ("Microsoft Access", [
            @"Microsoft Access (\d+ )?Driver";
            @"JET Database Engine";
            @"Access Database Engine";
            @"ODBC Microsoft Access";
            @"Syntax error \(missing operator\) in query expression";
        ]);

        ("Oracle", [
            @"\bORA-\d{5}";
            @"Oracle error";
            @"Oracle.*Driver";
            @"Warning.*\Woci_.*";
            @"Warning.*\Wora_.*";
            @"oracle\.jdbc\.driver";
            @"quoted string not properly terminated";
        ]);

        ("IBM DB2", [
            @"CLI Driver.*DB2";
            @"DB2 SQL error";
            @"\bdb2_\w+\(";
            @"SQLSTATE.+SQLCODE";
        ]);

        ("Informix", [
            @"Exception.*Informix";
            @"Informix ODBC Driver";
            @"com\.informix\.jdbc";
            @"weblogic\.jdbc\.informix";
        ]);

        ("Firebird", [
            @"Dynamic SQL Error";
            @"Warning.*ibase_.*";
        ]);

        ("SQLite", [
            @"SQLite/JDBCDriver";
            @"SQLite\.Exception";
            @"System\.Data\.SQLite\.SQLiteException";
            @"Warning.*sqlite_.*";
            @"Warning.*SQLite3::";
            @"\[SQLITE_ERROR\]";
            @"SQL logic error or missing database";
            @"unrecognized token:"
        ]);

        ("SAP MaxDB", [
            @"SQL error.*POS([0-9]+).*";
            @"Warning.*maxdb.*";
        ]);

        ("Sybase", [
            @"Warning.*sybase.*";
            @"Sybase message";
            @"Sybase.*Server message.*";
            @"SybSQLException";
            @"com\.sybase\.jdbc";
        ]);

        ("Ingres", [
            @"Warning.*ingres_";
            @"Ingres SQLSTATE";
            @"Ingres\W.*Driver";
        ]);

        ("Frontbase", [
            @"Exception (condition )?\d+. Transaction rollback.";
        ]);

        ("HSQLDB", [
            @"org\.hsqldb\.jdbc";
            @"Unexpected end of command in statement \[";
            @"Unexpected token.*in statement \[";
        ]);
    ]
    |> List.iter(fun (a, b) -> sqliErrors.Add(a, new List<String>(b)))
    Writer.writeAddOnData(sqliAddOn, sqliErrors, "Errors", buildDir)

let writeUsernameAndPassword(buildDir: String) =
    let bruteforceAddOn = new ES.Taipan.Inspector.AddOns.HttpBruteforcer.HttpBruteforcerAddOn()

    // credit to: https://github.com/danielmiessler/SecLists/blob/master/Usernames/top-usernames-shortlist.txt
    let usernames = new List<String>(["root"; "admin"; "test"; "guest"; "info"; "adm"; "mysql"; "user"; "administrator"])
    Writer.writeAddOnData(bruteforceAddOn, usernames, "Usernames", buildDir)
    
    // credit to: https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/500-worst-passwords.txt
    let passwords = new List<String>([
        "123456"; "password"; "12345678"; "1234"; "pussy"; "12345"; "dragon"; "qwerty"; "696969"; "mustang"; "letmein"; "baseball"; "master"; "michael"; 
        "football"; "shadow"; "monkey"; "abc123"; "pass"; "fuckme"; "6969"; "jordan"; "harley"; "ranger"; "iwantu"; "jennifer"; "hunter"; "fuck"; "2000"; 
        "test"; "batman"; "trustno1"; "thomas"; "tigger"; "robert"; "access"; "love"; "buster"; "1234567"; "soccer"; "hockey"; "killer"; "george"; "sexy"; 
        "andrew"; "charlie"; "superman"; "asshole"; "fuckyou"; "dallas"; "jessica"; "panties"; "pepper"; "1111"; "austin"; "william"; "daniel"; "golfer"; 
        "summer"; "heather"; "hammer"; "yankees"; "joshua"; "maggie"; "biteme"; "enter"; "ashley"; "thunder"; "cowboy"; "silver"; "richard"; "fucker"; "orange"; 
        "merlin"; "michelle"; "corvette"; "bigdog"; "cheese"; "matthew"; "121212"; "patrick"; "martin"; "freedom"; "ginger"; "blowjob"; "nicole"; "sparky"; 
        "yellow"; "camaro"; "secret"; "dick"; "falcon"; "taylor"; "111111"; "131313"; "123123"; "bitch"; "hello"; "scooter"; "please"; "porsche"; "guitar"; 
        "chelsea"; "black"; "diamond"; "nascar"; "jackson"; "cameron"; "654321"; "computer"; "amanda"; "wizard"; "xxxxxxxx"; "money"; "phoenix"; "mickey"; 
        "bailey"; "knight"; "iceman"; "tigers"; "purple"; "andrea"; "horny"; "dakota"; "aaaaaa"; "player"; "sunshine"; "morgan"; "starwars"; "boomer"; 
        "cowboys"; "edward"; "charles"; "girls"; "booboo"; "coffee"; "xxxxxx"; "bulldog"; "ncc1701"; "rabbit"; "peanut"; "john"; "johnny"; "gandalf"; 
        "spanky"; "winter"; "brandy"; "compaq"; "carlos"; "tennis"; "james"; "mike"; "brandon"; "fender"; "anthony"; "blowme"; "ferrari"; "cookie"; 
        "chicken"; "maverick"; "chicago"; "joseph"; "diablo"; "sexsex"; "hardcore"; "666666"; "willie"; "welcome"; "chris"; "panther"; "yamaha"; "justin"; 
        "banana"; "driver"; "marine"; "angels"; "fishing"; "david"; "maddog"; "hooters"; "wilson"; "butthead"; "dennis"; "fucking"; "captain"; "bigdick"; 
        "chester"; "smokey"; "xavier"; "steven"; "viking"; "snoopy"; "blue"; "eagles"; "winner"; "samantha"; "house"; "miller"; "flower"; "jack"; "firebird"; 
        "butter"; "united"; "turtle"; "steelers"; "tiffany"; "zxcvbn"; "tomcat"; "golf"; "bond007"; "bear"; "tiger"; "doctor"; "gateway"; "gators"; "angel"; 
        "junior"; "thx1138"; "porno"; "badboy"; "debbie"; "spider"; "melissa"; "booger"; "1212"; "flyers"; "fish"; "porn"; "matrix"; "teens"; "scooby"; "jason"; 
        "walter"; "cumshot"; "boston"; "braves"; "yankee"; "lover"; "barney"; "victor"; "tucker"; "princess"; "mercedes"; "5150"; "doggie"; "zzzzzz"; "gunner"; 
        "horney"; "bubba"; "2112"; "fred"; "johnson"; "xxxxx"; "tits"; "member"; "boobs"; "donald"; "bigdaddy"; "bronco"; "penis"; "voyager"; "rangers"; 
        "birdie"; "trouble"; "white"; "topgun"; "bigtits"; "bitches"; "green"; "super"; "qazwsx"; "magic"; "lakers"; "rachel"; "slayer"; "scott"; "2222"; "asdf"; 
        "video"; "london"; "7777"; "marlboro"; "srinivas"; "internet"; "action"; "carter"; "jasper"; "monster"; "teresa"; "jeremy"; "11111111"; "bill"; 
        "crystal"; "peter"; "pussies"; "cock"; "beer"; "rocket"; "theman"; "oliver"; "prince"; "beach"; "amateur"; "7777777"; "muffin"; "redsox"; "star"; 
        "testing"; "shannon"; "murphy"; "frank"; "hannah"; "dave"; "eagle1"; "11111"; "mother"; "nathan"; "raiders"; "steve"; "forever"; "angela"; "viper"; 
        "ou812"; "jake"; "lovers"; "suckit"; "gregory"; "buddy"; "whatever"; "young"; "nicholas"; "lucky"; "helpme"; "jackie"; "monica"; "midnight"; "college"; 
        "baby"; "cunt"; "brian"; "mark"; "startrek"; "sierra"; "leather"; "232323"; "4444"; "beavis"; "bigcock"; "happy"; "sophie"; "ladies"; "naughty"; 
        "giants"; "booty"; "blonde"; "fucked"; "golden"; "0"; "fire"; "sandra"; "pookie"; "packers"; "einstein"; "dolphins"; "chevy"; "winston"; "warrior"; 
        "sammy"; "slut"; "8675309"; "zxcvbnm"; "nipples"; "power"; "victoria"; "asdfgh"; "vagina"; "toyota"; "travis"; "hotdog"; "paris"; "rock"; "xxxx"; 
        "extreme"; "redskins"; "erotic"; "dirty"; "ford"; "freddy"; "arsenal"; "access14"; "wolf"; "nipple"; "iloveyou"; "alex"; "florida"; "eric"; "legend"; 
        "movie"; "success"; "rosebud"; "jaguar"; "great"; "cool"; "cooper"; "1313"; "scorpio"; "mountain"; "madison"; "987654"; "brazil"; "lauren"; "japan"; 
        "naked"; "squirt"; "stars"; "apple"; "alexis"; "aaaa"; "bonnie"; "peaches"; "jasmine"; "kevin"; "matt"; "qwertyui"; "danielle"; "beaver"; "4321"; "4128"; 
        "runner"; "swimming"; "dolphin"; "gordon"; "casper"; "stupid"; "shit"; "saturn"; "gemini"; "apples"; "august"; "3333"; "canada"; "blazer"; "cumming"; 
        "hunting"; "kitty"; "rainbow"; "112233"; "arthur"; "cream"; "calvin"; "shaved"; "surfer"; "samson"; "kelly"; "paul"; "mine"; "king"; "racing"; "5555"; 
        "eagle"; "hentai"; "newyork"; "little"; "redwings"; "smith"; "sticky"; "cocacola"; "animal"; "broncos"; "private"; "skippy"; "marvin"; "blondes"; 
        "enjoy"; "girl"; "apollo"; "parker"; "qwert"; "time"; "sydney"; "women"; "voodoo"; "magnum"; "juice"; "abgrtyu"; "777777"; "dreams"; "maxwell"; "music"; 
        "rush2112"; "russia"; "scorpion"; "rebecca"; "tester"; "mistress"; "phantom"; "billy"; "6666"; "albert"
    ])
    Writer.writeAddOnData(bruteforceAddOn, passwords, "Passwords", buildDir)

    let combinations = new List<String * String>([
        ("admin", "1"); ("admin", "123"); ("admin", "0000"); ("admin", "00000000"); ("admin", "12345"); ("admin", "123456"); ("admin", "1234567"); 
        ("admin", "12345678"); ("admin", "123456789"); ("admin", "1234567890"); ("admin", "12admin"); ("admin", "qwerty"); ("admin", "qwerty12345"); 
        ("admin", "beeline"); ("admin", "beeline2013"); ("admin", "ghbdtn"); ("admin", "admin225"); ("admin", "rombik1"); ("admin", "ho4uku6at"); 
        ("admin", "t3mp0Pa55"); ("fuck3g1", "t3mp0Pa55"); ("fuck3g1", "Wf@b9?hJ"); ("admin", "juklop"); ("admin", "superheslo"); ("admin", "362729"); 
        ("admin", "free"); ("admin", "inet"); ("admin", "internet"); ("admin", "sysadmin"); ("admin", "router"); ("admin", "asus"); ("admin", "root"); 
        ("admin", "ADMIN"); ("admin", "adsl"); ("admin", "adslroot"); ("admin", "adsladmin"); ("admin", "Ferum"); ("admin", "Ferrum"); ("admin", "FERUM"); 
        ("admin", "FERRUM"); ("admin", "Kendalf9"); ("admin", "263297"); ("admin", "590152"); ("admin", "21232"); ("admin", "adn8pzszk"); ("admin", "amvqnekk"); 
        ("admin", "biyshs9eq"); ("admin", "e2b81d_1"); ("admin", "Dkdk8e89"); ("admin", "flvbyctnb"); ("admin", "qweasdOP"); ("admin", "EbS2P8"); 
        ("admin", "FhF8WS"); ("admin", "ZmqVfo"); ("admin", "ZmqVfo1"); ("admin", "ZmqVfo2"); ("admin", "ZmqVfo3"); ("admin", "ZmqVfo4"); ("admin", "ZmqVfoVPN"); 
        ("admin", "ZmqVfoSIP"); ("admin", "ZmqVfoN1"); ("admin", "ZmqVfoN2"); ("admin", "ZmqVfoN3"); ("admin", "ZmqVfoN4"); ("admin", "9f4r5r79//"); 
        ("admin", "airocon"); ("admin", "zyxel"); ("admin", "rjynhjkm"); ("admin", "rjyabuehfwbz"); ("admin", "pc77club"); ("admin", "mordor"); 
        ("admin", "rthaoudinf81"); ("supervisor", "zyad1234"); ("admin", "EbS3P12"); ("admin", "m4f6h3"); ("admin", "gddrjbv"); ("admin", "13579"); 
        ("admin", "a1103"); ("admin", "dfzcsoah4"); ("admin", "a35ctsorg"); ("admin", "ateladmin"); ("admin", "rle6mitfw"); ("admin", "jqeni66np"); 
        ("admin", "J396cb0157a6a"); ("admin", "9r3qr2tph"); ("admin", "admroutepassw"); ("admin", "muwrh1j8m"); ("admin", "jwfbwpn1s"); 
        ("admin", "Afce1b92c8804"); ("admin", "J4f1984527a6a"); ("admin", "I5ea544606cd0"); ("admin", "dtythf77"); ("admin", "xy3ow4mn0y"); 
        ("admin", "FLBYLDFNHB"); ("admin", "B852541841t"); ("admin", "cipiripi"); ("admin", "ghjcnbnenrj1"); ("admin", "adslhakeryuga"); ("admin", "aq1sw2de3"); 
        ("admin", "lord"); ("admin", "fdpm0r"); ("admin", "15011974"); ("admin", "s15011974"); ("admin", "vr10vr10tajn1pa55"); ("admin", "Polkilo44"); 
        ("admin", "celkirulyat")
    ])
    Writer.writeAddOnData(bruteforceAddOn, combinations, "Combinations", buildDir)

let createAddOnData(buildDir: String) =
    ensureDirectory (buildDir + "/Taipan/Data")  
    writeXssData(buildDir)
    writeSqliData(buildDir)   
    writeUsernameAndPassword(buildDir)

let deployToDirectory(buildDir: String) =
    createAddOnData(buildDir)

    // copy all AddOn Data
    ensureDirectory (buildDir + "/Taipan/Data")    
    FileUtils.cp_r ("../Data")  (buildDir + "/Taipan/Data")

    // copy lua script    
    FileUtils.cp_r "ES.Taipan.Fingerprinter/Lua" (buildDir + "/Taipan/Data/Scripts")