// --------------------------------------------------------------------------------------
// Script used to create vulnerability AddOns data
// --------------------------------------------------------------------------------------
#r @"packages/FAKE/tools/FakeLib.dll"
#r @"packages/FSharpLog/lib/ES.FsLog.dll"
#r @"build/Taipan/ES.Taipan.Infrastructure.dll"
#r @"build/Taipan/ES.Taipan.Inspector.dll"
#r @"build/Taipan/ES.Taipan.Inspector.AddOns.dll"

open System
open System.IO
open Fake
open ES.Taipan.Inspector
open ES.Taipan.Inspector.AddOns

let writeAddOnData(addOn: IVulnerabilityScannerAddOn, data, propertyName: String, buildDir: String) =
    let context = new Context(new FilesystemAddOnStorage(addOn, Path.Combine(buildDir, "Taipan")), fun _ -> ())
    context.AddOnStorage.SaveProperty<(String * String list) list>(propertyName, data)

let createAddOnData(buildDir: String) =
    ensureDirectory (buildDir + "/Taipan/Data")  
    // write xss payload  
    let xssData = [
        // attack vector | list of payloads to search in the html        
        ("<SCRIPT>document.write('<h1>-= TEXT XSS =-</h1>');</SCRIPT>", ["<h1>-= TEXT XSS =-</h1>"]);
        ("<SCRIPT>alert('XSS');</SCRIPT>", ["<SCRIPT>alert('XSS');</SCRIPT>"]);
        ("<IMG SRC=JaVaScRiPt:alert('XSS')>", ["<IMG SRC=JaVaScRiPt:alert('XSS')>"]);
        ("<IMG SRC=javascript:alert(&quot;XSS&quot;)>", ["<IMG SRC=javascript:alert('XSS')>"]);
        ("<IMG SRC=`javascript:alert(1)`>", ["<IMG SRC=`javascript:alert(1)`>"]);        
        ("<IMG SRC=\"jav   ascript:alert('XSS');\">", ["<IMG SRC=\"javascript:alert('XSS');\">"]);
        ("';!--\"<XSS>=javascript:&{()}", ["';!--\"<XSS>=javascript:&{()}"]);
        ("<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>", ["javascript:alert('XSS')"]);
        ("<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>", ["javascript:alert('XSS')"]);
        ("%25%33%63%25%34%39%25%34%64%25%34%37%25%32%30%25%35%33%25%35%32%25%34%33%25%33%64%25%34%61%25%36%31%25%35%36%25%36%31%25%35%33%25%36%33%25%35%32%25%36%39%25%35%30%25%37%34%25%33%61%25%36%31%25%36%63%25%36%35%25%37%32%25%37%34%25%32%38%25%32%37%25%35%38%25%35%33%25%35%33%25%32%37%25%32%39%25%33%65", ["javascript:alert('XSS')"])                
    ]

    [
        new ES.Taipan.Inspector.AddOns.ReflectedCrossSiteScripting.ReflectedCrossSiteScriptingAddOn() :> ES.Taipan.Inspector.AddOns.BaseStatelessAddOn
        new ES.Taipan.Inspector.AddOns.StoredCrossSiteScripting.StoredCrossSiteScriptingAddOn() :> ES.Taipan.Inspector.AddOns.BaseStatelessAddOn
    ] 
    |> List.iter(fun addOnId -> writeAddOnData(addOnId, xssData, "Payloads", buildDir))    

    // write sql injection errors, src: sqlmap project
    let sqliAddOn = new ES.Taipan.Inspector.AddOns.SqlInjection.SqlInjectionAddOn()
    let sqliErrors = [
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
    writeAddOnData(sqliAddOn, sqliErrors, "Errors", buildDir)

let deployToDirectory(buildDir: String) =
    createAddOnData(buildDir)

    // copy all AddOn Data
    ensureDirectory (buildDir + "/Taipan/Data")    
    FileUtils.cp_r ("../Data")  (buildDir + "/Taipan/Data")

    // copy lua script    
    FileUtils.cp_r "ES.Taipan.Fingerprinter/Lua" (buildDir + "/Taipan/Data/Scripts")