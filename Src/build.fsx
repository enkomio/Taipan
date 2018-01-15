// --------------------------------------------------------------------------------------
// FAKE build script
// --------------------------------------------------------------------------------------

#r @"packages/FAKE/tools/FakeLib.dll"
#r @"packages/FSharpLog/lib/ES.FsLog.dll"
#r @"ES.Taipan.Infrastructure/bin/Debug/ES.Taipan.Infrastructure.dll"
#r @"ES.Taipan.Inspector.AddOns/bin/Debug/ES.Taipan.Inspector.AddOns.dll"
#r @"ES.Taipan.Inspector/bin/Debug/ES.Taipan.Inspector.dll"
#load "templates.fsx"

open System
open System.Collections.Generic
open System.IO

open Fake
open Fake.AssemblyInfoFile
open Fake.ReleaseNotesHelper

open ES.Taipan.Inspector
 
// The name of the project
let project = "Taipan"

// Short summary of the project
let summary = "A web application vulnerability assessment tool."

// Longer description of the project
let description = "A web application vulnerability assessment tool."

// List of author names (for NuGet package)
let authors = [ "Enkomio" ]

// File system information
let solutionFile  = "TaipanSln.sln"

// Build dir
let buildDir = "./build"

// Package dir
let deployDir = "./deploy"

// Read additional information from the release notes document
let releaseNotesData = 
    let changelogFile = Path.Combine("..", "RELEASE_NOTES.md")
    File.ReadAllLines(changelogFile)
    |> parseAllReleaseNotes

let releaseVersion = (List.head releaseNotesData)
trace("Build release: " + releaseVersion.AssemblyVersion)

let stable = 
    match releaseNotesData |> List.tryFind (fun r -> r.NugetVersion.Contains("-") |> not) with
    | Some stable -> stable
    | _ -> releaseVersion

let genFSAssemblyInfo (projectPath) =
    let projectName = System.IO.Path.GetFileNameWithoutExtension(projectPath)
    let folderName = System.IO.Path.GetFileName(System.IO.Path.GetDirectoryName(projectPath))
    let fileName = folderName @@ "AssemblyInfo.fs"
    CreateFSharpAssemblyInfo fileName
      [ Attribute.Title (projectName)
        Attribute.Product project
        Attribute.Company (authors |> String.concat ", ")
        Attribute.Description summary
        Attribute.Version (releaseVersion.AssemblyVersion + ".*")
        Attribute.FileVersion (releaseVersion.AssemblyVersion + ".*")
        Attribute.InformationalVersion (releaseVersion.NugetVersion + ".*") ]

let writeAddOnData(addOn: IVulnerabilityScannerAddOn, data, propertyName: String) =
    let context = new Context(new FilesystemAddOnStorage(addOn, Path.Combine(buildDir, "Taipan")), fun _ -> ())
    context.AddOnStorage.SaveProperty<(String * String list) list>(propertyName, data)
    
// Generate assembly info files with the right version & up-to-date information
Target "Release" (fun _ ->
    let forbidden = [".pdb"]
    !! (buildDir + "/Taipan/**/*.*")         
    |> Seq.filter(fun f -> 
        forbidden 
        |> List.contains (Path.GetExtension(f).ToLowerInvariant())
        |> not
    )
    |> Zip buildDir (Path.Combine(deployDir, "Taipan." + releaseVersion.AssemblyVersion + ".zip"))
)

Target "CreateAddOnData" (fun _ ->
    ensureDirectory (buildDir + "/Taipan/Data")  
    // write xss payload  
    let rxssAddOn = new ES.Taipan.Inspector.AddOns.ReflectedCrossSiteScripting.ReflectedCrossSiteScriptingAddOn()
    let xssData = [
        // attack vector | list of payloads to search in the html        
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
    writeAddOnData(rxssAddOn, xssData, "Payloads")

    // write sql injection errors
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
    writeAddOnData(sqliAddOn, sqliErrors, "Errors")
)

Target "CopyData" (fun _ ->
    ensureDirectory (buildDir + "/Taipan/Data")
    ensureDirectory (buildDir + "/Taipan/Profiles")
    FileUtils.cp_r ("../Data")  (buildDir + "/Taipan/Data")

    // copy lua script    
    FileUtils.cp_r "ES.Taipan.Fingerprinter/Lua" (buildDir + "/Taipan/Data/Scripts")

    // copy templates
    for profile in Templates.templates do
        let xmlProfile = profile.ToXml()
        let filename = String.Format("{0}/Taipan/Profiles/{1}.xml", buildDir, profile.Name)
        File.WriteAllText(filename, xmlProfile) 
)

Target "CopyBinaries" (fun _ ->
    // copy chrome
    ensureDirectory (buildDir + "/Taipan/ChromeBins/Windows")    
    Unzip  (buildDir + "/Taipan/ChromeBins/Windows") ("../Bins/chrome-win32.zip")
        
    ensureDirectory (buildDir + "/Taipan/ChromeBins/Unix32")
    Unzip  (buildDir + "/Taipan/ChromeBins/Unix32") ("../Bins/chrome-linux32.zip")

    ensureDirectory (buildDir + "/Taipan/ChromeBins/Unix64")
    Unzip  (buildDir + "/Taipan/ChromeBins/Unix64") ("../Bins/chrome-linux64.zip")

    // copy ChromeDriver and clean build
    ensureDirectory (buildDir + "/Taipan/driver")
    FileUtils.rm (buildDir + "/Taipan/chromedriver")
    FileUtils.rm (buildDir + "/Taipan/chromedriver.exe")
    FileUtils.cp_r "../Bins/driver/" (buildDir + "/Taipan/driver")    
)

Target "Compile" (fun _ ->
    // compile Taipan
    let projectName = "Taipan"
    let project = Path.Combine(projectName, projectName + ".fsproj")
    let fileName = Path.GetFileNameWithoutExtension(projectName)
    let buildAppDir = Path.Combine(buildDir, fileName)
    ensureDirectory buildAppDir
    MSBuildRelease buildAppDir "Build" [project] |> Log "Taipan Build Output: "
)

Target "AssemblyInfo" (fun _ ->
  let fsProjs =  !! "*/**/*.fsproj"
  fsProjs |> Seq.iter genFSAssemblyInfo
)

Target "Clean" (fun _ ->
    CleanDir buildDir
    ensureDirectory buildDir

    CleanDir deployDir
    ensureDirectory deployDir
)

// --------------------------------------------------------------------------------------
// Run all targets by default. Invoke 'build <Target>' to override

Target "All" DoNothing

"Clean"
  ==> "AssemblyInfo"
  ==> "Compile"
  ==> "CreateAddOnData"
  ==> "CopyData"
  ==> "CopyBinaries"
  ==> "Release"
  ==> "All"

RunTargetOrDefault "All"