// --------------------------------------------------------------------------------------
// FAKE build script
// --------------------------------------------------------------------------------------

#r @"packages/FAKE/tools/FakeLib.dll"
#r @"packages/FSharpLog/lib/ES.FsLog.dll"
#r @"packages/FSharp.Compiler.Service/lib/net45/FSharp.Compiler.Service.dll"

open System
open System.Collections.Generic
open System.Text
open System.IO
open Microsoft.FSharp.Compiler.Interactive.Shell
open Fake
open Fake.AssemblyInfoFile
open Fake.ReleaseNotesHelper
 
// The name of the project
let project = "Taipan"

// Short summary of the project
let summary = "A web application vulnerability scanner tool."

// List of author names (for NuGet package)
let authors = [ "Enkomio" ]

// Specify if it is a local build. In local environment some tasks are skipped
let isLocal = String.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("CI"))
    
let appConfig = """
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <startup>
    <supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.6.1" />
  </startup>
  <runtime>
    <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
      <dependentAssembly>
        <assemblyIdentity name="FSharp.Core" publicKeyToken="b03f5f7f11d50a3a" culture="neutral" />
        <bindingRedirect oldVersion="0.0.0.0-4.4.0.0" newVersion="4.4.0.0" />
      </dependentAssembly>
    </assemblyBinding>
  </runtime>
</configuration>"""

// Build dir
let buildDir = "./build"

// Package dir
let deployDir = "./deploy"

// set the script dir as current
Directory.SetCurrentDirectory(__SOURCE_DIRECTORY__)

// Read additional information from the release notes document
let releaseNotesData = 
    let changelogFile = Path.Combine("..", "RELEASE_NOTES.md")
    File.ReadAllLines(changelogFile)
    |> parseAllReleaseNotes

let releaseNoteVersion = Version.Parse((List.head releaseNotesData).AssemblyVersion)
let buildVersion = int32(DateTime.UtcNow.Subtract(new DateTime(1980,2,1,0,0,0)).TotalHours)
let releaseVersionOfficial = new Version(releaseNoteVersion.Major, releaseNoteVersion.Minor, buildVersion)
let releaseVersion = {List.head releaseNotesData with AssemblyVersion = releaseVersionOfficial.ToString()}
trace("Build Version: " + releaseVersion.AssemblyVersion)

let genFSAssemblyInfo version projectPath =
    let projectName = System.IO.Path.GetFileNameWithoutExtension(projectPath)
    let folderName = System.IO.Path.GetFileName(System.IO.Path.GetDirectoryName(projectPath))
    let fileName = folderName @@ "AssemblyInfo.fs"
    CreateFSharpAssemblyInfo fileName
      [ Attribute.Title (projectName)
        Attribute.Product project
        Attribute.Company (authors |> String.concat ", ")
        Attribute.Description summary
        Attribute.Version (version + ".*")
        Attribute.FileVersion (version + ".*")
        Attribute.InformationalVersion (version + ".*") ]

Target "Clean" (fun _ ->
    CleanDir buildDir
    ensureDirectory buildDir

    CleanDir deployDir
    ensureDirectory deployDir
)

Target "AssemblyInfo" (fun _ ->
    let versionToUse =
        if isLocal 
        then "0.0.0"
        else releaseVersion.AssemblyVersion

    let fsProjs =  !! "*/**/*.fsproj"
    fsProjs |> Seq.iter(genFSAssemblyInfo versionToUse)
)

Target "Compile" (fun _ ->
    ["Taipan"; "EndToEndTests"]
    |> List.iter(fun projectName ->
        let project = Path.Combine(projectName, projectName + ".fsproj")
        let fileName = Path.GetFileNameWithoutExtension(projectName)
        let buildAppDir = Path.Combine(buildDir, fileName)
        ensureDirectory buildAppDir
        MSBuildRelease buildAppDir "Build" [project] |> Log "Build Output: "
    )
)

Target "GenerateTemplates" (fun _ ->
    let sbOut = StringBuilder()
    let sbErr = StringBuilder()
    ensureDirectory (String.Format("{0}/Taipan/Profiles/", buildDir))

    try
        let fsi =
            let inStream = new StringReader("")
            let outStream = new StringWriter(sbOut)
            let errStream = new StringWriter(sbErr)
            let fsiConfig = FsiEvaluationSession.GetDefaultConfiguration()        
            let argv = [|"fsi.exe"|]
            FsiEvaluationSession.Create(fsiConfig, argv, inStream, outStream, errStream)    

        fsi.EvalInteraction (File.ReadAllText("templates.fsx"))
        match fsi.EvalExpression("getTemplateContents()") with
        | Some fsiValue ->            
            fsiValue.ReflectionValue :?> (String * String) list
            |> List.iter(fun (name, xmlProfile) ->
                let filename = String.Format("{0}/Taipan/Profiles/{1}.xml", buildDir, name)
                File.WriteAllText(filename, xmlProfile) 
            )
        | None -> failwith "Template content not retrieved"
        Console.WriteLine(sbOut)
    with _ ->
        Console.Error.WriteLine("[!] ERROR: " + sbErr.ToString())
        reraise()
)

Target "GenerateAddOnData" (fun _ ->
    let sbOut = StringBuilder()
    let sbErr = StringBuilder()

    try
        let fsi =
            let inStream = new StringReader("")
            let outStream = new StringWriter(sbOut)
            let errStream = new StringWriter(sbErr)
            let fsiConfig = FsiEvaluationSession.GetDefaultConfiguration()        
            let argv = [|"fsi.exe"|]
            FsiEvaluationSession.Create(fsiConfig, argv, inStream, outStream, errStream)    

        fsi.EvalInteraction (File.ReadAllText("addOnData.fsx"))
        fsi.EvalExpression("deployToDirectory(\"" + buildDir + "\")") |> ignore
        Console.WriteLine(sbOut)
    with _ ->
        Console.Error.WriteLine("[!] ERROR: " + sbErr.ToString())
        reraise()
)

Target "CopyBrowserBinaries" (fun _ ->
    ["Taipan"; "EndToEndTests"]
    |> List.iter(fun directoryName ->
         // copy chrome
        ensureDirectory (buildDir + "/" + directoryName + "/ChromeBins/Windows")    
        Unzip  (buildDir + "/" + directoryName + "/ChromeBins/Windows") ("../Bins/chrome-win32.zip")
        
        ensureDirectory (buildDir + "/" + directoryName + "/ChromeBins/Unix32")
        Unzip  (buildDir + "/" + directoryName + "/ChromeBins/Unix32") ("../Bins/chrome-linux32.zip")

        ensureDirectory (buildDir + "/" + directoryName + "/ChromeBins/Unix64")
        Unzip  (buildDir + "/" + directoryName + "/ChromeBins/Unix64") ("../Bins/chrome-linux64.zip")

        // copy ChromeDriver and clean build
        ensureDirectory (buildDir + "/" + directoryName + "/driver")
        FileUtils.rm (buildDir + "/" + directoryName + "/chromedriver")
        FileUtils.rm (buildDir + "/" + directoryName + "/chromedriver.exe")
        FileUtils.cp_r "../Bins/driver/" (buildDir + "/" + directoryName + "/driver")    
    )
)

Target "EndToEndTests" (fun _ ->
    if not isLocal then
        Console.WriteLine("[!] Start End To End tests")
        let endToEndBinary = Path.Combine(buildDir, "EndToEndTests", "EndToEndTests.exe")
        let result = ExecProcess (fun info -> info.FileName <- endToEndBinary ) (TimeSpan.MaxValue)
        if result <> 0 then 
            failwith "EndToEndTests returned with a non-zero exit code"
)

// Generate assembly info files with the right version & up-to-date information
Target "Release" (fun _ ->
    let forbidden = [".pdb"]
    !! (buildDir + "/Taipan/**/*.*")         
    |> Seq.filter(fun f -> 
        forbidden 
        |> List.contains (Path.GetExtension(f).ToLowerInvariant())
        |> not
    )
    |> Zip buildDir (Path.Combine(deployDir, "Taipan.latest.zip"))
)

// --------------------------------------------------------------------------------------
// Run all targets by default. Invoke 'build <Target>' to override
Target "All" DoNothing

"Clean"  
  ==> "AssemblyInfo"
  ==> "Compile"    
  ==> "GenerateTemplates"  
  ==> "GenerateAddOnData"
  ==> "CopyBrowserBinaries"
  ==> "EndToEndTests"
  ==> "Release"
  ==> "All"

RunTargetOrDefault "All"