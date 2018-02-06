[<AutoOpen>]
module MockData

    open System
    open System.IO
    open System.Net
    open System.Reflection
    open System.Diagnostics
    open System.Threading
    open ES.Fslog
    open ES.Fslog.Loggers
    open ES.Taipan.Application
    open ES.Taipan.Crawler
    open ES.Taipan.Crawler.WebScrapers
    open ES.Taipan.Infrastructure.Text
    open ES.Taipan.Inspector.AddOns.WebApplicationVulnerability
        
    [<AutoOpen>]
    module Templates =
        let private _phpSignatureDir = Path.Combine("Data", "Signatures", "Php")

        let private createAppWithDependency(appName: String, dependantWebApp: String) =
            let filename = Path.Combine(_phpSignatureDir, appName, "Configuration", appName + ".xml")
            if not <| File.Exists(filename) then
                Directory.CreateDirectory(Path.Combine(_phpSignatureDir, appName, "Configuration")) |> ignore            
                File.WriteAllText(filename, String.Format("""
                <WebApplication>
                  <Id>{0}</Id>
                  <Name>{1}</Name>
                  <AcceptanceRate>0.01</AcceptanceRate>
                  <DependantWebApplications><WebAppName>{2}</WebAppName></DependantWebApplications>
                </WebApplication>
                """, Guid.NewGuid(), appName, dependantWebApp))

        let private createApp(appName: String) =
            let filename = Path.Combine(_phpSignatureDir, appName, "Configuration", appName + ".xml")
            if not <| File.Exists(filename) then
                Directory.CreateDirectory(Path.Combine(_phpSignatureDir, appName, "Configuration")) |> ignore            
                File.WriteAllText(filename, String.Format("""
                <WebApplication>
                  <Id>{0}</Id>
                  <Name>{1}</Name>
                  <AcceptanceRate>0.01</AcceptanceRate>
                  <DependantWebApplications />
                </WebApplication>
                """, Guid.NewGuid(), appName))

        let private createVersion(appName: String, version: String) =
            let filename = Path.Combine(_phpSignatureDir, appName, "Configuration", version + ".xml")
            if not <| File.Exists(filename) then
                Directory.CreateDirectory(Path.Combine(_phpSignatureDir, appName, "Configuration")) |> ignore
                File.WriteAllText(filename, String.Format("""
                <WebApplicationVersion>
                  <Id>{0}</Id>
                  <Version>{1}</Version>
                  <AcceptanceRate>1</AcceptanceRate>
                </WebApplicationVersion>
                """, Guid.NewGuid(), version))

        let private createAppSignature(appName: String, signature: String) =
            createApp(appName)

            Directory.CreateDirectory(Path.Combine(_phpSignatureDir, appName, "Apps", appName)) |> ignore
            File.WriteAllText(Path.Combine(_phpSignatureDir, appName, "Apps", appName, "FILE_" + Guid.NewGuid().ToString("N") + ".xml"), String.Format("""
            <FileExistsSignature>
              <Id>{0}</Id>
              <FilePath>{1}</FilePath>
            </FileExistsSignature>
            """, Guid.NewGuid(), signature))

        let private createVersionSignature(appName: String, version: String, signature: String, value: String) =
            createVersion(appName, version)

            Directory.CreateDirectory(Path.Combine(_phpSignatureDir, appName, "Apps", version)) |> ignore
            File.WriteAllText(Path.Combine(_phpSignatureDir, appName, "Apps", version, "MD5_" + Guid.NewGuid().ToString("N") + ".xml"), String.Format("""
            <FileExistsSignature>
              <Id>{0}</Id>
              <FilePath>{1}</FilePath>
              <MD5>{2}</MD5>
            </FileExistsSignature>
            """, Guid.NewGuid(), signature, toCleanTextMd5(value)))

        let sqliDatabaseErrors = [  
                ("MySQL", [
                    @"SQL syntax.*MySQL";
                    @"Warning.*mysql_.*";
                    @"MySqlException \(0x";
                    @"valid MySQL result";
                    @"check the manual that corresponds to your (MySQL|MariaDB) server version";
                    @"MySqlClient\.";
                    @"com\.mysql\.jdbc\.exceptions";
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

        let createWebApplications() =
            // cleaning
            if Directory.Exists(_phpSignatureDir) then
                Directory.Delete(_phpSignatureDir, true)
                        
            // create fake joomla files            
            createAppSignature("Joomla", "htaccess.txt")
            createVersionSignature("Joomla", "3.4.4", "joomla344version.html", "Joomla version 3.4.4")
            createVersionSignature("Joomla", "3.5.4", "joomla354version.html", "Joomla version 3.5.4")
            createVersionSignature("Joomla", "2.0.3", "joomla203version.html", "Joomla version 2.0.3")

            // create fake joomla plugin
            createAppWithDependency("Joomla plugin", "Joomla")
            createAppSignature("Joomla plugin", "plugin/dir/foo.html")
            createVersionSignature("Joomla plugin", "0.1.0", "plugin/dir/plugin.php", "Joomla awesome plugin version 0.1.0")

        let createWebApplicationVulnerabilities() =
            // cleaning
            let storageDir = Path.Combine("Data", "AddOnStorage")
            if Directory.Exists(storageDir) then
                Directory.Delete(storageDir, true)
            
            let addOn = new WebApplicationVulnerabilityAddOn()
            let context = new ES.Taipan.Inspector.Context(ES.Taipan.Inspector.FilesystemAddOnStorage(addOn), fun _ -> ())
            context.AddOnStorage.SaveProperty("Joomla", ["V0001"; "V0002"])
            
            let vuln = {Id = Guid.NewGuid(); Application = "Joomla"; AffectedVersions = ["3.0.0 - 3.4.5"]; VulnerabilityName = "Joomla 3.4.4 RXSS"; Impact = "Low"; ExternalReferer = "CVE-1.2.3"}
            context.AddOnStorage.SaveProperty("Joomla_V0001", vuln)

            let vuln = {Id = Guid.NewGuid(); Application = "Joomla"; AffectedVersions = ["3.4.3"]; VulnerabilityName = "Joomla 3.4.4 RCE"; Impact = "Medium"; ExternalReferer = "CVE-1.2.4"}
            context.AddOnStorage.SaveProperty("Joomla_V0002", vuln)
                        
        let ``Website fingerprinting``() =
            let webAppFingerprinterProfile = new ES.Taipan.Application.TemplateProfile(Id = Guid.Parse("4E813E5A-8738-4A86-B9F2-BC6E5023A7A9"), Name = "Fingerprint web application")        
            webAppFingerprinterProfile.RunWebAppFingerprinter <- true
            webAppFingerprinterProfile
            
        let createResources(resources: String list) =
            // create a fake dictionary file
            let dir = Path.Combine("Data", "Dictionaries")
            Directory.CreateDirectory(dir) |> ignore
            File.WriteAllText(Path.Combine(dir, "test.xml"), """ 
                <?xml version="1.0" encoding="UTF-8"?>
                <Dictionary>
	                <Id>A8EF3FFE-7CCF-4D1F-AA0A-2248DE6A0123</Id>
	                <Name>Test dictionary file</Name>
	                <Path>test.txt</Path>
                </Dictionary>
            """)

            let res = String.Join(Environment.NewLine, resources)
            File.WriteAllText(Path.Combine(dir, "test.txt"), res)

        let ``Website discovery``() =
            let discovererProfile = new ES.Taipan.Application.TemplateProfile(Id = Guid.Parse("51E0BF3F-759D-4454-9F53-C1FFDB835253"), Name = "Discover most common directories on web servers")        
            discovererProfile.RunResourceDiscoverer <- true
            discovererProfile.HttpRequestorSettings.UseJavascriptEngineForRequest <- false            
            discovererProfile.ResourceDiscovererSettings.Dictionaries.Add("A8EF3FFE-7CCF-4D1F-AA0A-2248DE6A0123")
            discovererProfile

        let ``Website crawling``() =
            let crawlerProfile = new ES.Taipan.Application.TemplateProfile(Id = Guid.Parse("54983E19-3CDE-4650-9494-5DA90EF87907"), Name = "Crawl web application")
            crawlerProfile.RunCrawler <- true  
            crawlerProfile.CrawlerSettings.Scope <- NavigationScope.EnteredPathAndBelow            
            crawlerProfile.CrawlerSettings.ActivateAllAddOns <- true
            crawlerProfile.CrawlerSettings.CrawlPageWithoutExtension <- true
            crawlerProfile.CrawlerSettings.CrawlOnlyPageWithTheSpecifiedExtensions <- false
            crawlerProfile.CrawlerSettings.HasLinkNavigationLimit <- false
            crawlerProfile.CrawlerSettings.WebPageExtensions.AddRange
                ([
                    ".flv"; ".docx"; "gif"; "jpeg"; "jpg"; "jpe"; "png"; "vis"; "tif"; "tiff"; "psd"; "bmp"; "ief"; "wbmp"; "ras"; "pnm"; "pbm"; "pgm"; "ppm"; 
                    "rgb"; "xbm"; "xpm"; "xwd"; "djv"; "djvu"; "iw4"; "iw44"; "fif"; "ifs"; "dwg"; "svf"; "wi"; "uff"; "mpg"; "mov"; "mpeg"; "mpeg2"; "avi"; 
                    "asf"; "asx"; "wmv"; "qt"; "movie"; "ice"; "viv"; "vivo"; "fvi"; "tar"; "tgz"; "gz"; "zip"; "jar"; "cab"; "hqx"; "arj"; "rar"; "rpm"; "ace"; 
                    "wav"; "vox"; "ra"; "rm"; "ram"; "wma"; "au"; "snd"; "mid"; "midi"; "kar"; "mpga"; "mp2"; "mp3"; "mp4"; "aif"; "aiff"; "aifc"; "es"; "esl"; 
                    "pac"; "pae"; "a3c"; "pdf"; "doc"; "xls"; "ppt"; "mp"; "msi"; "rmf"; "smi"; "bin"; "m4p"; "m4a"; "PS"; "EPS"; "svg"
                ])
            crawlerProfile.CrawlerSettings.ContentTypeToFilter.AddRange
                ([
                    "image/bmp"; "image/fif"; "image/gif"; "image/ief"; "image/jpeg"; "image/png"; "image/tiff"; "image/vasa"; "image/vnd.rn-realpix"; 
                    "image/x-cmu-raster"; "image/x-freehand"; "image/x-jps"; "image/x-portable-anymap"; "image/x-portable-bitmap"; "image/x-portable-graymap"; 
                    "image/x-portable-pixmap"; "image/x-rgb"; "image/x-xbitmap"; "image/x-xpixmap"; "image/x-xres"; "image/x-xwindowdump"; "video/animaflex"; 
                    "video/x-ms-asf"; "video/x-ms-asf-plugin"; "video/avi"; "video/msvideo"; "video/x-msvideo"; "video/avs-video"; "video/dl"; "video/x-dl"; 
                    "video/x-dv"; "video/fli"; "video/x-fli"; "video/x-atomic3d-feature"; "video/gl"; "video/x-gl"; "audio/x-gsm"; "video/x-isvideo"; "audio/nspaudio"; 
                    "audio/x-nspaudio"; "audio/mpeg"; "audio/x-mpequrl"; "x-music/x-midi"; "audio/midi"; "audio/x-mid"; "audio/x-midi"; "music/crescendo"; 
                    "audio/x-vnd.audioexplosion.mjuicemediafile"; "video/x-motion-jpeg"; "audio/mod"; "audio/x-mod"; "audio/x-mpeg"; "video/mpeg"; "video/x-mpeq2a"; 
                    "audio/mpeg3"; "audio/x-mpeg-3"; "video/x-mpeg"; "video/x-sgi-movie"; "audio/make"; "audio/vnd.qcelp"; "video/quicktime"; "video/x-qtc"; 
                    "audio/x-pn-realaudio"; "audio/x-pn-realaudio-plugin"; "audio/x-realaudio"; "audio/mid"; "video/vnd.rn-realvideo"; "audio/s3m"; "video/x-scm"; 
                    "audio/x-psid"; "audio/basic"; "audio/x-adpcm.tsi"; "audio/tsp-audio"; "audio/tsplayereb"; "video/vivo"; "video/vnd.vivo"; "video/vnd.vivodeo/vdo"; 
                    "audio/voc"; "audio/x-voc"; "video/vosaic"; "audio/voxware"; "audio/x-twinvq-plugin"; "audio/x-twinvq"; "audio/wav"; "audio/x-wav"; 
                    "video/x-amt-demorun"; "audio/xm"; "video/x-amt-showrun"
                ])
            
            // disable Javascript Engine
            crawlerProfile.HttpRequestorSettings.UseJavascriptEngineForRequest <- false

            // disable the Crawler parser
            crawlerProfile.CrawlerSettings.ActivateAllAddOns <- false
            crawlerProfile.CrawlerSettings.AddOnIdsToActivate.Clear()
            crawlerProfile.CrawlerSettings.AddOnIdsToActivate.AddRange
                ([
                    FormLinkScraper.AddOnId
                    HeaderRedirectLinkScraper.AddOnId
                    HyperLinkScraper.AddOnId
                    MetadataLinkScraper.AddOnId
                ])
            
            crawlerProfile

        let ``Website inspector``() =
            let inspectorProfile = new ES.Taipan.Application.TemplateProfile(Id = Guid.Parse("72383EB3-2873-466B-A400-2F83E796CD9D"), Name = "Identify vulnerabilities")
            inspectorProfile.RunVulnerabilityScanner <- true            
            inspectorProfile.RunCrawler <- true
            inspectorProfile.CrawlerSettings.Scope <- NavigationScope.EnteredPathAndBelow            
            inspectorProfile

        let ``Full template``() =
            let fullTemplate = ``Website crawling``()
            fullTemplate.Name <- "Full Scan Template"
            fullTemplate.ResourceDiscovererSettings <- ``Website discovery``().ResourceDiscovererSettings
            fullTemplate.RunResourceDiscoverer <- true
            fullTemplate.WebAppFingerprinterSettings <- ``Website fingerprinting``().WebAppFingerprinterSettings
            fullTemplate.RunWebAppFingerprinter <- true
            fullTemplate.VulnerabilityScannerSettings <- ``Website inspector``().VulnerabilityScannerSettings
            fullTemplate.RunVulnerabilityScanner <- true
            fullTemplate