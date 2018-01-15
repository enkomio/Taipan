namespace UnitTests

open System

module Program =

    [<EntryPoint>]
    let main argv = 
        RegexUtilityTests.run()
        CrawlerTests.run()
        HttpRequestorSettingsTests.run()
        0