namespace UnitTests

open System
open ES.Taipan.Crawler.WebScrapers
open ES.Taipan.Crawler
open ES.Taipan.Crawler.Utility
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Crawler

module HttpRequestorSettingsTests =
    
    let serializeJourneyScan() =
        let settings = new HttpRequestorSettings()
        let path = settings.Journey.CreatePath()
        
        let t = path.CreateTransaction()
        t.Index <- 0
        t.AddParameter("na\0me", "va\0lue", "query", true)
        t.TemplateRequest.Headers <- [("na\0me", "value")]                
        t.TemplateRequest.Method <- "POST"
        t.TemplateRequest.Uri <- "http://www.exmaple.com"
        t.TemplateResponse.Content <- "Some data with NULL character: " + Char.ConvertFromUtf32(0).ToString()

        let t = path.CreateTransaction()
        t.Index <- 1
        t.AddParameter("name1", "value1", "query", true)
        t.TemplateRequest.Headers <- [("name1", "value1")]
        t.TemplateResponse.Content <- "Some content"
        t.TemplateResponse.ResponseCode <- 12345

        let xml = settings.ToXml()
        if String.IsNullOrWhiteSpace(xml) then
            failwith("Unable to serialize Journey Scan Settings")

    let run() =
        serializeJourneyScan()