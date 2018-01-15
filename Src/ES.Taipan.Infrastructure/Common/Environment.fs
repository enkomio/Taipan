namespace ES.Taipan.Infrastructure.Common

open System
open System.Text
open System.Reflection

module Environment =
    let softwareVersion = 
        let execAssembly = Assembly.GetExecutingAssembly()
        let assemblyInfoVersion = execAssembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()
        if assemblyInfoVersion = null then execAssembly.GetName().Version.ToString()
        else assemblyInfoVersion.InformationalVersion