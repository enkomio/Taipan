namespace ES.Taipan.Discoverer

open System

type IResourceRepository =
    interface
        abstract GetAllDictionaries: unit -> ResourceDictionary list
        abstract GetAllSelectedDictionaries: Guid list -> ResourceDictionary list
        abstract GetForbiddenDirectories: unit -> String list
    end

