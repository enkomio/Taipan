namespace ES.Taipan.Inspector

open System

type IAddOnStorage =
    interface
        abstract ReadProperty : String -> 'a option
        abstract SaveProperty : String * 'a -> unit
    end