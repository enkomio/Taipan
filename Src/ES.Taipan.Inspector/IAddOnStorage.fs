namespace ES.Taipan.Inspector

open System

type IAddOnStorage =
    interface
        abstract ReadProperty : String -> 'a option
        abstract GetProperties : ('a -> Boolean) -> 'a seq
        abstract SaveProperty : String * 'a -> unit
    end