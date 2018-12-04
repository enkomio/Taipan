namespace ES.Taipan.Infrastructure.Text

open System
open DiffLib

module TextUtility =
    let computeDifferenceRatio(text1: String, text2: String) =        
        let sections = Diff.CalculateSections(text1.ToCharArray(), text2.ToCharArray()) |> Seq.toList
        let lengthMatched = 
            sections 
            |> List.filter(fun section -> section.IsMatch)
            |> List.sumBy(fun section -> section.LengthInCollection1)

        let totalLength =
            sections 
            |> List.sumBy(fun section -> section.LengthInCollection1)
        
        float lengthMatched / float totalLength

