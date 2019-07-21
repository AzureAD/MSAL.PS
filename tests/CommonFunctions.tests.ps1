
Remove-Module CommonFunctions -ErrorAction SilentlyContinue
Import-Module ..\**\CommonFunctions.psm1

Resolve-FullPath "*.ps*1" -BaseDirectory "..\" -Recurse
Resolve-FullPath "src" -BaseDirectory "..\" -Recurse
Resolve-FullPath "*.json" -RecurseUp
