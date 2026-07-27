param([string]$Version="", [string]$Release="", [switch]$Commit)
$ErrorActionPreference="Stop"

$statePath = Join-Path $PSScriptRoot "..\build-version.json"
if(Test-Path -LiteralPath $statePath){
    $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
} else {
    $state = [PSCustomObject]@{Version="0.1.0"; Release=0}
}

if(!$Version){
    $Version = [string]$state.Version
}

if(!$Release){
    if($Version -eq $state.Version){
        $Release = ([int]$state.Release + 1).ToString()
    } else {
        $Release = "1"
    }
} elseif($Version -eq $state.Version -and [int]$Release -le [int]$state.Release){
    throw "Release $Release is not newer than current release $($state.Release). Specify a newer release number."
}

if($Commit){
    [PSCustomObject]@{Version=$Version; Release=[int]$Release} |
        ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8
} else {
    Write-Output "$Version|$Release"
}
