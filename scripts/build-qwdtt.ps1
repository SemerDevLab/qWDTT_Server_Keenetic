param([string]$Version="", [string]$Release="")
$ErrorActionPreference="Stop"
$targets = & $PSScriptRoot\keenetic-targets.ps1
if(!$Version -or !$Release){
  $buildState = Get-Content (Join-Path (Get-Location) "build-version.json") -Raw | ConvertFrom-Json
  if(!$Version){$Version=[string]$buildState.Version}
  if(!$Release){$Release=[string]$buildState.Release}
}
New-Item -ItemType Directory -Force -Path dist | Out-Null
$env:GOCACHE = Join-Path (Get-Location) ".gocache"
foreach($target in $targets){
	$env:CGO_ENABLED="0"; $env:GOOS="linux"; $env:GOARCH=$target.GOARCH; $env:GOARM=$target.GOARM; $env:GOMIPS=$target.GOMIPS
	$ldflags = "-s -w -X qwdtt/internal/qwdtt.BuildVersion=$Version -X qwdtt/internal/qwdtt.BuildRelease=$Release"
	go build -buildvcs=false -trimpath "-ldflags=$ldflags" -o ("dist/qwdtt-linux-"+$target.Name) ./cmd/qwdtt
	if($LASTEXITCODE -ne 0){ throw "Build failed for $($target.Name)" }
}
