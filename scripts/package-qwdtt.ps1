param([string]$Version="0.1.0", [string]$Release="1", [string]$OutDir="dist/ipk")
$ErrorActionPreference="Stop"
$work=Join-Path $OutDir "work"
$env:GOCACHE = Join-Path (Get-Location) ".gocache"
$targets = & $PSScriptRoot\keenetic-targets.ps1 | ForEach-Object {
    @{Arch=$_.PackageArch; Bin=("dist/qwdtt-linux-"+$_.Name)}
}
function Write-Text($path,$text){$dir=Split-Path $path; New-Item -ItemType Directory -Force $dir | Out-Null; $normalized=$text -replace "`r`n","`n" -replace "`r","`n"; [IO.File]::WriteAllText($path,($normalized.TrimEnd()+"`n"),[Text.Encoding]::ASCII)}
New-Item -ItemType Directory -Force $OutDir | Out-Null
foreach($t in $targets){
 if(!(Test-Path $t.Bin)){throw "Missing binary: $($t.Bin)"}
 $pkg=Join-Path $work ("qwdtt_${Version}-${Release}_$($t.Arch)"); if(Test-Path $pkg){Remove-Item -LiteralPath $pkg -Recurse -Force}
 $data=Join-Path $pkg "data"; $control=Join-Path $pkg "control"
	# opkg runs against the router root filesystem; /opt is the writable
	# Entware prefix and therefore must remain part of every data path.
	New-Item -ItemType Directory -Force (Join-Path $data "opt/bin"),(Join-Path $data "opt/etc/init.d"),(Join-Path $data "opt/etc/ndm/netfilter.d"),(Join-Path $data "opt/etc/qwdtt"),$control | Out-Null
	Copy-Item $t.Bin (Join-Path $data "opt/bin/qwdtt")
	$init = (Get-Content "scripts/S99qwdtt" -Raw) -replace "`r`n", "`n" -replace "`r", "`n"
	[IO.File]::WriteAllText((Join-Path $data "opt/etc/init.d/S99qwdtt"), $init, [Text.Encoding]::ASCII)
	$hook = (Get-Content "scripts/60-qwdtt-netfilter.sh" -Raw) -replace "`r`n", "`n" -replace "`r", "`n"
	[IO.File]::WriteAllText((Join-Path $data "opt/etc/ndm/netfilter.d/60-qwdtt-netfilter.sh"), $hook, [Text.Encoding]::ASCII)
	Copy-Item "qwdtt.config.example.json" (Join-Path $data "opt/etc/qwdtt/config.example.json")
	Write-Text (Join-Path $control "control") "Package: qwdtt`nVersion: $Version-$Release`nArchitecture: $($t.Arch)`nMaintainer: qWDTT`nSection: net`nPriority: optional`nDepends: wireguard-tools, iptables`nDescription: qWDTT client and server for Keenetic routers."
	Write-Text (Join-Path $control "preinst") @'
#!/bin/sh
STATE=/tmp/qwdtt-opkg-was-running
rm -f "$STATE"
if pidof qwdtt >/dev/null 2>&1; then
    echo running > "$STATE"
    /opt/etc/init.d/S99qwdtt stop >/dev/null 2>&1 || killall qwdtt >/dev/null 2>&1 || true
    # The updater is started by qwdtt itself. Wait until the old process has
    # really exited so opkg/postinst can bind the web and DTLS ports cleanly.
    for WAIT in 1 2 3 4 5 6 7 8 9 10; do
        pidof qwdtt >/dev/null 2>&1 || break
        sleep 1
    done
    if pidof qwdtt >/dev/null 2>&1; then
        killall qwdtt >/dev/null 2>&1 || true
        sleep 1
    fi
fi
exit 0
'@
Write-Text (Join-Path $control "postinst") @'
#!/bin/sh
STATE=/tmp/qwdtt-opkg-was-running
if [ -f "$STATE" ]; then
    rm -f "$STATE"
fi

# Dependencies from control/Depends must be installed before postinst runs.
# Verify the complete installation before starting the service. Do not hide a
# failed check: opkg must report the installation as incomplete.
INIT=/opt/etc/init.d/S99qwdtt
CFG=/opt/etc/qwdtt/config.json
if [ ! -f "$CFG" ]; then
    cp /opt/etc/qwdtt/config.example.json "$CFG" || {
        echo "qWDTT could not create the initial config: $CFG" >&2
        exit 1
    }
    chmod 600 "$CFG"
fi
if ! "$INIT" check; then
    echo "qWDTT was installed but was not started: dependency check failed." >&2
    echo "Run '$INIT check' to see the failed checks." >&2
    exit 1
fi
if ! "$INIT" start; then
    echo "qWDTT installation completed, but automatic start failed." >&2
    exit 1
fi
WEB_PORT=$(sed -n 's/.*"webListen"[[:space:]]*:[[:space:]]*"[^:]*:\([0-9][0-9]*\)".*/\1/p' /opt/etc/qwdtt/config.json | head -n 1)
DTLS_PORT=$(sed -n 's/.*"dtlsPort"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' /opt/etc/qwdtt/config.json | awk '$1 + 0 > 0 { print; exit }')
[ -n "$WEB_PORT" ] || WEB_PORT=3333
[ -n "$DTLS_PORT" ] || DTLS_PORT=56000
LAN_IP=$(ip -4 addr show br0 2>/dev/null | sed -n 's/.*inet \([0-9.]*\)\/.*/\1/p' | head -n 1)
[ -n "$LAN_IP" ] || LAN_IP=0.0.0.0
echo "qWDTT started"
echo "Web panel: http://$LAN_IP:$WEB_PORT"
echo "DTLS: UDP $DTLS_PORT"
exit 0
'@
	Write-Text (Join-Path $control "prerm") @'
#!/bin/sh
# Keep configuration and network state intact while opkg replaces the package.
[ "$1" = "upgrade" ] && exit 0

INIT=/opt/etc/init.d/S99qwdtt
CFG=/opt/etc/qwdtt/config.json
NETWORK=10.66.0.0/16
WAN=br0
INTERFACE=wdtt0

if [ -f "$CFG" ]; then
    VALUE=$(sed -n 's/.*"network"[[:space:]]*:[[:space:]]*"\([^" ]*\)".*/\1/p' "$CFG" | head -n 1)
    [ -n "$VALUE" ] && NETWORK=$VALUE
    VALUE=$(sed -n 's/.*"wan"[[:space:]]*:[[:space:]]*"\([^" ]*\)".*/\1/p' "$CFG" | head -n 1)
    [ -n "$VALUE" ] && WAN=$VALUE
    VALUE=$(sed -n 's/.*"interface"[[:space:]]*:[[:space:]]*"\([^" ]*\)".*/\1/p' "$CFG" | head -n 1)
    [ -n "$VALUE" ] && INTERFACE=$VALUE
fi

if [ -x "$INIT" ]; then
    "$INIT" stop >/dev/null 2>&1 || true
else
    killall qwdtt >/dev/null 2>&1 || true
fi

# Remove both current profile chains and rules used by older releases.
iptables -D INPUT -i "$INTERFACE" -j QWDTT_PROFILE_IN 2>/dev/null || true
iptables -D FORWARD -i "$INTERFACE" -j QWDTT_PROFILE_FWD 2>/dev/null || true
iptables -F QWDTT_PROFILE_IN 2>/dev/null || true
iptables -F QWDTT_PROFILE_FWD 2>/dev/null || true
iptables -X QWDTT_PROFILE_IN 2>/dev/null || true
iptables -X QWDTT_PROFILE_FWD 2>/dev/null || true
iptables -D INPUT -i "$INTERFACE" -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i "$INTERFACE" -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -o "$INTERFACE" -j ACCEPT 2>/dev/null || true
iptables -t nat -D POSTROUTING -s "$NETWORK" -o "$WAN" -j MASQUERADE 2>/dev/null || true
iptables -t nat -D POSTROUTING -s "$NETWORK" -j MASQUERADE 2>/dev/null || true
[ "$WAN" = "br0" ] || iptables -t nat -D POSTROUTING -s "$NETWORK" -o br0 -j MASQUERADE 2>/dev/null || true
ip link del "$INTERFACE" 2>/dev/null || true
exit 0
'@
	Write-Text (Join-Path $control "postrm") @'
#!/bin/sh
# Never erase user data when this package is merely being upgraded/replaced.
[ "$1" = "upgrade" ] && exit 0

killall qwdtt >/dev/null 2>&1 || true
rm -rf /opt/etc/qwdtt
rm -f /opt/bin/qwdtt
rm -f /opt/etc/init.d/S99qwdtt
rm -f /opt/etc/ndm/netfilter.d/60-qwdtt-netfilter.sh
rm -f /tmp/qwdtt-opkg-was-running
rm -f /opt/tmp/qwdtt-update-*.ipk
rm -f /opt/tmp/qwdtt-update-runner-*.sh
rm -f /opt/tmp/qwdtt-update.log
exit 0
'@
	# config.json is created by postinst and intentionally is not registered as
	# an opkg conffile. This avoids resolve_conffiles warnings and keeps the
	# user's configuration untouched on reinstall/upgrade.
 Write-Text (Join-Path $pkg "debian-binary") "2.0"
	go run ./cmd/ipkpack -out (Join-Path $OutDir ("qwdtt_${Version}-${Release}_$($t.Arch)-kn.ipk")) -pkg $pkg
	if($LASTEXITCODE -ne 0){ throw "Packaging failed for $($t.Arch)" }
	Write-Host "Created package"
}
