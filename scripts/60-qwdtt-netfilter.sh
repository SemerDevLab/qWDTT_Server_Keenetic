#!/bin/sh
# qWDTT rules for Keenetic NDMS netfilter.d.
[ "$type" = "ip6tables" ] && exit 0
case "$table" in filter|nat) ;; *) exit 0 ;; esac

IPTABLES=/opt/sbin/iptables
[ -x "$IPTABLES" ] || IPTABLES=iptables
CFG=/opt/etc/qwdtt/config.json
[ -f "$CFG" ] || exit 0
pidof qwdtt >/dev/null 2>&1 || exit 0

NETWORK=$(sed -n 's/.*"network"[[:space:]]*:[[:space:]]*"\([^" ]*\)".*/\1/p' "$CFG" | head -1)
[ -n "$NETWORK" ] || NETWORK=10.66.66.0/24
WAN=$(sed -n 's/.*"wan"[[:space:]]*:[[:space:]]*"\([^" ]*\)".*/\1/p' "$CFG" | head -1)
[ -n "$WAN" ] || WAN=br0
# Config also contains client.dtlsPort=0. Select the first usable port, which
# is server.dtlsPort; profile copies that follow have the same shared value.
DTLS=$(sed -n 's/.*"dtlsPort"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$CFG" | awk '$1 + 0 > 0 { print; exit }')
[ -n "$DTLS" ] || DTLS=56000

run() { "$IPTABLES" -w "$@" 2>/dev/null || "$IPTABLES" "$@" 2>/dev/null; }

if [ "$table" = nat ]; then
	# The DTLS socket listens directly on all addresses. Drop the obsolete
	# same-port REDIRECT from older releases to avoid stale UDP conntrack NAT.
	run -t nat -D PREROUTING -p udp --dport "$DTLS" -j REDIRECT --to-ports "$DTLS" || true
	 run -t nat -C POSTROUTING -s "$NETWORK" -o "$WAN" -j MASQUERADE || \
	 run -t nat -A POSTROUTING -s "$NETWORK" -o "$WAN" -j MASQUERADE
	# The configured WAN can be the LAN bridge (br0), while the actual uplink
	# may be dynamically named. Keep NAT independent of the egress interface.
	run -t nat -C POSTROUTING -s "$NETWORK" -j MASQUERADE || \
		run -t nat -A POSTROUTING -s "$NETWORK" -j MASQUERADE
	if [ "$WAN" != br0 ]; then
		run -t nat -C POSTROUTING -s "$NETWORK" -o br0 -j MASQUERADE || \
		run -t nat -A POSTROUTING -s "$NETWORK" -o br0 -j MASQUERADE
	fi
else
	# Keep the DTLS exception ahead of Keenetic's terminal INPUT rejects.
	# Remove old/appended copies first so -C cannot hide a rule in the wrong
	# position after NDMS rebuilds the firewall.
	while run -D INPUT -p udp --dport "$DTLS" -j ACCEPT; do :; done
	run -I INPUT 1 -p udp --dport "$DTLS" -j ACCEPT
	run -N QWDTT_PROFILE_FWD || true
	run -N QWDTT_PROFILE_IN || true
	run -F QWDTT_PROFILE_FWD
	run -F QWDTT_PROFILE_IN
	run -C FORWARD -i wdtt0 -j QWDTT_PROFILE_FWD || run -I FORWARD 1 -i wdtt0 -j QWDTT_PROFILE_FWD
	run -C INPUT -i wdtt0 -j QWDTT_PROFILE_IN || run -I INPUT 1 -i wdtt0 -j QWDTT_PROFILE_IN
	INTERNET_IPS=$(awk '
		/"clientIP"/ {
			if (match($0, /[0-9][0-9.]*/)) ip=substr($0,RSTART,RLENGTH)
		}
		/"accessMode"[[:space:]]*:[[:space:]]*"internet"/ {
			if (ip != "") print ip
			ip=""
		}
	' "$CFG")
	for IP in $INTERNET_IPS; do
		# Keenetic can DNAT public DNS to its local resolver before filtering.
		# Permit DNS only; the router UI and all other LAN services stay closed.
		run -A QWDTT_PROFILE_FWD -s "$IP/32" -p udp --dport 53 -j ACCEPT
		run -A QWDTT_PROFILE_FWD -s "$IP/32" -p tcp --dport 53 -j ACCEPT
		run -A QWDTT_PROFILE_IN -s "$IP/32" -p udp --dport 53 -j ACCEPT
		run -A QWDTT_PROFILE_IN -s "$IP/32" -p tcp --dport 53 -j ACCEPT
		for NET in 172.16.0.0/12 192.168.0.0/16; do
			run -A QWDTT_PROFILE_FWD -s "$IP/32" -d "$NET" -j REJECT
			run -A QWDTT_PROFILE_IN -s "$IP/32" -d "$NET" -j REJECT
		done
	done
	run -A QWDTT_PROFILE_FWD -j RETURN
	run -A QWDTT_PROFILE_IN -j RETURN
	run -C FORWARD -i wdtt0 -j ACCEPT || run -A FORWARD -i wdtt0 -j ACCEPT
	run -C FORWARD -o wdtt0 -j ACCEPT || run -A FORWARD -o wdtt0 -j ACCEPT
	run -C INPUT -i wdtt0 -j ACCEPT || run -A INPUT -i wdtt0 -j ACCEPT
fi
exit 0
