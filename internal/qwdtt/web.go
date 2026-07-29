package qwdtt

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/skip2/go-qrcode"
)

func defaultRouteInterface() string {
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		// Skip the table header.
	}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 4 && fields[1] == "00000000" && fields[3] != "0000" {
			return fields[0]
		}
	}
	return ""
}

func WebHandler(cfg *Config, path string, logs *LogBook, runtime ...*Runtime) http.Handler {
	var rt *Runtime
	if len(runtime) > 0 {
		rt = runtime[0]
	}
	m := http.NewServeMux()
	auth := newWebAuth()
	var cfgMu sync.RWMutex
	currentConfig := func() Config {
		if rt != nil {
			return rt.Config()
		}
		cfgMu.RLock()
		defer cfgMu.RUnlock()
		return *cfg
	}
	requestedProfile := func(r *http.Request) (Config, ConnectionProfile, bool) {
		current := currentConfig()
		id := r.URL.Query().Get("id")
		if id == "" {
			return current, current.defaultProfile(), true
		}
		profile, ok := current.ProfileByID(id)
		return current, profile, ok
	}
	m.HandleFunc("GET /login", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(loginPage))
	})
	m.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		if err := authenticateKeenetic(ctx, r.FormValue("login"), r.FormValue("password")); err != nil {
			http.Redirect(w, r, "/login?error=1", http.StatusFound)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "qwdtt_session", Value: auth.create(), Path: "/", MaxAge: 7 * 24 * 60 * 60, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		http.Redirect(w, r, "/", http.StatusFound)
	})
	m.HandleFunc("GET /", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(webPage))
	})
	m.HandleFunc("GET /api/qwdtt/state", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Header().Set("Content-Type", "application/json")
		state := struct {
			Version        string                            `json:"version"`
			Config         Config                            `json:"config"`
			Running        bool                              `json:"running"`
			Traffic        TrafficSnapshot                   `json:"traffic"`
			ProfileTraffic map[string]ProfileTrafficSnapshot `json:"profileTraffic"`
		}{ServerVersion(), currentConfig(), rt != nil && rt.Running(), TrafficSnapshot{}, map[string]ProfileTrafficSnapshot{}}
		if rt != nil {
			state.Traffic = rt.traffic.Snapshot()
			state.ProfileTraffic = rt.profileTraffic.Snapshot()
		}
		_ = json.NewEncoder(w).Encode(state)
	})
	m.HandleFunc("GET /api/qwdtt/interfaces", func(w http.ResponseWriter, _ *http.Request) {
		interfaces, err := net.Interfaces()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out := make([]string, 0, len(interfaces))
		for _, iface := range interfaces {
			if iface.Name != "lo" && iface.Name != "wdtt0" {
				out = append(out, iface.Name)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	m.HandleFunc("GET /api/qwdtt/interface-ip", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		findIPv4 := func(iface *net.Interface, publicOnly bool) string {
			addrs, err := iface.Addrs()
			if err != nil {
				return ""
			}
			for _, addr := range addrs {
				var ip net.IP
				switch value := addr.(type) {
				case *net.IPNet:
					ip = value.IP
				case *net.IPAddr:
					ip = value.IP
				}
				if ipv4 := ip.To4(); ipv4 != nil && !ipv4.IsLoopback() && (!publicOnly || (ipv4.IsGlobalUnicast() && !ipv4.IsPrivate())) {
					return ipv4.String()
				}
			}
			return ""
		}
		routeInterfaceName := defaultRouteInterface()
		if routeInterfaceName != "" {
			if routeInterface, err := net.InterfaceByName(routeInterfaceName); err == nil {
				if ip := findIPv4(routeInterface, true); ip != "" {
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]string{"ip": ip, "interface": routeInterface.Name})
					return
				}
			}
		}
		if selected, err := net.InterfaceByName(name); err == nil {
			if ip := findIPv4(selected, true); ip != "" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{"ip": ip, "interface": selected.Name})
				return
			}
		}
		interfaces, err := net.Interfaces()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, iface := range interfaces {
			if iface.Name == "lo" || iface.Name == "wdtt0" {
				continue
			}
			if ip := findIPv4(&iface, true); ip != "" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{"ip": ip, "interface": iface.Name})
				return
			}
		}
		if routeInterfaceName != "" {
			if routeInterface, err := net.InterfaceByName(routeInterfaceName); err == nil {
				if ip := findIPv4(routeInterface, false); ip != "" {
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]string{"ip": ip, "interface": routeInterface.Name})
					return
				}
			}
		}
		if selected, err := net.InterfaceByName(name); err == nil {
			if ip := findIPv4(selected, false); ip != "" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{"ip": ip, "interface": selected.Name})
				return
			}
		}
		http.Error(w, "IPv4 address not found", http.StatusNotFound)
	})
	m.HandleFunc("GET /api/qwdtt/logs", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(logs.Snapshot())
	})
	m.HandleFunc("DELETE /api/qwdtt/logs", func(w http.ResponseWriter, _ *http.Request) {
		logs.Clear()
		w.WriteHeader(http.StatusNoContent)
	})
	m.HandleFunc("GET /api/qwdtt/link", func(w http.ResponseWriter, r *http.Request) {
		current, profile, ok := requestedProfile(r)
		if !ok {
			http.Error(w, "profile not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(current.ProfileLegacyLink(profile)))
	})
	m.HandleFunc("GET /api/qwdtt/link-qr", func(w http.ResponseWriter, r *http.Request) {
		// QR uses the query-style URI because the official client expects
		// named fields such as peer, hashes and pass. The legacy colon-based
		// URI can make the password look like another port to QR importers.
		current, profile, ok := requestedProfile(r)
		if !ok {
			http.Error(w, "profile not found", http.StatusNotFound)
			return
		}
		png, err := qrcode.Encode(current.ProfileQWDTTLink(profile), qrcode.Medium, 320)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(png)
	})
	m.HandleFunc("GET /api/qwdtt/qwdtt-link", func(w http.ResponseWriter, r *http.Request) {
		current, profile, ok := requestedProfile(r)
		if !ok {
			http.Error(w, "profile not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(current.ProfileQWDTTLink(profile)))
	})
	m.HandleFunc("GET /api/qwdtt/legacy-link", func(w http.ResponseWriter, r *http.Request) {
		current, profile, ok := requestedProfile(r)
		if !ok {
			http.Error(w, "profile not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(current.ProfileLegacyLink(profile)))
	})
	m.HandleFunc("POST /api/qwdtt/config", func(w http.ResponseWriter, r *http.Request) {
		var n Config
		if e := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&n); e != nil {
			http.Error(w, e.Error(), http.StatusBadRequest)
			return
		}
		var e error
		if rt != nil {
			e = rt.Update(n)
		} else {
			e = n.Validate()
			if e == nil {
				b, _ := json.MarshalIndent(n, "", "  ")
				e = os.WriteFile(path, append(b, '\n'), 0600)
				if e == nil {
					cfgMu.Lock()
					*cfg = n
					cfgMu.Unlock()
				}
			}
		}
		if e != nil {
			http.Error(w, e.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	m.HandleFunc("POST /api/qwdtt/toggle", func(w http.ResponseWriter, r *http.Request) {
		if rt == nil {
			http.Error(w, "runtime controller unavailable", http.StatusServiceUnavailable)
			return
		}
		var request struct {
			Enabled bool `json:"enabled"`
		}
		if e := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&request); e != nil {
			http.Error(w, e.Error(), http.StatusBadRequest)
			return
		}
		if e := rt.Toggle(request.Enabled); e != nil {
			http.Error(w, e.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","service":"qwdtt-server"}`))
	})
	attachUpdateEndpoints(m)
	return protectWeb(m, auth, currentConfig)
}

func protectWeb(next http.Handler, auth *webAuth, currentConfig func() Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webAuthEnabled := currentConfig().WebAuthEnabled()
		if r.URL.Path == "/login" && !webAuthEnabled {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		if r.URL.Path == "/login" || r.URL.Path == "/healthz" || !webAuthEnabled || auth.valid(r) {
			next.ServeHTTP(w, r)
			return
		}
		if r.Method == http.MethodGet {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

const loginPage = `<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>qWDTT — Вход</title><style>:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#080d18;color:#f1f5ff;font:14px system-ui,sans-serif}.login{width:min(360px,calc(100% - 28px));padding:24px;background:#131e32;border:1px solid #273650;border-radius:14px;box-shadow:0 24px 70px #0008}h1{font-size:23px;margin:0 0 5px;text-align:center}.muted{color:#8998b4;margin:0 0 26px;text-align:center}label{display:block;color:#b8c4dc;font-size:12px;font-weight:600;margin:12px 0 5px}input{display:block;width:100%;margin-top:7px;padding:10px;border:1px solid #2b3c5c;border-radius:8px;background:#0a1322;color:#fff}button{width:100%;margin-top:18px;padding:10px;border:0;border-radius:8px;background:#6d8dff;color:#fff;font-weight:700}.error{color:#ff657d;font-size:12px;margin:12px 0 0}</style><main class="login"><h1>qWDTT Server</h1><p class="muted">Войдите с учётной записью Keenetic</p><form method="post" action="/login"><label>Логин<input name="login" autocomplete="username" required autofocus></label><label>Пароль<input name="password" type="password" autocomplete="current-password" required></label><button type="submit">Войти</button></form><p class="error" id="error" hidden>Неверный логин или пароль</p></main><script>document.getElementById('error').hidden=!location.search.includes('error=1')</script>`

//go:embed web.html
var webPage string

const legacyWebPage = `<!doctype html>
<html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>qWDTT — управление</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#121a2b;--panel2:#182238;--line:#2a3855;--text:#e9eefb;--muted:#8e9bb5;--blue:#5b8cff;--green:#35d07f;--red:#ff647c;--shadow:0 18px 50px #02040b80}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 15% 0,#1a2d5c 0,transparent 36%),var(--bg);color:var(--text);font:14px/1.5 Inter,system-ui,-apple-system,Segoe UI,sans-serif}main{max-width:1160px;margin:auto;padding:28px 18px 46px}.top{display:flex;align-items:center;justify-content:space-between;gap:18px;margin-bottom:26px}.brand{display:flex;align-items:center;gap:13px}.logo{display:grid;place-items:center;width:44px;height:44px;border-radius:13px;background:linear-gradient(135deg,#6d9cff,#7466ff);font-weight:800;font-size:20px;box-shadow:0 8px 26px #526cff55}.brand h1{font-size:22px;margin:0}.brand p{color:var(--muted);margin:2px 0 0}.status{display:flex;align-items:center;gap:12px;background:#10192b;border:1px solid var(--line);border-radius:14px;padding:9px 11px 9px 15px}.dot{width:9px;height:9px;border-radius:50%;background:var(--red)}.dot.on{background:var(--green);box-shadow:0 0 0 4px #35d07f18}.status strong{font-weight:650}.btn{border:0;border-radius:9px;background:var(--blue);color:white;padding:9px 14px;font-weight:650;cursor:pointer;transition:.2s}.btn:hover{filter:brightness(1.12);transform:translateY(-1px)}.btn.small{padding:7px 10px;font-size:12px}.btn.secondary{background:#243452}.grid{display:grid;grid-template-columns:1.08fr .92fr;gap:18px}.card{background:linear-gradient(145deg,#141e32,#101827);border:1px solid var(--line);border-radius:16px;padding:20px;box-shadow:var(--shadow);margin-bottom:18px}fieldset{border:0;margin:0;padding:0}legend{color:var(--text);font-size:16px;font-weight:700;margin-bottom:15px}label{display:block;color:#bdc8df;font-size:12px;font-weight:600;margin:0 0 6px}input,select{box-sizing:border-box;width:100%;padding:10px 11px;background:#0c1424;border:1px solid #2b3a59;border-radius:9px;color:var(--text);outline:0}input:focus,select:focus{border-color:var(--blue);box-shadow:0 0 0 3px #5b8cff20}fieldset>label{margin:14px 0}.row{display:grid;grid-template-columns:1fr 1fr;gap:14px 16px}.status button{width:auto;margin:0;background:var(--blue)}.on{color:var(--green)}.off{color:#ffb454}pre{white-space:pre-wrap;word-break:break-all;background:#080d17;border:1px solid #263653;border-radius:10px;padding:13px;color:#a9f2bf;font:12px/1.65 ui-monospace,SFMono-Regular,Consolas,monospace}.card:has(pre){box-shadow:var(--shadow)}#links{color:#a9c5ff}.message{color:var(--green);font-size:12px}.footer{text-align:center;color:#60708d;font-size:11px;margin-top:22px}@media(max-width:820px){.grid{grid-template-columns:1fr}}@media(max-width:600px){main{padding:18px 12px 30px}.top{align-items:flex-start;flex-direction:column}.status{width:100%;justify-content:space-between}.row{grid-template-columns:1fr}.card{padding:16px}}
fieldset{background:linear-gradient(145deg,#141e32,#101827);border:1px solid var(--line);border-radius:16px;padding:20px;box-shadow:var(--shadow);margin:0 0 18px;min-width:0}legend{padding:0 8px}
</style>
<main><header class="top"><div class="brand"><div class="logo">q</div><div><h1>qWDTT Control</h1><p>Управление сервером туннеля</p></div></div><div class="status"><span id="dot" class="dot"></span><strong id="status">Проверка...</strong><button id="toggle">...</button></div></header>
<div class="status">Состояние: <strong id="status">—</strong><button id="toggle">—</button></div>
<form id="form">
<fieldset><legend>Основное</legend><div class="row">
<label>Включен <input id="enabled" type="checkbox"></label>
<label>Режим <select id="mode"><option value="server">server</option></select></label>
</div><label>Каталог данных <input id="dataDir" required></label><label>Web-порт <input id="webListen" required></label></fieldset>
<fieldset><legend>Сервер qWDTT</legend><div class="row">
<label>Публичный IP / DDNS <input id="publicHost" required></label><label>Адрес прослушивания DTLS <input id="listenAddr" required></label>
<label>DTLS-порт <input id="dtlsPort" type="number" min="1" max="65535" required></label><label>WireGuard-порт <input id="wgPort" type="number" min="1" max="65535" required></label>
</div><label>Пароль <input id="password" type="password" required></label><label>VK hash <input id="vkHash"></label><label>Сеть клиентов <input id="network" required></label></fieldset>
<fieldset><legend>Маршрутизация</legend><div class="row">
<label>Режим <select id="routeMode"><option value="all">Весь трафик</option><option value="selective">Выбранные сети</option></select></label><label>WAN-интерфейс <input id="wan" placeholder="br0, ppp0..."></label>
</div><label>Интерфейс WireGuard <input id="interface" required></label><label>Клиенты (IP через запятую) <input id="clients"></label><label>Сети CIDR (через запятую) <input id="networks"></label><label>DNS (через запятую) <input id="dns"></label></fieldset>
<button type="submit">Сохранить и применить</button>
</form>
<fieldset><legend>Ссылки для клиента</legend><pre id="links">—</pre></fieldset><pre id="message"></pre>
<fieldset><legend>Консоль сервера</legend><pre id="logs" style="height:260px;overflow:auto"></pre></fieldset>
<div class="footer">qWDTT • настройки сохраняются в конфигурации роутера</div></main><script>
const $=id=>document.getElementById(id), csv=a=>(a||[]).join(','); let dirty=false;
function set(id,v){$(id).value=v??''} function values(){return {enabled:$("enabled").checked,mode:$('mode').value,dataDir:$('dataDir').value,webListen:$('webListen').value,client:{},server:{publicHost:$('publicHost').value,listenAddr:$('listenAddr').value,dtlsPort:+$('dtlsPort').value,wgPort:+$('wgPort').value,password:$('password').value,network:$('network').value,vkHash:$('vkHash').value},routing:{mode:$('routeMode').value,interface:$('interface').value,wan:$('wan').value,clients:$('clients').value.split(',').map(x=>x.trim()).filter(Boolean),networks:$('networks').value.split(',').map(x=>x.trim()).filter(Boolean),dns:$('dns').value.split(',').map(x=>x.trim()).filter(Boolean)}}}
function fill(x){if(dirty)return;let c=x.config; $('enabled').checked=c.enabled;set('mode',c.mode);set('dataDir',c.dataDir);set('webListen',c.webListen);set('publicHost',c.server.publicHost);set('listenAddr',c.server.listenAddr);set('dtlsPort',c.server.dtlsPort||56000);set('wgPort',c.server.wgPort||56001);set('password',c.server.password);set('vkHash',c.server.vkHash);set('network',c.server.network);set('routeMode',c.routing.mode||'all');set('interface',c.routing.interface||'wdtt0');set('wan',c.routing.wan);set('clients',csv(c.routing.clients));set('networks',csv(c.routing.networks));set('dns',csv(c.routing.dns));$('status').textContent=x.running?'Сервер работает':'Сервер выключен';$('status').className='';$('dot').className='dot '+(x.running?'on':'');$('toggle').textContent=x.running?'Выключить':'Включить';$('toggle').onclick=()=>toggle(!x.running)}
async function load(){let x=await fetch('/api/qwdtt/state').then(r=>r.json());fill(x);let [a,b]=await Promise.all([fetch('/api/qwdtt/link').then(r=>r.text()),fetch('/api/qwdtt/qwdtt-link').then(r=>r.text())]);$('links').textContent='Основная ссылка (официальный клиент):\n'+a+'\n\nЭкспериментальный формат qwdtt://:\n'+b}
async function refreshStatus(){let x=await fetch('/api/qwdtt/state').then(r=>r.json());$('status').textContent=x.running?'Сервер работает':'Сервер выключен';$('status').className='';$('dot').className='dot '+(x.running?'on':'');$('toggle').textContent=x.running?'Выключить':'Включить';$('toggle').onclick=()=>toggle(!x.running)}
async function refreshLogs(){let x=await fetch('/api/qwdtt/logs',{cache:'no-store'}).then(r=>r.json());$('logs').textContent=(x||[]).map(e=>'['+new Date(e.time).toLocaleString()+'] '+e.level+' '+e.message).join('\\n');$('logs').scrollTop=$('logs').scrollHeight}
async function toggle(enabled){let r=await fetch('/api/qwdtt/toggle',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled})});$('message').textContent=r.ok?'Состояние изменено':'Ошибка: '+await r.text();if(r.ok)await refreshStatus()}
document.addEventListener('input',()=>dirty=true);document.addEventListener('change',()=>dirty=true);
$('form').onsubmit=async e=>{e.preventDefault();let r=await fetch('/api/qwdtt/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(values())});$('message').textContent=r.ok?'Настройки сохранены и применены':'Ошибка: '+await r.text();if(r.ok){dirty=false;await load()}};load();refreshLogs();setInterval(refreshLogs,2000)
</script>`
