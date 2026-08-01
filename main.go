// pocketwg — a tiny WireGuard tunnel manager with a web UI, for headless and
// embedded Linux. Single static binary: serves a web UI (own login) to import
// .conf files, run multiple client tunnels, enable/disable them, and see live
// status. Also exposes a local unix socket for an on-device touch UI.
//
// Tunnels are driven directly via `wg` + `ip` (the kernel wireguard module does
// the work). State persists as JSON under PWG_DATA (default /var/lib/pocketwg).
//
// Copyright (C) 2026 Jacob Schooley
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Affero General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version. This program is distributed WITHOUT ANY WARRANTY. See the GNU
// Affero General Public License <https://www.gnu.org/licenses/> for details.
package main

import (
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/curve25519"
)

//go:embed web
var webFS embed.FS

var nameRE = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,15}$`) // valid tunnel/iface name

// ---------- persistent state ----------

type Tunnel struct {
	Name      string `json:"name"`
	Conf      string `json:"conf"`      // raw wg-quick-style config text
	Enabled   bool   `json:"enabled"`   // desired state (restored on start)
	Autostart bool   `json:"autostart"` // bring up at boot
}

type Store struct {
	AdminUser string             `json:"admin_user"`
	AdminHash string             `json:"admin_hash"` // bcrypt; empty until first-run setup
	Tunnels   map[string]*Tunnel `json:"tunnels"`
}

type App struct {
	mu       sync.Mutex
	store    Store
	dataPath string
	wgBin    string
	ipBin    string

	sessMu   sync.Mutex
	sessions map[string]time.Time // token -> expiry
}

func (a *App) load() error {
	b, err := os.ReadFile(a.dataPath)
	if errors.Is(err, os.ErrNotExist) {
		a.store = Store{Tunnels: map[string]*Tunnel{}}
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &a.store); err != nil {
		return err
	}
	if a.store.Tunnels == nil {
		a.store.Tunnels = map[string]*Tunnel{}
	}
	return nil
}

func (a *App) save() error {
	b, _ := json.MarshalIndent(a.store, "", "  ")
	tmp := a.dataPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, a.dataPath)
}

// ---------- wireguard .conf parsing ----------

type parsedConf struct {
	addresses []string // Interface Address = ...
	mtu       string
	wgConf    string // only the [Interface]/[Peer] keys that `wg setconf` accepts
	allowed   []string
}

// parseConf splits a wg-quick config into the `wg setconf` portion (crypto/peers)
// and the wg-quick-only interface bits (Address/DNS/MTU) that `ip` must apply.
func parseConf(conf string) parsedConf {
	var p parsedConf
	var out strings.Builder
	section := ""
	for _, raw := range strings.Split(conf, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			out.WriteString("[" + strings.Title(section) + "]\n")
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(k))
		val := strings.TrimSpace(v)
		if section == "interface" {
			switch key {
			case "address":
				for _, a := range strings.Split(val, ",") {
					if a = strings.TrimSpace(a); a != "" {
						p.addresses = append(p.addresses, a)
					}
				}
				continue // wg-quick-only; not for `wg setconf`
			case "dns":
				continue
			case "mtu":
				p.mtu = val
				continue
			case "privatekey", "listenport", "fwmark":
				out.WriteString(key + " = " + val + "\n")
			}
			continue
		}
		if section == "peer" {
			switch key {
			case "publickey", "presharedkey", "endpoint", "persistentkeepalive":
				out.WriteString(key + " = " + val + "\n")
			case "allowedips":
				out.WriteString("allowedips = " + val + "\n")
				for _, a := range strings.Split(val, ",") {
					if a = strings.TrimSpace(a); a != "" {
						p.allowed = append(p.allowed, a)
					}
				}
			}
		}
	}
	p.wgConf = out.String()
	return p
}

// ---------- tunnel control (wg + ip) ----------

func run(bin string, args ...string) (string, error) {
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %v: %s", bin, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func (a *App) up(t *Tunnel) error {
	p := parseConf(t.Conf)
	tmp, err := os.CreateTemp("", "wg-*.conf")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	tmp.WriteString(p.wgConf)
	tmp.Close()

	a.down(t) // idempotent: clear any stale iface
	if _, err := run(a.ipBin, "link", "add", "dev", t.Name, "type", "wireguard"); err != nil {
		return err
	}
	if _, err := run(a.wgBin, "setconf", t.Name, tmp.Name()); err != nil {
		a.down(t)
		return err
	}
	for _, addr := range p.addresses {
		fam := "-4"
		if strings.Contains(addr, ":") {
			fam = "-6"
		}
		run(a.ipBin, fam, "address", "add", addr, "dev", t.Name)
	}
	if p.mtu != "" {
		run(a.ipBin, "link", "set", "mtu", p.mtu, "dev", t.Name)
	}
	if _, err := run(a.ipBin, "link", "set", "up", "dev", t.Name); err != nil {
		a.down(t)
		return err
	}
	// v1 routing: add a device route for each non-default AllowedIP. Full-tunnel
	// (0.0.0.0/0) via policy routing is a later enhancement; skip 0.0.0.0/0 / ::/0.
	for _, cidr := range p.allowed {
		if cidr == "0.0.0.0/0" || cidr == "::/0" {
			continue
		}
		fam := "-4"
		if strings.Contains(cidr, ":") {
			fam = "-6"
		}
		run(a.ipBin, fam, "route", "add", cidr, "dev", t.Name)
	}
	return nil
}

func (a *App) down(t *Tunnel) error {
	run(a.ipBin, "link", "del", "dev", t.Name)
	return nil
}

// ensureModule loads the wireguard kernel module. On a normal distro the default
// `modprobe wireguard` works; embedded targets that ship a custom module set point
// PWG_MODLOAD at an insmod sequence. Run via `sh -c` so the value may be a
// multi-command load chain. Best-effort (ignored if WG is built-in).
func (a *App) ensureModule() {
	cmd := os.Getenv("PWG_MODLOAD")
	if cmd == "" {
		cmd = "modprobe wireguard"
	}
	if out, err := run("sh", "-c", cmd); err != nil {
		log.Printf("module load (%q): %v", cmd, strings.TrimSpace(out))
	}
}

// PeerStatus / TunnelStatus mirror `wg show <if> dump`.
type PeerStatus struct {
	PublicKey     string `json:"public_key"`
	Endpoint      string `json:"endpoint"`
	AllowedIPs    string `json:"allowed_ips"`
	LastHandshake int64  `json:"last_handshake"` // unix secs, 0 = never
	RxBytes       int64  `json:"rx_bytes"`
	TxBytes       int64  `json:"tx_bytes"`
}
type TunnelStatus struct {
	Name      string       `json:"name"`
	Up        bool         `json:"up"`
	ListenPort string      `json:"listen_port"`
	Peers     []PeerStatus `json:"peers"`
}

func (a *App) status(name string) TunnelStatus {
	st := TunnelStatus{Name: name}
	out, err := run(a.wgBin, "show", name, "dump")
	if err != nil {
		return st // iface not present => down
	}
	st.Up = true
	for i, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Split(line, "\t")
		if i == 0 { // interface: privkey pubkey listen-port fwmark
			if len(f) >= 3 {
				st.ListenPort = f[2]
			}
			continue
		}
		// peer dump fields: pubkey, psk, endpoint, allowed-ips, last-handshake, rx, tx, keepalive
		if len(f) < 8 {
			continue
		}
		hs, _ := strconv.ParseInt(f[4], 10, 64)
		rx, _ := strconv.ParseInt(f[5], 10, 64)
		tx, _ := strconv.ParseInt(f[6], 10, 64)
		st.Peers = append(st.Peers, PeerStatus{
			PublicKey:     f[0],
			Endpoint:      f[2],
			AllowedIPs:    f[3],
			LastHandshake: hs,
			RxBytes:       rx,
			TxBytes:       tx,
		})
	}
	return st
}

// keygen: WireGuard uses Curve25519. Private = clamped 32 random bytes; public = X25519(base).
func genKeypair() (priv, pub string) {
	var k [32]byte
	rand.Read(k[:])
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	pk, _ := curve25519.X25519(k[:], curve25519.Basepoint)
	return base64.StdEncoding.EncodeToString(k[:]), base64.StdEncoding.EncodeToString(pk)
}

// ---------- HTTP ----------

func (a *App) newSession() string {
	var b [24]byte
	rand.Read(b[:])
	tok := base64.RawURLEncoding.EncodeToString(b[:])
	a.sessMu.Lock()
	a.sessions[tok] = time.Now().Add(12 * time.Hour)
	a.sessMu.Unlock()
	return tok
}

func (a *App) validSession(r *http.Request) bool {
	c, err := r.Cookie("pocketwg_session")
	if err != nil {
		return false
	}
	a.sessMu.Lock()
	defer a.sessMu.Unlock()
	exp, ok := a.sessions[c.Value]
	if !ok || time.Now().After(exp) {
		delete(a.sessions, c.Value)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func (a *App) setupNeeded() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.store.AdminHash == ""
}

func (a *App) handleAuthState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"setup_needed": a.setupNeeded(), "authed": a.validSession(r)})
}

func (a *App) handleSetup(w http.ResponseWriter, r *http.Request) {
	if !a.setupNeeded() {
		writeJSON(w, 409, map[string]string{"error": "already configured"})
		return
	}
	var req struct{ User, Password string }
	json.NewDecoder(r.Body).Decode(&req)
	if len(req.User) < 1 || len(req.Password) < 8 {
		writeJSON(w, 400, map[string]string{"error": "username required, password >= 8 chars"})
		return
	}
	h, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	a.mu.Lock()
	a.store.AdminUser = req.User
	a.store.AdminHash = string(h)
	a.save()
	a.mu.Unlock()
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct{ User, Password string }
	json.NewDecoder(r.Body).Decode(&req)
	a.mu.Lock()
	user, hash := a.store.AdminUser, a.store.AdminHash
	a.mu.Unlock()
	if req.User != user || bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) != nil {
		time.Sleep(500 * time.Millisecond) // basic brute-force friction
		writeJSON(w, 401, map[string]string{"error": "invalid credentials"})
		return
	}
	tok := a.newSession()
	http.SetCookie(w, &http.Cookie{Name: "pocketwg_session", Value: tok, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("pocketwg_session"); err == nil {
		a.sessMu.Lock()
		delete(a.sessions, c.Value)
		a.sessMu.Unlock()
	}
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

// authed wraps a handler requiring a valid session.
func (a *App) authed(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.validSession(r) {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		h(w, r)
	}
}

func (a *App) tunnelsJSON() []map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	var list []map[string]any
	for _, t := range a.store.Tunnels {
		st := a.status(t.Name)
		list = append(list, map[string]any{"name": t.Name, "enabled": t.Enabled,
			"autostart": t.Autostart, "status": st})
	}
	return list
}

func (a *App) handleTunnels(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, map[string]any{"tunnels": a.tunnelsJSON()})
	case http.MethodPost: // import
		var req struct{ Name, Conf string }
		json.NewDecoder(r.Body).Decode(&req)
		req.Name = strings.TrimSpace(req.Name)
		if !nameRE.MatchString(req.Name) {
			writeJSON(w, 400, map[string]string{"error": "invalid name (a-z0-9_- , <=15 chars)"})
			return
		}
		if !strings.Contains(strings.ToLower(req.Conf), "[interface]") {
			writeJSON(w, 400, map[string]string{"error": "config missing [Interface]"})
			return
		}
		a.mu.Lock()
		a.store.Tunnels[req.Name] = &Tunnel{Name: req.Name, Conf: req.Conf}
		a.save()
		a.mu.Unlock()
		writeJSON(w, 200, map[string]string{"status": "ok"})
	default:
		w.WriteHeader(405)
	}
}

func (a *App) tunnelByPath(r *http.Request, suffix string) (*Tunnel, string) {
	name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/tunnels/"), suffix)
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.store.Tunnels[name], name
}

func (a *App) handleEnable(w http.ResponseWriter, r *http.Request) {
	t, name := a.tunnelByPath(r, "/enable")
	if t == nil {
		writeJSON(w, 404, map[string]string{"error": "no such tunnel: " + name})
		return
	}
	if err := a.up(t); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	a.mu.Lock()
	t.Enabled = true
	a.save()
	a.mu.Unlock()
	writeJSON(w, 200, map[string]string{"status": "up"})
}

func (a *App) handleDisable(w http.ResponseWriter, r *http.Request) {
	t, name := a.tunnelByPath(r, "/disable")
	if t == nil {
		writeJSON(w, 404, map[string]string{"error": "no such tunnel: " + name})
		return
	}
	a.down(t)
	a.mu.Lock()
	t.Enabled = false
	a.save()
	a.mu.Unlock()
	writeJSON(w, 200, map[string]string{"status": "down"})
}

func (a *App) handleDelete(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/tunnels/")
	a.mu.Lock()
	t := a.store.Tunnels[name]
	if t != nil {
		a.down(t)
		delete(a.store.Tunnels, name)
		a.save()
	}
	a.mu.Unlock()
	writeJSON(w, 200, map[string]string{"status": "deleted"})
}

func (a *App) handleGenkey(w http.ResponseWriter, r *http.Request) {
	priv, pub := genKeypair()
	writeJSON(w, 200, map[string]string{"private_key": priv, "public_key": pub})
}

// route /api/tunnels/<name>[/enable|/disable] (POST) and DELETE.
func (a *App) handleTunnelItem(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasSuffix(r.URL.Path, "/enable") && r.Method == http.MethodPost:
		a.handleEnable(w, r)
	case strings.HasSuffix(r.URL.Path, "/disable") && r.Method == http.MethodPost:
		a.handleDisable(w, r)
	case r.Method == http.MethodDelete:
		a.handleDelete(w, r)
	default:
		w.WriteHeader(405)
	}
}

// ---------- local unix socket for the touch UI (no auth; local root only) ----------

func (a *App) serveLocal(sockPath string) {
	os.Remove(sockPath)
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		log.Printf("local socket: %v", err)
		return
	}
	os.Chmod(sockPath, 0600)
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"tunnels": a.tunnelsJSON()})
	})
	mux.HandleFunc("/toggle", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		a.mu.Lock()
		t := a.store.Tunnels[name]
		a.mu.Unlock()
		if t == nil {
			writeJSON(w, 404, map[string]string{"error": "no such tunnel"})
			return
		}
		if t.Enabled {
			a.handleDisable(w, r)
		} else {
			a.handleEnable(w, r)
		}
	})
	log.Printf("local touch API on %s", sockPath)
	http.Serve(l, mux)
}

// restore brings up tunnels marked enabled (called at start).
func (a *App) restore() {
	a.mu.Lock()
	var toUp []*Tunnel
	for _, t := range a.store.Tunnels {
		if t.Enabled {
			toUp = append(toUp, t)
		}
	}
	a.mu.Unlock()
	for _, t := range toUp {
		if err := a.up(t); err != nil {
			log.Printf("restore %s: %v", t.Name, err)
		}
	}
}

func main() {
	// Generic defaults so the same binary runs on any Linux client; device-specific
	// deployments override via env in their init/service file, e.g.:
	//   PWG_DATA=/data/pocketwg  PWG_WG=/data/pocketwg/wg
	//   PWG_MODLOAD='insmod .../libchacha.ko; ...; insmod .../wireguard.ko'
	data := envOr("PWG_DATA", "/var/lib/pocketwg")
	httpAddr := envOr("PWG_HTTP", ":8088")
	sock := envOr("PWG_SOCK", filepath.Join(data, "pocketwg.sock"))
	wgBin := envOr("PWG_WG", "wg") // from PATH on a normal distro
	ipBin := envOr("PWG_IP", "ip")

	os.MkdirAll(data, 0700)
	app := &App{
		dataPath: filepath.Join(data, "pocketwg.json"),
		wgBin:    wgBin, ipBin: ipBin,
		sessions: map[string]time.Time{},
	}
	if err := app.load(); err != nil {
		log.Fatalf("load state: %v", err)
	}
	app.ensureModule()
	app.restore()
	go app.serveLocal(sock)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth", app.handleAuthState)
	mux.HandleFunc("/api/setup", app.handleSetup)
	mux.HandleFunc("/api/login", app.handleLogin)
	mux.HandleFunc("/api/logout", app.handleLogout)
	mux.HandleFunc("/api/genkey", app.authed(app.handleGenkey))
	mux.HandleFunc("/api/tunnels", app.authed(app.handleTunnels))
	mux.HandleFunc("/api/tunnels/", app.authed(app.handleTunnelItem))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}
		b, err := webFS.ReadFile("web/" + p)
		if err != nil {
			b, _ = webFS.ReadFile("web/index.html")
			p = "index.html"
		}
		w.Header().Set("Content-Type", contentType(p))
		w.Write(b)
	})

	log.Printf("pocketwg: http %s, data %s, wg %s", httpAddr, data, wgBin)
	log.Fatal(http.ListenAndServe(httpAddr, mux))
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func contentType(p string) string {
	switch {
	case strings.HasSuffix(p, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(p, ".js"):
		return "application/javascript"
	case strings.HasSuffix(p, ".css"):
		return "text/css"
	}
	return "text/plain"
}
