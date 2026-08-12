// pocketwg — a tiny WireGuard tunnel manager with a web UI, for headless and
// embedded Linux. Single static binary: serves a web UI (own login) to import
// .conf files, run multiple client tunnels, enable/disable them, and see live
// status. Also exposes a local unix socket for an on-device touch UI.
//
// Tunnels are driven directly via `wg` + `ip` (the kernel wireguard module does
// the work). State persists as JSON under PWG_DATA (default /var/lib/pocketwg).
//
// # Copyright (C) 2026 Jacob Schooley
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
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/curve25519"
)

//go:embed web
var webFS embed.FS

var nameRE = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,15}$`) // valid tunnel/iface name

// ---------- persistent state ----------

type Tunnel struct {
	Name      string     `json:"name"`
	Conf      string     `json:"conf"`             // raw wg-quick-style config text
	Enabled   bool       `json:"enabled"`          // desired state (restored on start)
	Autostart bool       `json:"autostart"`        // bring up at boot
	Health    *HealthCfg `json:"health,omitempty"` // per-tunnel health-check override (nil -> global defaults)
}

// HealthCfg tunes the per-tunnel liveness watchdog. All fields optional; zero values fall
// back to the global defaults (PWG_HEALTH*). See monitorLoop for the detection logic.
type HealthCfg struct {
	Off   bool   `json:"off,omitempty"`   // disable health monitoring for this tunnel
	Probe string `json:"probe,omitempty"` // ping this IP through the tunnel each interval;
	// definitive + fast (~threshold*interval). If empty,
	// use handshake-staleness detection (zero-config).
	Interval int `json:"interval,omitempty"` // seconds between checks
	Stale    int `json:"stale,omitempty"`    // handshake-staleness threshold (handshake mode), seconds
}

// healthDefaults holds the process-wide defaults from PWG_HEALTH* env.
type healthDefaults struct {
	on       bool
	interval int
	stale    int
}

// resolvedHealth is the effective config for one tunnel (per-tunnel over global).
type resolvedHealth struct {
	off      bool
	probe    string
	interval int
	stale    int
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
	wggoBin  string // userspace WireGuard impl (wireguard-go / boringtun-cli)
	wggoArgs string // extra args before the iface name (e.g. boringtun: --disable-drop-privileges)
	backend  string // "kernel" (ip link add type wireguard) or "userspace" (TUN via wggoBin)

	dnsUp   string // PWG_DNS_UP: command to apply a tunnel's DNS= (else write /etc/resolv.conf directly)
	dnsDown string // PWG_DNS_DOWN: command to revert it

	opMu sync.Mutex // serializes tunnel up/down/restart so the health monitor can't race enable/disable

	health   healthDefaults
	monMu    sync.Mutex
	monitors map[string]chan struct{} // tunnel name -> stop signal for its health-monitor goroutine

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
	dns       []string // Interface DNS = ... (nameserver IPs)
	dnsSearch []string // Interface DNS = ... (non-IP entries -> search domains)
	table     string   // Interface Table = auto|off|<id> ("" == auto)
	saveConf  bool     // Interface SaveConfig = true (recognized; no-op here)
	preUp     []string // wg-quick hooks (run via sh -c, %i -> iface name)
	postUp    []string
	preDown   []string
	postDown  []string
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
				// IPs -> nameservers; anything else -> search domains (wg-quick semantics).
				for _, d := range strings.Split(val, ",") {
					if d = strings.TrimSpace(d); d == "" {
						continue
					}
					if net.ParseIP(d) != nil {
						p.dns = append(p.dns, d)
					} else {
						p.dnsSearch = append(p.dnsSearch, d)
					}
				}
				continue
			case "table":
				p.table = strings.ToLower(val)
				continue
			case "saveconfig":
				p.saveConf = strings.EqualFold(val, "true")
				continue
			case "mtu":
				p.mtu = val
				continue
			case "preup":
				p.preUp = append(p.preUp, val)
				continue
			case "postup":
				p.postUp = append(p.postUp, val)
				continue
			case "predown":
				p.preDown = append(p.preDown, val)
				continue
			case "postdown":
				p.postDown = append(p.postDown, val)
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

// runHook executes a wg-quick-style PreUp/PostUp/PreDown/PostDown command via `sh -c`,
// substituting %i with the interface name (as wg-quick does). Best-effort: a failing
// hook is logged but does not abort tunnel bring-up/tear-down.
func runHook(kind, iface, cmd string) {
	c := strings.ReplaceAll(cmd, "%i", iface)
	if out, err := run("sh", "-c", c); err != nil {
		log.Printf("%s hook (%s): %v", kind, iface, strings.TrimSpace(out))
	}
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

	a.teardownIface(t) // idempotent: clear any stale iface (no hooks)
	for _, h := range p.preUp {
		runHook("PreUp", t.Name, h)
	}
	// Create the WireGuard interface. Either backend leaves a device named t.Name that
	// `wg` configures identically (userspace impls expose the same UAPI socket).
	if a.backend == "userspace" {
		args := append(strings.Fields(a.wggoArgs), t.Name)
		if _, err := run(a.wggoBin, args...); err != nil {
			return fmt.Errorf("userspace backend (%s): %w", a.wggoBin, err)
		}
	} else {
		if _, err := run(a.ipBin, "link", "add", "dev", t.Name, "type", "wireguard"); err != nil {
			return err
		}
	}
	if _, err := run(a.wgBin, "setconf", t.Name, tmp.Name()); err != nil {
		a.teardownIface(t)
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
		a.teardownIface(t)
		return err
	}
	a.addRoutes(t, p)
	a.applyDNS(t, p)
	for _, h := range p.postUp {
		runHook("PostUp", t.Name, h)
	}
	return nil
}

// fwmarkFor returns a stable routing table id / fwmark for a tunnel, used for
// full-tunnel (Table=auto with a /0 AllowedIP). It is deliberately kept out of the
// device's fwmark bits (this platform runs WWAN policy routing under mask 0x35), so
// pick a base whose low bits don't overlap and offset by a hash of the name.
func fwmarkFor(name string) string {
	var h uint32 = 2166136261
	for i := 0; i < len(name); i++ { // FNV-1a, no rand (deterministic across restarts)
		h ^= uint32(name[i])
		h *= 16777619
	}
	// 0x8880 base (0x8880 & 0x35 == 0); vary in the high nibble only, still & 0x35 == 0.
	return strconv.Itoa(int(0x8880 + (h%8)*0x1000))
}

// addRoutes installs routes for the tunnel's AllowedIPs following wg-quick's Table rules:
//
//	Table=off      -> no routes;
//	Table=<id>     -> plain routes into that table;
//	Table=auto ("")-> plain routes, unless a default route (0.0.0.0/0 or ::/0) is present,
//	                  in which case use policy routing (fwmark + suppress_prefixlength) so
//	                  the encrypted WG packets themselves aren't looped back into the tunnel.
func (a *App) addRoutes(t *Tunnel, p parsedConf) {
	if p.table == "off" {
		return
	}
	hasV4Def, hasV6Def := false, false
	for _, c := range p.allowed {
		switch c {
		case "0.0.0.0/0":
			hasV4Def = true
		case "::/0":
			hasV6Def = true
		}
	}
	auto := p.table == "" || p.table == "auto"
	if auto && (hasV4Def || hasV6Def) {
		mark := fwmarkFor(t.Name)
		run(a.wgBin, "set", t.Name, "fwmark", mark)
		// Keep the encrypted WG packets out of the tunnel. The kernel backend marks its
		// own socket (SO_MARK=fwmark), so the `not fwmark` rule below diverts everything
		// EXCEPT those to the tunnel table. Userspace backends (boringtun) don't reliably
		// SO_MARK, so their unmarked handshake packets would match `not fwmark` and loop
		// back into the tunnel. Guard both cases by pinning a /32 host route to each peer
		// endpoint via the current WAN path, inside the tunnel table (more specific than
		// its default), so endpoint traffic always egresses the real uplink.
		for _, ip := range a.peerEndpoints(t.Name) {
			a.pinEndpointRoute(ip, mark)
		}
		for _, c := range p.allowed {
			fam := "-4"
			if strings.Contains(c, ":") {
				fam = "-6"
			}
			run(a.ipBin, fam, "route", "add", c, "dev", t.Name, "table", mark)
		}
		if hasV4Def {
			run("sysctl", "-wq", "net.ipv4.conf.all.src_valid_mark=1")
			run(a.ipBin, "-4", "rule", "add", "not", "fwmark", mark, "table", mark)
			run(a.ipBin, "-4", "rule", "add", "table", "main", "suppress_prefixlength", "0")
		}
		if hasV6Def {
			run(a.ipBin, "-6", "rule", "add", "not", "fwmark", mark, "table", mark)
			run(a.ipBin, "-6", "rule", "add", "table", "main", "suppress_prefixlength", "0")
		}
		return
	}
	for _, c := range p.allowed {
		if auto && (c == "0.0.0.0/0" || c == "::/0") {
			continue // no /0 handling outside the fwmark path
		}
		fam := "-4"
		if strings.Contains(c, ":") {
			fam = "-6"
		}
		args := []string{fam, "route", "add", c, "dev", t.Name}
		if !auto {
			args = append(args, "table", p.table)
		}
		run(a.ipBin, args...)
	}
}

// peerEndpoints returns the current resolved endpoint IPs for a tunnel's peers, as WG
// itself sees them (`wg show <iface> endpoints`), so the pinned route matches the exact
// address WG sends to (avoids re-resolving to a different round-robin answer).
func (a *App) peerEndpoints(iface string) []string {
	out, err := run(a.wgBin, "show", iface, "endpoints")
	if err != nil {
		return nil
	}
	var ips []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		if h, _, err := net.SplitHostPort(f[1]); err == nil && h != "" {
			ips = append(ips, h)
		}
	}
	return ips
}

// pinEndpointRoute installs a /32 (or /128) host route to ip via the current default path,
// into the given routing table, so encrypted WG packets to the peer bypass the tunnel.
func (a *App) pinEndpointRoute(ip, table string) {
	out, err := run(a.ipBin, "route", "get", ip)
	if err != nil {
		return
	}
	fields := strings.Fields(out)
	var gw, dev string
	for i := 0; i+1 < len(fields); i++ {
		switch fields[i] {
		case "via":
			gw = fields[i+1]
		case "dev":
			dev = fields[i+1]
		}
	}
	if dev == "" {
		return // couldn't determine egress; leave routing as-is
	}
	prefix := "/32"
	if strings.Contains(ip, ":") {
		prefix = "/128"
	}
	args := []string{"route", "replace", ip + prefix}
	if gw != "" {
		args = append(args, "via", gw)
	}
	args = append(args, "dev", dev, "table", table)
	run(a.ipBin, args...)
}

// runEnv runs a command via `sh -c` with extra environment (KEY=VALUE) appended to the
// process env. Used for the configurable DNS up/down hooks.
func runEnv(env []string, cmd string) (string, error) {
	c := exec.Command("sh", "-c", cmd)
	c.Env = append(os.Environ(), env...)
	out, err := c.CombinedOutput()
	if err != nil {
		return string(out), err
	}
	return string(out), nil
}

// applyDNS points the resolver at the tunnel's DNS servers (wg-quick DNS=). Default: back up
// /etc/resolv.conf once and write it directly (restoreDNS puts it back). If PWG_DNS_UP is set,
// run that instead — it receives WG_TUNNEL / WG_DNS (space-separated nameservers) / WG_DNS_SEARCH
// in the environment, so a deployment can apply DNS however it likes (e.g. a LAN dnsmasq, resolvconf).
func (a *App) applyDNS(t *Tunnel, p parsedConf) {
	if len(p.dns) == 0 {
		return
	}
	if a.dnsUp != "" {
		env := []string{
			"WG_TUNNEL=" + t.Name,
			"WG_DNS=" + strings.Join(p.dns, " "),
			"WG_DNS_SEARCH=" + strings.Join(p.dnsSearch, " "),
		}
		if out, err := runEnv(env, a.dnsUp); err != nil {
			log.Printf("dns-up hook (%s): %v: %s", t.Name, err, strings.TrimSpace(out))
		}
		return
	}
	bak := a.resolvBak(t)
	if _, err := os.Stat(bak); err != nil {
		if cur, err := os.ReadFile("/etc/resolv.conf"); err == nil {
			os.WriteFile(bak, cur, 0644)
		}
	}
	var b strings.Builder
	b.WriteString("# pocketwg: DNS for " + t.Name + "\n")
	for _, s := range p.dnsSearch {
		b.WriteString("search " + s + "\n")
	}
	for _, ns := range p.dns {
		b.WriteString("nameserver " + ns + "\n")
	}
	if err := os.WriteFile("/etc/resolv.conf", []byte(b.String()), 0644); err != nil {
		log.Printf("applyDNS %s: %v", t.Name, err)
	}
}

func (a *App) restoreDNS(t *Tunnel) {
	if a.dnsDown != "" {
		if out, err := runEnv([]string{"WG_TUNNEL=" + t.Name}, a.dnsDown); err != nil {
			log.Printf("dns-down hook (%s): %v: %s", t.Name, err, strings.TrimSpace(out))
		}
		return
	}
	bak := a.resolvBak(t)
	if data, err := os.ReadFile(bak); err == nil {
		os.WriteFile("/etc/resolv.conf", data, 0644)
		os.Remove(bak)
	}
}

func (a *App) resolvBak(t *Tunnel) string {
	return filepath.Join(filepath.Dir(a.dataPath), "resolv."+t.Name+".bak")
}

// cleanupStaleDNS restores /etc/resolv.conf from any leftover backup at startup. A backup
// only survives if a tunnel with DNS= was brought up but never cleanly torn down (crash,
// kill, reboot). If left in place, the next bring-up's `wg setconf` would try to resolve
// the peer Endpoint via a resolver that's only reachable *through* the not-yet-up tunnel,
// deadlocking. Restoring first guarantees the endpoint resolves via the real upstream.
func (a *App) cleanupStaleDNS() {
	if a.dnsDown != "" {
		// command mode: best-effort clear of any DNS left applied by an unclean prior shutdown
		runEnv([]string{"WG_TUNNEL="}, a.dnsDown)
		return
	}
	dir := filepath.Dir(a.dataPath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		n := e.Name()
		if strings.HasPrefix(n, "resolv.") && strings.HasSuffix(n, ".bak") {
			bak := filepath.Join(dir, n)
			if data, err := os.ReadFile(bak); err == nil {
				os.WriteFile("/etc/resolv.conf", data, 0644)
				log.Printf("restored /etc/resolv.conf from stale %s", n)
			}
			os.Remove(bak)
		}
	}
}

// teardownIface removes the WireGuard interface (and, for the userspace backend, its
// engine + UAPI socket) plus any full-tunnel policy-routing rules it may have added.
// It runs NO hooks — up() uses it for the idempotent pre-clear. Deleting the link drops
// its routes (including in the custom table), but ip rules are not link-scoped, so remove
// them here by the tunnel's deterministic fwmark. Best-effort: absent rules just no-op.
func (a *App) teardownIface(t *Tunnel) {
	run(a.ipBin, "link", "del", "dev", t.Name)
	mark := fwmarkFor(t.Name)
	for _, fam := range []string{"-4", "-6"} {
		run(a.ipBin, fam, "rule", "del", "not", "fwmark", mark, "table", mark)
		run(a.ipBin, fam, "rule", "del", "table", "main", "suppress_prefixlength", "0")
		run(a.ipBin, fam, "route", "flush", "table", mark) // drop default + pinned endpoint /32
	}
	if a.backend == "userspace" {
		// tear down the userspace impl + its UAPI socket. `ip link del` removes the TUN,
		// which normally makes the engine exit, but kill it explicitly too: a lingering
		// boringtun keeps ownership of the UAPI socket, so the next bring-up starts a
		// second instance that fights it for the socket/TUN and wedges the tunnel (tx=0).
		killByCmdline(a.wggoBin, t.Name)
		os.Remove("/var/run/wireguard/" + t.Name + ".sock")
	}
}

// killByCmdline SIGKILLs every process whose /proc cmdline contains all the given
// substrings. Replaces a dependency on pkill, which minimal userlands (busybox without
// procps) don't ship — a missing pkill silently no-ops and lets stale engines pile up.
func killByCmdline(subs ...string) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	self := os.Getpid()
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		data, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err != nil {
			continue
		}
		cmd := strings.ReplaceAll(string(data), "\x00", " ")
		match := true
		for _, s := range subs {
			if !strings.Contains(cmd, s) {
				match = false
				break
			}
		}
		if match {
			syscall.Kill(pid, syscall.SIGKILL)
		}
	}
}

func (a *App) down(t *Tunnel) error {
	p := parseConf(t.Conf)
	for _, h := range p.preDown {
		runHook("PreDown", t.Name, h)
	}
	a.restoreDNS(t)
	a.teardownIface(t)
	for _, h := range p.postDown {
		runHook("PostDown", t.Name, h)
	}
	return nil
}

// ---------- per-tunnel health monitor (self-healing) ----------
//
// WireGuard never rebinds its source port on its own: if the path dies while the same
// UDP mapping is expected (classic CGNAT teardown — the client keeps sending, the peer
// never answers), the tunnel stays wedged forever. This monitor watches each up tunnel
// and, when it looks dead, restarts it (down+up) so the engine rebinds a fresh source
// port and re-resolves the endpoint — the only thing that recovers that state.
//
// Detection (per tick):
//   - Probe mode (Health.Probe set): ping that IP through the tunnel; N consecutive
//     failures => dead. Definitive and fast (~N*interval); needs a reachable in-tunnel IP.
//   - Handshake mode (default, zero-config): a tunnel that's up but whose last handshake is
//     stale (or never happened) while it's actively trying to send is wedged. Uses WG's own
//     state (`wg show dump`), so no probe target required. Idle tunnels (no tx) are left alone.

func (a *App) healthCfg(t *Tunnel) resolvedHealth {
	r := resolvedHealth{off: !a.health.on, interval: a.health.interval, stale: a.health.stale}
	if h := t.Health; h != nil {
		if h.Off {
			r.off = true
		}
		if h.Probe != "" {
			r.probe = h.Probe
		}
		if h.Interval > 0 {
			r.interval = h.Interval
		}
		if h.Stale > 0 {
			r.stale = h.Stale
		}
	}
	if r.interval <= 0 {
		r.interval = 15
	}
	if r.stale <= 0 {
		r.stale = 150
	}
	return r
}

// startMonitor (re)starts the health goroutine for a tunnel. Idempotent: any existing
// monitor for the name is stopped first, so it's safe to call on every up/adopt.
func (a *App) startMonitor(t *Tunnel) {
	cfg := a.healthCfg(t)
	if cfg.off {
		return
	}
	a.monMu.Lock()
	if old, ok := a.monitors[t.Name]; ok {
		close(old)
		delete(a.monitors, t.Name)
	}
	stop := make(chan struct{})
	a.monitors[t.Name] = stop
	a.monMu.Unlock()
	go a.monitorLoop(t, cfg, stop)
}

func (a *App) stopMonitor(name string) {
	a.monMu.Lock()
	if ch, ok := a.monitors[name]; ok {
		close(ch)
		delete(a.monitors, name)
	}
	a.monMu.Unlock()
}

// pingThrough pings target, which is expected to route through the tunnel (it's in the
// tunnel's AllowedIPs). Best-effort: any error (unreachable, no ping binary) counts as down.
func (a *App) pingThrough(target string) bool {
	_, err := run("ping", "-c", "1", "-W", "3", target)
	return err == nil
}

func (a *App) monitorLoop(t *Tunnel, cfg resolvedHealth, stop chan struct{}) {
	iv := time.Duration(cfg.interval) * time.Second
	// grace: let the tunnel handshake before the first check (and after each restart)
	select {
	case <-stop:
		return
	case <-time.After(iv):
	}
	var lastTx int64 = -1
	fails := 0
	// probe mode needs ~THRESHOLD fails; handshake mode confirms staleness over a couple ticks
	probeThresh, hsThresh := 8, 2
	for {
		select {
		case <-stop:
			return
		default:
		}
		st := a.status(t.Name)
		if !st.Up {
			// not up (mid-restart or externally torn down) — don't act, just wait
			fails, lastTx = 0, -1
			select {
			case <-stop:
				return
			case <-time.After(iv):
			}
			continue
		}
		var peer PeerStatus
		if len(st.Peers) > 0 {
			peer = st.Peers[0]
		}
		dead := false
		if cfg.probe != "" {
			if a.pingThrough(cfg.probe) {
				fails = 0
			} else {
				fails++
			}
			dead = fails >= probeThresh
		} else {
			neverHS := peer.LastHandshake == 0
			stale := neverHS || time.Now().Unix()-peer.LastHandshake >= int64(cfg.stale)
			sending := lastTx >= 0 && peer.TxBytes > lastTx // outbound traffic since last check
			if stale && (neverHS || sending) {
				fails++
			} else {
				fails = 0
			}
			lastTx = peer.TxBytes
			dead = fails >= hsThresh
		}
		if dead {
			log.Printf("health[%s]: unresponsive -> restarting for a new source port", t.Name)
			a.restartHealth(t, stop)
			fails, lastTx = 0, -1
			// grace after restart before resuming checks
			select {
			case <-stop:
				return
			case <-time.After(iv):
			}
			continue
		}
		select {
		case <-stop:
			return
		case <-time.After(iv):
		}
	}
}

// restartHealth cycles a tunnel (down+up) under opMu so it can't interleave with a
// user-driven enable/disable. It re-checks the stop signal so a disable that fired while
// we were waiting on opMu wins (leaves the tunnel down instead of resurrecting it).
func (a *App) restartHealth(t *Tunnel, stop chan struct{}) {
	a.opMu.Lock()
	defer a.opMu.Unlock()
	select {
	case <-stop:
		return // disabled while we waited for the lock — don't bring it back
	default:
	}
	a.down(t)
	if err := a.up(t); err != nil {
		log.Printf("health[%s]: restart failed: %v", t.Name, err)
	}
}

// ensureModule loads the wireguard kernel module. On a normal distro the default
// `modprobe wireguard` works; embedded targets that ship a custom module set point
// PWG_MODLOAD at an insmod sequence. Run via `sh -c` so the value may be a
// multi-command load chain. Best-effort (ignored if WG is built-in).
func (a *App) ensureModule() {
	if a.backend == "userspace" {
		return // userspace impl uses TUN; no wireguard kernel module needed
	}
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
	Name       string       `json:"name"`
	Up         bool         `json:"up"`
	ListenPort string       `json:"listen_port"`
	Peers      []PeerStatus `json:"peers"`
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
	names := make([]string, 0, len(a.store.Tunnels))
	for n := range a.store.Tunnels {
		names = append(names, n)
	}
	sort.Strings(names) // stable, name-sorted order (map iteration is random otherwise)
	list := make([]map[string]any, 0, len(names))
	for _, n := range names {
		t := a.store.Tunnels[n]
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

// enableTunnel/disableTunnel are the core state transitions, shared by the HTTP API and
// the local touch socket (so both drive the same up()/down() + persist path).
func (a *App) enableTunnel(t *Tunnel) error {
	a.opMu.Lock()
	err := a.up(t)
	a.opMu.Unlock()
	if err != nil {
		return err
	}
	a.mu.Lock()
	t.Enabled = true
	a.save()
	a.mu.Unlock()
	a.startMonitor(t) // self-healing watchdog for as long as it's up
	return nil
}

func (a *App) disableTunnel(t *Tunnel) {
	a.stopMonitor(t.Name) // stop watching BEFORE tearing down so it can't restart it
	a.opMu.Lock()
	a.down(t)
	a.opMu.Unlock()
	a.mu.Lock()
	t.Enabled = false
	a.save()
	a.mu.Unlock()
}

func (a *App) handleEnable(w http.ResponseWriter, r *http.Request) {
	t, name := a.tunnelByPath(r, "/enable")
	if t == nil {
		writeJSON(w, 404, map[string]string{"error": "no such tunnel: " + name})
		return
	}
	if err := a.enableTunnel(t); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{"status": "up"})
}

func (a *App) handleDisable(w http.ResponseWriter, r *http.Request) {
	t, name := a.tunnelByPath(r, "/disable")
	if t == nil {
		writeJSON(w, 404, map[string]string{"error": "no such tunnel: " + name})
		return
	}
	a.disableTunnel(t)
	writeJSON(w, 200, map[string]string{"status": "down"})
}

func (a *App) handleDelete(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/tunnels/")
	a.stopMonitor(name)
	a.mu.Lock()
	t := a.store.Tunnels[name]
	a.mu.Unlock()
	if t != nil {
		a.opMu.Lock()
		a.down(t)
		a.opMu.Unlock()
		a.mu.Lock()
		delete(a.store.Tunnels, name)
		a.save()
		a.mu.Unlock()
	}
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
	case strings.HasSuffix(r.URL.Path, "/config") && r.Method == http.MethodGet:
		a.handleGetConfig(w, r)
	case r.Method == http.MethodPut:
		a.handleUpdate(w, r)
	case r.Method == http.MethodDelete:
		a.handleDelete(w, r)
	default:
		w.WriteHeader(405)
	}
}

// handleGetConfig returns a tunnel's raw config for editing.
func (a *App) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/tunnels/"), "/config")
	a.mu.Lock()
	t := a.store.Tunnels[name]
	a.mu.Unlock()
	if t == nil {
		writeJSON(w, 404, map[string]string{"error": "no such tunnel: " + name})
		return
	}
	writeJSON(w, 200, map[string]string{"name": t.Name, "conf": t.Conf})
}

// handleUpdate replaces a tunnel's config; if it's currently enabled, re-applies it live.
func (a *App) handleUpdate(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/tunnels/")
	var req struct{ Conf string }
	json.NewDecoder(r.Body).Decode(&req)
	if !strings.Contains(strings.ToLower(req.Conf), "[interface]") {
		writeJSON(w, 400, map[string]string{"error": "config missing [Interface]"})
		return
	}
	a.mu.Lock()
	t := a.store.Tunnels[name]
	if t == nil {
		a.mu.Unlock()
		writeJSON(w, 404, map[string]string{"error": "no such tunnel: " + name})
		return
	}
	t.Conf = req.Conf
	wasEnabled := t.Enabled
	a.save()
	a.mu.Unlock()
	if wasEnabled { // re-apply live so the edit takes effect immediately
		a.stopMonitor(t.Name)
		a.opMu.Lock()
		a.down(t)
		err := a.up(t)
		a.opMu.Unlock()
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "saved, but re-apply failed: " + err.Error()})
			return
		}
		a.startMonitor(t) // pick up any changed health config
	}
	writeJSON(w, 200, map[string]string{"status": "ok"})
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
			a.disableTunnel(t)
			writeJSON(w, 200, map[string]string{"status": "down"})
		} else {
			if err := a.enableTunnel(t); err != nil {
				writeJSON(w, 500, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, 200, map[string]string{"status": "up"})
		}
	})
	log.Printf("local touch API on %s", sockPath)
	http.Serve(l, mux)
}

// ifaceUp reports whether a network interface with this name currently exists.
func (a *App) ifaceUp(name string) bool {
	_, err := run(a.ipBin, "link", "show", name)
	return err == nil
}

// reconcile makes the live interface state match the desired (enabled) state at startup.
// It's called on every pocketwg start, so it must handle three cases without disrupting
// what's already correct:
//   - enabled + already up  -> ADOPT it (leave the working interface + its rules alone);
//   - enabled + down         -> bring it up (auto-start what was enabled);
//   - disabled + up          -> tear down the orphan (e.g. a tunnel left running when a
//     previous pocketwg died — its engine/interface outlive it).
//
// Adopting matters: a bare restart of pocketwg shouldn't flap a healthy tunnel.
func (a *App) reconcile() {
	a.mu.Lock()
	names := make([]string, 0, len(a.store.Tunnels))
	for n := range a.store.Tunnels {
		names = append(names, n)
	}
	sort.Strings(names)
	tunnels := make([]*Tunnel, 0, len(names))
	for _, n := range names {
		tunnels = append(tunnels, a.store.Tunnels[n])
	}
	a.mu.Unlock()
	for _, t := range tunnels {
		up := a.ifaceUp(t.Name)
		switch {
		case t.Enabled && !up:
			if err := a.up(t); err != nil {
				log.Printf("reconcile: bring up %s: %v", t.Name, err)
			} else {
				log.Printf("reconcile: started %s (was enabled)", t.Name)
				a.startMonitor(t)
			}
		case t.Enabled && up:
			log.Printf("reconcile: adopted already-up %s", t.Name)
			a.startMonitor(t)
		case !t.Enabled && up:
			log.Printf("reconcile: tore down orphaned %s (disabled but up)", t.Name)
			a.down(t)
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
	// Backend: "kernel" uses the in-kernel wireguard netdev (ip link add type wireguard);
	// "userspace" runs a userspace impl (wireguard-go/boringtun) over TUN — same `wg`
	// control plane, no kernel module needed. Useful where wireguard.ko is unavailable
	// or ABI-incompatible with the running kernel.
	backend := envOr("PWG_WG_BACKEND", "kernel")
	wggoBin := envOr("PWG_WGGO", "wireguard-go")
	// Extra args for the userspace impl, before the interface name. boringtun needs
	// "--disable-drop-privileges" on systems where dropping to nobody fails; wireguard-go
	// takes none. Space-separated.
	wggoArgs := envOr("PWG_WGGO_ARGS", "")
	// Optional DNS apply/revert commands (wg-quick DNS=). Default writes /etc/resolv.conf; set these to
	// apply DNS elsewhere (LAN dnsmasq, resolvconf, ...). The up cmd gets WG_TUNNEL/WG_DNS/WG_DNS_SEARCH env.
	dnsUp := envOr("PWG_DNS_UP", "")
	dnsDown := envOr("PWG_DNS_DOWN", "")
	// Self-healing health monitor defaults (per-tunnel override via the tunnel's "health" field).
	// PWG_HEALTH=off disables it globally. Handshake-staleness detection by default (zero-config);
	// set a per-tunnel Health.Probe for faster, definitive ping-through-tunnel detection.
	health := healthDefaults{
		on:       envOr("PWG_HEALTH", "on") != "off",
		interval: envInt("PWG_HEALTH_INTERVAL", 15),
		stale:    envInt("PWG_HEALTH_STALE", 150),
	}

	os.MkdirAll(data, 0700)
	app := &App{
		dataPath: filepath.Join(data, "pocketwg.json"),
		wgBin:    wgBin, ipBin: ipBin, wggoBin: wggoBin, wggoArgs: wggoArgs, backend: backend,
		dnsUp: dnsUp, dnsDown: dnsDown,
		sessions: map[string]time.Time{},
		monitors: map[string]chan struct{}{},
		health:   health,
	}
	if err := app.load(); err != nil {
		log.Fatalf("load state: %v", err)
	}
	app.ensureModule()
	app.cleanupStaleDNS() // undo any DNS poison from an unclean prior shutdown, before bring-up
	app.reconcile()       // start enabled tunnels, adopt already-up ones, clean orphans
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

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
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
