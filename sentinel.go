package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ─── Config ──────────────────────────────────────────────────────────────────

const (
	confFile = "/etc/openpanel/openpanel/conf/openpanel.config"
	iniFile  = "/etc/openpanel/openadmin/config/notifications.ini"
	lockFile = "/tmp/swap_cleanup.lock"
	logFile  = "/var/log/openpanel/admin/notifications.log"
	version  = "20.251.104-go"
)

type Config struct {
	Email          string
	EmailAlert     bool
	Reboot         bool
	DNS            bool
	Login          bool
	SSHLogin       bool
	Attack         bool
	Limit          bool
	Update         bool
	Services       []string
	LoadThreshold  int
	CPUThreshold   int
	RAMThreshold   int
	DiskThreshold  int
	SwapThreshold  int
}

// ─── Counters ─────────────────────────────────────────────────────────────────

var (
	pass   int
	warn   int
	fail   int
	status int // 0=ok 1=warn 2=fail
	debug  bool
	start  = time.Now()
)

// ─── INI / Config helpers ─────────────────────────────────────────────────────

func readKV(path string) map[string]string {
	m := make(map[string]string)
	f, err := os.Open(path)
	if err != nil {
		return m
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		idx := strings.Index(line, "=")
		if idx < 0 {
			continue
		}
		k := strings.TrimSpace(line[:idx])
		v := strings.TrimSpace(line[idx+1:])
		m[k] = v
	}
	return m
}

func getStr(m map[string]string, key, def string) string {
	if v, ok := m[key]; ok && v != "" {
		return v
	}
	return def
}

func getBool(m map[string]string, key string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(m[key]))
	if v == "yes" {
		return true
	}
	if v == "no" {
		return false
	}
	return def
}

func getInt(m map[string]string, key string, def int) int {
	v := m[key]
	if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 1 && n <= 100 {
		return n
	}
	return def
}

func loadConfig() Config {
	conf := readKV(confFile)
	ini := readKV(iniFile)

	email := getStr(conf, "email", "")
	services := strings.Split(getStr(ini, "services", "admin,docker,mysql,csf,panel"), ",")
	for i := range services {
		services[i] = strings.TrimSpace(services[i])
	}

	return Config{
		Email:         email,
		EmailAlert:    email != "",
		Reboot:        getBool(ini, "reboot", true),
		DNS:           getBool(ini, "dns", true),
		Login:         getBool(ini, "login", true),
		SSHLogin:      getBool(ini, "ssh", true),
		Attack:        getBool(ini, "attack", true),
		Limit:         getBool(ini, "limit", true),
		Update:        getBool(ini, "update", true),
		Services:      services,
		LoadThreshold: getInt(ini, "load", 20),
		CPUThreshold:  getInt(ini, "cpu", 90),
		RAMThreshold:  getInt(ini, "ram", 85),
		DiskThreshold: getInt(ini, "du", 85),
		SwapThreshold: getInt(ini, "swap", 40),
	}
}

// ─── Logging ──────────────────────────────────────────────────────────────────

func ensureLog() {
	dir := filepath.Dir(logFile)
	_ = os.MkdirAll(dir, 0755)
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err == nil {
		f.Close()
	}
}

func lastLogLine() string {
	f, err := os.Open(logFile)
	if err != nil {
		return ""
	}
	defer f.Close()
	var last string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		last = sc.Text()
	}
	return last
}

func hasUnread(keyword string) bool {
	f, err := os.Open(logFile)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	needle := "UNREAD " + keyword
	for sc.Scan() {
		if strings.Contains(sc.Text(), needle) {
			return true
		}
	}
	return false
}

func appendLog(title, message string) {
	line := fmt.Sprintf("%s UNREAD %s MESSAGE: %s\n",
		time.Now().Format("2006-01-02 15:04:05"), title, message)
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(line)
}

// ─── Notification ─────────────────────────────────────────────────────────────

func writeNotification(cfg Config, title, message string) {
	if hasUnread(title) {
		return
	}
	last := lastLogLine()
	if strings.Contains(last, message) {
		return
	}
	appendLog(title, message)
	if cfg.EmailAlert {
		sendEmail(cfg, title, message)
	} else {
		logInfo("Email alerts disabled.")
	}
}

func sendEmail(cfg Config, title, message string) {
	// Generate one-time token and call the OpenAdmin endpoint
	token := randomToken(64)
	// Persist token to conf (best-effort)
	replaceInFile(confFile, "mail_security_token=", "mail_security_token="+token)

	domain := strings.TrimSpace(runCmd("opencli", "domain"))
	protocol := "http"
	if isValidDomain(domain) {
		protocol = "https"
	}

	url := fmt.Sprintf("%s://%s:2087/send_email", protocol, domain)
	args := []string{
		"-4", "--max-time", "5", "-k", "-X", "POST", url,
		"-F", "transient=" + token,
		"-F", "recipient=" + cfg.Email,
		"-F", "subject=" + title,
		"-F", "body=" + message,
	}
	// basic auth if configured
	adminConf := readKV("/etc/openpanel/openadmin/config/admin.ini")
	if adminConf["basic_auth"] == "yes" {
		creds := adminConf["basic_auth_username"] + ":" + adminConf["basic_auth_password"]
		args = append([]string{"-u", creds}, args...)
	}

	out, err := exec.Command("curl", args...).Output()
	if err != nil {
		logFail("curl email error: " + err.Error())
		return
	}
	if strings.Contains(string(out), `"error"`) {
		logFail("Email send failed: " + string(out))
	} else {
		logInfo("Email sent.")
	}
}

// ─── ANSI helpers ─────────────────────────────────────────────────────────────

func logPass(msg string) { fmt.Printf("\033[32m[✔]\033[0m %s\n", msg) }
func logFail(msg string) { fmt.Printf("\033[31m[✘]\033[0m %s\n", msg) }
func logWarn(msg string) { fmt.Printf("\033[38;5;214m[!]\033[0m %s\n", msg) }
func logInfo(msg string) { fmt.Println(msg) }

// ─── Shell helpers ────────────────────────────────────────────────────────────

func runCmd(name string, args ...string) string {
	out, _ := exec.Command(name, args...).Output()
	return strings.TrimSpace(string(out))
}

func serviceActive(name string) bool {
	err := exec.Command("systemctl", "is-active", "--quiet", name).Run()
	return err == nil
}

func dockerRunning(name string) bool {
	out := runCmd("docker", "--context=default", "ps", "--format", "{{.Names}}")
	for _, n := range strings.Split(out, "\n") {
		if strings.TrimSpace(n) == name {
			return true
		}
	}
	return false
}

func dockerStart(svc string) {
	_ = exec.Command("sh", "-c", "cd /root && docker --context=default compose up -d "+svc+" > /dev/null 2>&1").Run()
}

func isValidDomain(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '-') {
			return false
		}
	}
	return strings.Contains(s, ".")
}

func randomToken(n int) string {
	b, _ := exec.Command("sh", "-c",
		fmt.Sprintf("tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c %d", n)).Output()
	return strings.TrimSpace(string(b))
}

func replaceInFile(path, prefix, newLine string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, prefix) {
			lines[i] = newLine
		}
	}
	_ = os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644)
}

// ─── Checks ───────────────────────────────────────────────────────────────────

func checkServiceStatus(cfg Config, svcName, title string) {
	if serviceActive(svcName) {
		pass++
		logPass(svcName + " is active.")
		return
	}
	// OpenAdmin disabled-by-admin check
	if svcName == "admin" {
		if _, err := os.Stat("/root/openadmin_is_disabled"); err == nil {
			pass++
			logPass("admin is disabled by Administrator.")
			return
		}
	}
	fail++
	if status < 2 {
		status = 2
	}
	logFail(svcName + " is not active.")
	errLog := runCmd("journalctl", "-n", "5", "-u", svcName)
	if errLog != "" {
		writeNotification(cfg, title, errLog)
	}
	_ = exec.Command("systemctl", "restart", svcName).Run()
	if serviceActive(svcName) {
		logPass(svcName + " restarted successfully.")
	} else {
		logFail("Failed to restart " + svcName)
	}
}

func checkMySQLContainer(cfg Config) {
	if !dockerRunning("openpanel_mysql") {
		fail++
		if status < 2 {
			status = 2
		}
		logFail("MySQL Docker container is not active, initiating restart..")
		dockerStart("openpanel_mysql")
		time.Sleep(5 * time.Second)
	}
	// ping
	out := runCmd("mysql", "-Ne", "SELECT 'PONG' AS PING;")
	title := "MySQL service is not active. Users are unable to log into OpenPanel!"
	if strings.Contains(out, "PONG") {
		pass++
		logPass("MySQL container is active and service running.")
	} else {
		fail++
		if status < 2 {
			status = 2
		}
		logFail("MySQL not responding.")
		msg := "MySQL container is running but did not respond to queries. Sentinel failed to restart mysql."
		writeNotification(cfg, title, msg)
	}
}

func checkDockerContainer(cfg Config, svcName, title string) {
	running := dockerRunning(svcName)

	caddyOK := func() bool {
		out, err := exec.Command("curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
			"--connect-timeout", "1", "--max-time", "1", "http://localhost/check").Output()
		if err != nil {
			return false
		}
		code := strings.TrimSpace(string(out))
		return code == "200" || code == "404"
	}

	if running {
		if svcName == "caddy" {
			if caddyOK() {
				pass++
				logPass("caddy docker container is active.")
			} else {
				warn++
				logWarn("caddy is running but not responding.")
			}
		} else {
			pass++
			logPass(svcName + " docker container is active.")
		}
		return
	}

	// Not running — smart restart logic
	switch svcName {
	case "openpanel":
		users := runCmd("opencli", "user-list", "--json")
		if users == "" || users == "No users." {
			warn++
			logWarn("openpanel: no users found, skipping start.")
		} else {
			dockerStart("openpanel")
			if dockerRunning("openpanel") {
				logPass("openpanel started.")
			} else {
				fail++
				if status < 2 {
					status = 2
				}
				logFail("openpanel failed to start.")
				errLog := runCmd("docker", "--context=default", "logs", "--tail", "10", svcName)
				writeNotification(cfg, title, errLog)
			}
		}
	case "openpanel_dns":
		matches, _ := filepath.Glob("/etc/bind/zones/*.zone")
		if len(matches) == 0 {
			warn++
			logWarn("DNS: no zones found, skipping BIND9 start.")
		} else {
			dockerStart("openpanel_dns")
			if dockerRunning("openpanel_dns") {
				logPass("openpanel_dns started.")
			} else {
				fail++
				if status < 2 {
					status = 2
				}
				logFail("openpanel_dns failed to start.")
			}
		}
	case "caddy":
		matches, _ := filepath.Glob("/etc/openpanel/caddy/domains/*")
		if len(matches) == 0 {
			logInfo("Caddy: no domains yet, skipping.")
		} else {
			dockerStart("caddy")
			if caddyOK() {
				pass++
				logPass("caddy started and responding.")
			} else {
				fail++
				if status < 2 {
					status = 2
				}
				logFail("caddy started but not responding.")
				errLog := runCmd("docker", "--context=default", "logs", "--tail", "10", "caddy")
				writeNotification(cfg, title, errLog)
			}
		}
	default:
		_ = exec.Command("docker", "--context=default", "restart", svcName).Run()
		if dockerRunning(svcName) {
			logPass(svcName + " restarted.")
		} else {
			fail++
			if status < 2 {
				status = 2
			}
			logFail(svcName + " failed to restart.")
			errLog := runCmd("docker", "--context=default", "logs", "--tail", "10", svcName)
			writeNotification(cfg, title, errLog)
		}
	}
}

func hasService(cfg Config, name string) bool {
	for _, s := range cfg.Services {
		if s == name {
			return true
		}
	}
	return false
}

func checkServices(cfg Config) {
	logInfo("Checking health for monitored services:")
	fmt.Println()

	if hasService(cfg, "caddy") {
		checkDockerContainer(cfg, "caddy", "Caddy is not active. Users websites are not working!")
	}
	if hasService(cfg, "csf") {
		checkServiceStatus(cfg, "csf", "Sentinel Firewall (CSF) is not active. Server and websites are not protected!")
	}
	if hasService(cfg, "admin") {
		checkServiceStatus(cfg, "admin", "Admin service is not active. OpenAdmin service is not accessible!")
	}
	if hasService(cfg, "docker") {
		checkServiceStatus(cfg, "docker", "Docker service is not active. User websites are down!")
	}
	if hasService(cfg, "panel") {
		checkDockerContainer(cfg, "openpanel", "OpenPanel docker container is not running. Users are unable to access the OpenPanel interface!")
	}
	if hasService(cfg, "mysql") {
		checkMySQLContainer(cfg)
	}
	if hasService(cfg, "named") {
		checkDockerContainer(cfg, "openpanel_dns", "Named (BIND9) service is not active. DNS resolving of domains is not working!")
	}
}

func checkNewLogins(cfg Config) {
	if !cfg.Login {
		warn++
		logWarn("Login notifications disabled. Skipping.")
		return
	}

	loginLogPath := "/var/log/openpanel/admin/login.log"
	_ = os.MkdirAll(filepath.Dir(loginLogPath), 0755)
	f, _ := os.OpenFile(loginLogPath, os.O_CREATE|os.O_APPEND, 0644)
	if f != nil {
		f.Close()
	}

	data, err := os.ReadFile(loginLogPath)
	if err != nil || len(strings.TrimSpace(string(data))) == 0 {
		pass++
		logPass("No new logins to OpenAdmin detected.")
		return
	}

	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	last := lines[len(lines)-1]
	parts := strings.Fields(last)
	if len(parts) < 4 {
		pass++
		logPass("No new logins to OpenAdmin detected.")
		return
	}
	username := parts[2]
	ipAddr := parts[3]

	if !isIPv4(ipAddr) || ipAddr == "127.0.0.1" {
		logInfo("Invalid or loopback IP in login log, skipping.")
		return
	}

	count := 0
	for _, l := range lines {
		if strings.Contains(l, username) {
			count++
		}
	}
	if count == 1 {
		pass++
		logPass(fmt.Sprintf("First login for %s from %s.", username, ipAddr))
		return
	}

	// Check if IP appeared before in previous lines
	prevLines := lines[:len(lines)-1]
	seenBefore := false
	for _, l := range prevLines {
		if strings.Contains(l, username+" "+ipAddr) {
			seenBefore = true
			break
		}
	}
	if seenBefore {
		pass++
		logPass(fmt.Sprintf("Admin %s from known IP %s.", username, ipAddr))
	} else {
		fail++
		if status < 2 {
			status = 2
		}
		logFail(fmt.Sprintf("Admin %s accessed from new IP %s", username, ipAddr))
		title := fmt.Sprintf("Admin account %s accessed from new IP address", username)
		msg := fmt.Sprintf("Admin account %s was accessed from a new IP address: %s", username, ipAddr)
		writeNotification(cfg, title, msg)
	}
}

func checkSSHLogins(cfg Config) {
	if !cfg.SSHLogin {
		warn++
		logWarn("SSH login notifications disabled. Skipping.")
		return
	}
	title := "Suspicious SSH login detected"
	if hasUnread(title) {
		warn++
		logWarn("Unread SSH login notification already exists. Skipping.")
		return
	}

	whoOut := runCmd("who")
	var sshIPs []string
	for _, line := range strings.Split(whoOut, "\n") {
		if !strings.Contains(line, "pts") {
			continue
		}
		// Extract IP from (1.2.3.4) or (1.2.3.4:0)
		start := strings.Index(line, "(")
		end := strings.LastIndex(line, ")")
		if start < 0 || end < 0 || end <= start {
			continue
		}
		raw := line[start+1 : end]
		raw = strings.Split(raw, ":")[0]
		if isIPv4(raw) {
			sshIPs = append(sshIPs, raw)
		}
	}

	if len(sshIPs) == 0 {
		pass++
		logPass("No currently logged in SSH users detected.")
		return
	}

	// Read known IPs from OpenAdmin login log
	loginData, _ := os.ReadFile("/var/log/openpanel/admin/login.log")
	if len(loginData) == 0 {
		warn++
		logWarn("SSH user detected but login checks postponed — OpenAdmin not ready.")
		return
	}
	knownIPs := make(map[string]bool)
	for _, l := range strings.Split(string(loginData), "\n") {
		parts := strings.Fields(l)
		if len(parts) >= 1 {
			knownIPs[parts[len(parts)-1]] = true
		}
	}

	// Load whitelist
	whitelist := loadSSHWhitelist()

	var suspicious, safe []string
	for _, ip := range sshIPs {
		if isWhitelisted(ip, whitelist) || knownIPs[ip] {
			safe = append(safe, ip)
		} else {
			suspicious = append(suspicious, ip)
		}
	}

	if len(suspicious) > 0 {
		fail++
		if status < 2 {
			status = 2
		}
		msg := "Suspicious SSH IPs: " + strings.Join(suspicious, ", ")
		logFail(msg)
		writeNotification(cfg, title, msg)
	} else {
		pass++
		logPass(fmt.Sprintf("Detected %d active SSH user(s), all marked safe. IPs: %s",
			len(safe), strings.Join(safe, " ")))
	}
}

type whitelist struct {
	ips   []string
	cidrs []string
}

func loadSSHWhitelist() whitelist {
	wl := whitelist{}
	f, err := os.Open("/etc/openpanel/openadmin/ssh_whitelist.conf")
	if err != nil {
		return wl
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		entry := strings.TrimSpace(sc.Text())
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			wl.cidrs = append(wl.cidrs, entry)
		} else {
			wl.ips = append(wl.ips, entry)
		}
	}
	return wl
}

func isWhitelisted(ip string, wl whitelist) bool {
	for _, wip := range wl.ips {
		if wip == ip {
			return true
		}
	}
	for _, cidr := range wl.cidrs {
		if ipInCIDR(ip, cidr) {
			return true
		}
	}
	return false
}

func ipInCIDR(ip, cidr string) bool {
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 {
		return false
	}
	mask, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}
	ipInt := ip4ToInt(ip)
	netInt := ip4ToInt(parts[0])
	if ipInt == 0 || netInt == 0 {
		return false
	}
	shift := uint(32 - mask)
	return (ipInt >> shift) == (netInt >> shift)
}

func ip4ToInt(ip string) uint32 {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return 0
	}
	var n uint32
	for _, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil {
			return 0
		}
		n = (n << 8) | uint32(v)
	}
	return n
}

func isIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 || v > 255 {
			return false
		}
	}
	return true
}

// ─── Resource checks ──────────────────────────────────────────────────────────

func checkDiskUsage(cfg Config) {
	title := "Running out of Disk Space!"
	out := runCmd("df", "-h", "--output=pcent", "/")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 2 {
		return
	}
	pctStr := strings.TrimSpace(strings.TrimRight(lines[len(lines)-1], "%"))
	pct, err := strconv.Atoi(pctStr)
	if err != nil {
		return
	}
	if pct > cfg.DiskThreshold {
		if hasUnread(title) {
			warn++
			logWarn("Unread DU notification already exists. Skipping.")
			return
		}
		fail++
		if status < 2 {
			status = 2
		}
		logFail(fmt.Sprintf("Disk usage (%d%%) > threshold (%d%%). Writing notification.", pct, cfg.DiskThreshold))
		partitions := runCmd("df", "-h")
		writeNotification(cfg, title, fmt.Sprintf("Disk Usage: %d%% | Partitions:\n%s", pct, partitions))
	} else {
		pass++
		logPass(fmt.Sprintf("Disk usage %d%% < threshold %d%%.", pct, cfg.DiskThreshold))
	}
}

func checkSystemLoad(cfg Config) {
	title := "High System Load!"
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return
	}
	parts := strings.Fields(string(data))
	if len(parts) == 0 {
		return
	}
	load1, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return
	}
	if int(load1) > cfg.LoadThreshold {
		fail++
		if status < 2 {
			status = 2
		}
		logFail(fmt.Sprintf("Load (%.2f) > threshold (%d). Writing notification.", load1, cfg.LoadThreshold))
		writeNotification(cfg, title, fmt.Sprintf("Current load: %.2f", load1))
	} else {
		pass++
		logPass(fmt.Sprintf("Load %.2f < threshold %d.", load1, cfg.LoadThreshold))
	}
}

func checkRAMUsage(cfg Config) {
	title := "High Memory Usage!"
	if hasUnread("Used RAM") {
		warn++
		logWarn("Unread RAM notification already exists. Skipping.")
		return
	}

	total, used := parseMeminfo()
	if total == 0 {
		return
	}
	pct := used * 100 / total
	msg := fmt.Sprintf("Used RAM: %d MB, Total RAM: %d MB, Usage: %d%%", used, total, pct)
	if pct > cfg.RAMThreshold {
		fail++
		if status < 2 {
			status = 2
		}
		logFail(fmt.Sprintf("RAM %d%% > threshold %d%%.", pct, cfg.RAMThreshold))
		writeNotification(cfg, title, msg)
	} else {
		pass++
		logPass(fmt.Sprintf("RAM %d%% < threshold %d%%.", pct, cfg.RAMThreshold))
	}
}

func parseMeminfo() (total, used int) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return
	}
	defer f.Close()
	var memTotal, memFree, buffers, cached int
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		var v int
		if n, _ := fmt.Sscanf(line, "MemTotal: %d kB", &v); n == 1 {
			memTotal = v / 1024
		} else if n, _ := fmt.Sscanf(line, "MemFree: %d kB", &v); n == 1 {
			memFree = v / 1024
		} else if n, _ := fmt.Sscanf(line, "Buffers: %d kB", &v); n == 1 {
			buffers = v / 1024
		} else if n, _ := fmt.Sscanf(line, "Cached: %d kB", &v); n == 1 {
			cached = v / 1024
		}
	}
	total = memTotal
	used = memTotal - memFree - buffers - cached
	return
}

func checkCPUUsage(cfg Config) {
	title := "High CPU Usage!"
	// Read two snapshots of /proc/stat for accurate idle %
	idle1, total1 := readCPUStat()
	time.Sleep(200 * time.Millisecond)
	idle2, total2 := readCPUStat()

	dIdle := idle2 - idle1
	dTotal := total2 - total1
	if dTotal == 0 {
		return
	}
	pct := int((dTotal-dIdle)*100/dTotal)

	if pct > cfg.CPUThreshold {
		fail++
		if status < 2 {
			status = 2
		}
		logFail(fmt.Sprintf("CPU %d%% > threshold %d%%.", pct, cfg.CPUThreshold))
		procs := runCmd("ps", "aux", "--sort", "-%cpu")
		writeNotification(cfg, title, fmt.Sprintf("CPU Usage: %d%% | Top Processes:\n%s", pct, procs))
	} else {
		pass++
		logPass(fmt.Sprintf("CPU %d%% < threshold %d%%.", pct, cfg.CPUThreshold))
	}
}

func readCPUStat() (idle, total uint64) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			break
		}
		for i, v := range fields[1:] {
			n, _ := strconv.ParseUint(v, 10, 64)
			total += n
			if i == 3 { // idle
				idle = n
			}
		}
		break
	}
	return
}

func checkSwapUsage(cfg Config) {
	title := "High SWAP usage!"
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return
	}
	var swapTotal, swapFree int
	for _, line := range strings.Split(string(data), "\n") {
		var v int
		if n, _ := fmt.Sscanf(line, "SwapTotal: %d kB", &v); n == 1 {
			swapTotal = v
		} else if n, _ := fmt.Sscanf(line, "SwapFree: %d kB", &v); n == 1 {
			swapFree = v
		}
	}
	if swapTotal == 0 {
		pass++
		logPass("No swap configured, skipping swap check.")
		return
	}
	swapUsed := swapTotal - swapFree
	pct := swapUsed * 100 / swapTotal

	if pct <= cfg.SwapThreshold {
		pass++
		logPass(fmt.Sprintf("SWAP %d%% < threshold %d%%.", pct, cfg.SwapThreshold))
		_ = os.Remove(lockFile)
		return
	}

	// Check lock file
	if info, err := os.Stat(lockFile); err == nil {
		age := time.Since(info.ModTime())
		if age < 6*time.Hour {
			warn++
			logWarn("Previous SWAP cleanup still in progress. Skipping.")
			return
		}
		_ = os.Remove(lockFile)
	}

	logInfo(fmt.Sprintf("SWAP %d%% > threshold %d%%. Clearing...", pct, cfg.SwapThreshold))
	writeNotification(cfg, title, fmt.Sprintf("SWAP: %d%%. Starting cleanup...", pct))

	// Create lock, clear swap
	_ = os.WriteFile(lockFile, []byte{}, 0644)
	_ = os.WriteFile("/proc/sys/vm/drop_caches", []byte("3"), 0644)
	_ = exec.Command("swapoff", "-a").Run()
	_ = exec.Command("swapon", "-a").Run()

	// Re-check
	data2, _ := os.ReadFile("/proc/meminfo")
	swapTotal2, swapFree2 := 0, 0
	for _, line := range strings.Split(string(data2), "\n") {
		var v int
		if n, _ := fmt.Sscanf(line, "SwapTotal: %d kB", &v); n == 1 {
			swapTotal2 = v
		} else if n, _ := fmt.Sscanf(line, "SwapFree: %d kB", &v); n == 1 {
			swapFree2 = v
		}
	}
	newPct := 0
	if swapTotal2 > 0 {
		newPct = (swapTotal2 - swapFree2) * 100 / swapTotal2
	}

	if newPct < cfg.SwapThreshold {
		logPass("SWAP cleared successfully.")
		writeNotification(cfg, "SWAP cleared - Current value: "+strconv.Itoa(newPct)+"%",
			"Sentinel cleared SWAP successfully.")
		_ = os.Remove(lockFile)
	} else {
		fail++
		if status < 2 {
			status = 2
		}
		logFail("URGENT! SWAP could not be cleared.")
		writeNotification(cfg, "URGENT! SWAP could not be cleared on "+runCmd("hostname"),
			fmt.Sprintf("Sentinel tried clearing SWAP but usage is still %d%%.", newPct))
	}
}

// ─── DNS check ────────────────────────────────────────────────────────────────

func checkDNS(cfg Config) {
	if !cfg.DNS {
		warn++
		logWarn("DNS check disabled in INI. Skipping.")
		return
	}

	domain := runCmd("opencli", "domain")
	checkDomain := isValidDomain(domain)

	confKV := readKV(confFile)
	ns1 := getStr(confKV, "ns1", "")
	checkNS := isValidDomain(ns1)

	if !checkDomain && !checkNS {
		warn++
		logWarn("No valid domain or NS configured. Skipping DNS checks.")
		return
	}

	// Get server IP
	serverIP := getServerIP()

	if checkDomain {
		ip := runCmd("dig", "+short", "@8.8.8.8", domain)
		ip = strings.TrimSpace(ip)
		if ip == serverIP {
			pass++
			logPass(fmt.Sprintf("%s resolves to %s", domain, serverIP))
		} else {
			nsRec := runCmd("dig", "+short", "@8.8.8.8", "NS", domain)
			if strings.Contains(nsRec, "cloudflare") {
				warn++
				logWarn(fmt.Sprintf("%s may be proxied via Cloudflare. Skipping.", domain))
			} else {
				fail++
				if status < 2 {
					status = 2
				}
				logFail(fmt.Sprintf("%s resolves to %s, expected %s", domain, ip, serverIP))
				writeNotification(cfg,
					fmt.Sprintf("%s does not resolve to %s", domain, serverIP),
					fmt.Sprintf("%s resolves to %s instead of %s", domain, ip, serverIP))
			}
		}
	}

	if !checkNS {
		pass++
		logPass("No nameservers configured, skipping NS check.")
		return
	}

	allIPs := runCmd("hostname", "-I")
	ns2 := getStr(confKV, "ns2", "")
	ns3 := getStr(confKV, "ns3", "")
	ns4 := getStr(confKV, "ns4", "")

	nsMap := map[string]string{"ns1": ns1, "ns2": ns2, "ns3": ns3, "ns4": ns4}
	var failedNS []string

	for _, key := range []string{"ns1", "ns2"} {
		nsHost := nsMap[key]
		if nsHost == "" {
			continue
		}
		nsIP := strings.TrimSpace(runCmd("dig", "+short", "@8.8.8.8", nsHost))
		if !strings.Contains(allIPs, nsIP) {
			failedNS = append(failedNS, fmt.Sprintf("%s resolves to %s (expected one of: %s)", nsHost, nsIP, allIPs))
		}
	}
	for _, key := range []string{"ns3", "ns4"} {
		nsHost := nsMap[key]
		if !isValidDomain(nsHost) {
			continue
		}
		nsIP := strings.TrimSpace(runCmd("dig", "+short", "@8.8.8.8", nsHost))
		if !strings.Contains(allIPs, nsIP) {
			failedNS = append(failedNS, fmt.Sprintf("%s resolves to %s (expected one of: %s)", nsHost, nsIP, allIPs))
		}
	}

	if len(failedNS) == 0 {
		pass++
		logPass("All nameservers resolve to local IPs.")
	} else if ns2 == "" {
		warn++
		logWarn("Only one NS configured. Add a second for redundancy.")
	} else {
		fail++
		if status < 2 {
			status = 2
		}
		for _, f := range failedNS {
			logFail(f)
		}
		writeNotification(cfg,
			"Configured nameservers do not resolve to local IPs",
			strings.Join(failedNS, " | "))
	}
}

func getServerIP() string {
	for _, url := range []string{
		"https://ip.openpanel.com",
		"https://ipv4.openpanel.com",
		"https://ipconfig.me",
	} {
		out, err := exec.Command("curl", "--silent", "--max-time", "2", "-4", url).Output()
		if err == nil && len(out) > 0 {
			return strings.TrimSpace(string(out))
		}
	}
	// fallback
	out, _ := exec.Command("sh", "-c",
		"ip addr | grep 'inet ' | grep global | head -n1 | awk '{print $2}' | cut -f1 -d/").Output()
	return strings.TrimSpace(string(out))
}

// ─── Startup / report modes ───────────────────────────────────────────────────

func performStartupAction(cfg Config) {
	if !cfg.Reboot {
		warn++
		logWarn("Reboot notifications disabled. Skipping.")
		return
	}
	uptime := runCmd("uptime")
	writeNotification(cfg, "SYSTEM REBOOT!", "System was rebooted. "+uptime)
}

func emailDailyReport(cfg Config) {
	if !cfg.EmailAlert {
		logInfo("Email alerts disabled — daily report skipped.")
		return
	}
	logInfo("Sending daily usage report...")
	sendEmail(cfg, "Daily Usage Report", "Daily Usage Report")
}

// ─── Summary ──────────────────────────────────────────────────────────────────

func printSummary() {
	sep := strings.Repeat("-", 60)
	fmt.Println(sep)
	switch status {
	case 0:
		fmt.Println("\033[32mAll Tests Passed!\033[0m")
	case 1:
		fmt.Println("\033[93mSome non-critical tests failed. Please review.\033[0m")
	default:
		fmt.Println("\033[41mOne or more tests failed. Please review.\033[0m")
	}
	fmt.Println(sep)
	fmt.Printf("\033[1m%d Tests PASSED\033[0m\n", pass)
	fmt.Printf("\033[1m%d WARNINGS\033[0m\n", warn)
	fmt.Printf("\033[1m%d Tests FAILED\033[0m\n", fail)
	fmt.Println(sep)
	elapsed := time.Since(start)
	mem := runCmd("sh", "-c", fmt.Sprintf("ps -p %d -o rss= 2>/dev/null", os.Getpid()))
	fmt.Printf("Elapsed time: %.3f seconds\n", elapsed.Seconds())
	fmt.Printf("Memory usage: %s KB\n", mem)
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	if _, err := os.Stat(iniFile); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: INI file not found: %s\n", iniFile)
		os.Exit(1)
	}

	ensureLog()
	cfg := loadConfig()

	args := os.Args[1:]
	for _, a := range args {
		if a == "--debug" {
			debug = true
		}
	}

	if debug {
		hostname := runCmd("hostname")
		fmt.Printf("\n--- DEBUG ---\nHOSTNAME: %s\nVERSION: %s\nPID: %d\n",
			hostname, version, os.Getpid())
		fmt.Printf("EMAIL_ALERT: %v | EMAIL: %s\n", cfg.EmailAlert, cfg.Email)
		fmt.Printf("SERVICES: %v\nTHRESHOLDS: load=%d cpu=%d ram=%d disk=%d swap=%d\n\n",
			cfg.Services, cfg.LoadThreshold, cfg.CPUThreshold, cfg.RAMThreshold, cfg.DiskThreshold, cfg.SwapThreshold)
	}

	// Flags
	if len(args) > 0 {
		switch args[0] {
		case "--startup":
			performStartupAction(cfg)
			return
		case "--report":
			emailDailyReport(cfg)
			return
		}
	}

	// Normal run
	fmt.Printf("\n Sentinel v%s\n\n", version)

	checkServices(cfg)

	fmt.Println(strings.Repeat("-", 60))
	fmt.Println("Checking SSH and OpenAdmin logins:")
	fmt.Println()
	checkNewLogins(cfg)
	checkSSHLogins(cfg)

	fmt.Println(strings.Repeat("-", 60))
	fmt.Println("Checking server resource usage:")
	fmt.Println()
	checkDiskUsage(cfg)
	checkSystemLoad(cfg)
	checkRAMUsage(cfg)
	checkCPUUsage(cfg)
	checkSwapUsage(cfg)

	fmt.Println(strings.Repeat("-", 60))
	fmt.Println("Checking DNS:")
	fmt.Println()
	checkDNS(cfg)

	printSummary()
}
