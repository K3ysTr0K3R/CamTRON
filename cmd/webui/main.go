// Command camtron-web serves a browser dashboard for CamTRON.
//
// It reuses the same detection engine as the CamTRON CLI (see ../../camtron.go)
// but drives it from a small HTTP + Server-Sent-Events API instead of the
// terminal, so scans can be configured, watched live, and exported from a
// browser.
//
// Build:  go build -o camtron-web ./cmd/webui
// Run:    ./camtron-web            (defaults to :8787)
//         ./camtron-web -addr :9000
package main

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"embed"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/html"
)

//go:embed frontend/*
var embeddedFrontend embed.FS

const (
	maxBodySize        = 2 << 20
	maxExpandedTargets = 65536 // safety cap so a big CIDR can't accidentally lock up the demo server
)

// ---------------------------------------------------------------------------
// Detection rules (identical rule set to the CLI, kept in sync by hand).
// ---------------------------------------------------------------------------

type Rule struct {
	Brand         string
	Path          string
	Condition     string
	Exclude       string
	CaseSensitive bool
}

var rules = []Rule{
	{"avtech", "/", "title=`::: Login :::`", "", false},
	{"avtech", "/", "title=`Remote Surveillance`&&title=`Any time & Any where`", "", false},
	{"avtech", "/nobody/favicon.ico", "md5=`6a7e13b3f9197a383c96618fe32e345a`", "", true},
	{"axis", "/favicon.ico", "md5=`a3fd8705f010b90e37d42128000f620b`", "", true},
	{"cctv", "/", "body=`IP Surveillance for Your Life`", "", false},
	{"cctv", "/", "body=`/nobody/loginDevice.js`", "", false},
	{"cctv", "/", "headers=`JAWS`", "", false},
	{"dahua", "/", "body=`WEB SERVICE`", "", false},
	{"dahua", "/", "title=`WEB SERVICE`", "", false},
	{"cctv", "/favicon.ico", "md5=`f066b751b858f75ef46536f5b357972b`", "", true},
	{"dahua", "/favicon.ico", "md5=`bd9e17c46bbbc18af2a2bd718dddad0e`", "", true},
	{"dahua", "/favicon.ico", "md5=`605f51b413980667766a9aff2e53b9ed`", "", true},
	{"dahua", "/favicon.ico", "md5=`b39f249362a2e4ab62be4ddbc9125f53`", "", true},
	{"dahua", "/image/lgbg.jpg", "md5=`4ff53be6165e430af41d782e00207fda`", "", true},
	{"dlink-dcs", "/", "headers=`realm=\"DCS`", "", false},
	{"dlink-dcs", "/", "headers=`realm=DCS`", "", false},
	{"dvr", "/login.rsp", "title=`LOGIN`", "", false},
	{"geovision", "/", "title=`GeoVision`", "", false},
	{"hikvision", "/", "body=`doc/page/login.asp`", "", false},
	{"hikvision", "/", "body=`g_szCacheTime`&&body=`iVMS`", "", false},
	{"hikvision", "/", "headers=`Webs`", "", false},
	{"hikvision", "/", "headers=`APP-webs`", "", false},
	{"hikvision", "/", "headers=`DVRDVS-Webs`", "", false},
	{"hikvision", "/", "headers=`DNVRS-Webs`", "", false},
	{"hikvision", "/", "headers=`Hikvision-Webs`", "", false},
	{"hikvision", "/", "headers=`_goaheadwebSessionId`", "", false},
	{"hikvision", "/", "title=`hikvision`", "", false},
	{"hikvision", "/favicon.ico", "md5=`89b932fcc47cf4ca3faadb0cfdef89cf`", "", true},
	{"instar", "/", "title=`INSTAR`&&title=`Camera`", "", false},
	{"ipcamera", "/", "headers=`IPCamera`&&status_code=`401`", "", false},
	{"netwave", "/", "headers=`Netwave IP Camera`", "", false},
	{"nuuo", "/", "title=`network video recorder login`", "", false},
	{"reecam", "/", "headers=`ReeCam IP Camera`", "", false},
	{"tenda", "/", "title=`Tenda | login`", "", false},
	{"tenda", "/", "title=`Tenda|login`", "", false},
	{"tenda", "/", "title=`Tenda | 登录`", "", false},
	{"tenda", "/", "title=`Tenda|登录`", "", false},
	{"tenda", "/", "title=`Tenda | Web Master`", "", false},
	{"tenda", "/", "title=`Tenda | Wireless Router`", "", false},
	{"tenda", "/favicon.ico", "md5=`fa31b29eab2da688b11d8fafc5fc6b27`", "", true},
	{"uniview", "/favicon.ico", "md5=`1536f25632f78fb03babedcb156d3f69`", "", true},
	{"uniview", "/skin/default_1/images/logo.png", "md5=`c30a692ad0d1324389485de06c96d9b8`", "", true},
	{"xiongmai", "/", "title=`NETSurveillance WEB`", "", false},
	{"xiongmai", "/", "title=`NetSurveillance WEB`", "", false},
}

// ---------------------------------------------------------------------------
// HTTP client + scan engine (ported from the CLI's camtron.go)
// ---------------------------------------------------------------------------

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:          200,
			MaxIdleConnsPerHost:   50,
			MaxConnsPerHost:       50,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   2 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			DisableCompression:    true,
			ForceAttemptHTTP2:     false,
			DialContext: (&net.Dialer{
				Timeout:   2 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func fetchRaw(client *http.Client, url string) (*http.Response, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	resp.Body.Close()

	return resp, body, nil
}

func fetchWithRetry(client *http.Client, url string, maxRetries int) (*http.Response, []byte, error) {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		resp, body, err := fetchRaw(client, url)
		if err == nil {
			return resp, body, nil
		}
		lastErr = err
		if attempt < maxRetries {
			time.Sleep(time.Duration(1<<uint(attempt)) * 100 * time.Millisecond)
		}
	}
	return nil, nil, lastErr
}

func isPortOpen(host string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func isAlive(client *http.Client, url string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return true
}

func buildRuleURL(base, path string) string {
	if path == "" || path == "/" {
		return strings.TrimRight(base, "/")
	}
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(path, "/")
}

func expandCIDR(targets []string) []string {
	var out []string
	for _, t := range targets {
		if !strings.Contains(t, "/") {
			out = append(out, t)
			continue
		}
		out = append(out, cidrToHosts(t)...)
	}
	return out
}

func cidrToHosts(cidr string) []string {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}
	ones, bits := ipnet.Mask.Size()
	var all []string
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		all = append(all, ip.String())
		if len(all) > maxExpandedTargets {
			break
		}
	}
	if (bits-ones) > 1 && len(all) > 2 {
		return all[1 : len(all)-1]
	}
	return all
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

type pathEntry struct {
	resp *http.Response
	body []byte
	ok   bool
	once sync.Once
}

type pathCache struct {
	mu    sync.Mutex
	items map[string]*pathEntry
}

func newPathCache() *pathCache { return &pathCache{items: make(map[string]*pathEntry)} }

func (pc *pathCache) get(client *http.Client, url string, maxRetries int) (*http.Response, []byte, bool) {
	pc.mu.Lock()
	entry, exists := pc.items[url]
	if !exists {
		entry = &pathEntry{}
		pc.items[url] = entry
	}
	pc.mu.Unlock()

	entry.once.Do(func() {
		resp, body, err := fetchWithRetry(client, url, maxRetries)
		entry.resp, entry.body, entry.ok = resp, body, err == nil
	})
	return entry.resp, entry.body, entry.ok
}

func matchRules(client *http.Client, baseURL string, maxRetries int) []string {
	cache := newPathCache()
	var detected []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)

	for _, r := range rules {
		wg.Add(1)
		go func(r Rule) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			fullURL := buildRuleURL(baseURL, r.Path)
			resp, body, ok := cache.get(client, fullURL, maxRetries)
			if !ok || !evaluateCondition(resp, body, r) {
				return
			}
			mu.Lock()
			if !slices.Contains(detected, r.Brand) {
				detected = append(detected, r.Brand)
			}
			mu.Unlock()
		}(r)
	}
	wg.Wait()
	return detected
}

func evaluateCondition(resp *http.Response, body []byte, rule Rule) bool {
	if rule.Exclude != "" && bodyContains(body, rule.Exclude, rule.CaseSensitive) {
		return false
	}
	for _, cond := range strings.Split(rule.Condition, "&&") {
		if !checkCondition(resp, body, cond, rule.CaseSensitive) {
			return false
		}
	}
	return true
}

func checkCondition(resp *http.Response, body []byte, cond string, caseSensitive bool) bool {
	parts := strings.SplitN(cond, "=", 2)
	if len(parts) != 2 {
		return false
	}
	key := strings.TrimSpace(parts[0])
	val := normalize(strings.Trim(parts[1], "` "), caseSensitive)

	switch key {
	case "title":
		return strings.Contains(normalize(extractTitle(body), caseSensitive), val)
	case "body":
		return strings.Contains(normalize(string(body), caseSensitive), val)
	case "headers":
		return matchHeaders(resp, val, caseSensitive)
	case "md5":
		return fmt.Sprintf("%x", md5.Sum(body)) == val
	case "status_code":
		return fmt.Sprintf("%d", resp.StatusCode) == val
	default:
		return false
	}
}

func bodyContains(body []byte, substr string, caseSensitive bool) bool {
	return strings.Contains(normalize(string(body), caseSensitive), normalize(substr, caseSensitive))
}

func matchHeaders(resp *http.Response, value string, caseSensitive bool) bool {
	for name, vals := range resp.Header {
		if strings.Contains(normalize(name, caseSensitive), value) {
			return true
		}
		for _, v := range vals {
			if strings.Contains(normalize(v, caseSensitive), value) {
				return true
			}
		}
	}
	return false
}

func normalize(s string, caseSensitive bool) string {
	if caseSensitive {
		return s
	}
	return strings.ToLower(s)
}

func extractTitle(body []byte) string {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return ""
	}
	return findTitle(doc)
}

func findTitle(n *html.Node) string {
	if n.Type == html.ElementNode && n.Data == "title" && n.FirstChild != nil {
		return n.FirstChild.Data
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if t := findTitle(c); t != "" {
			return t
		}
	}
	return ""
}

func parsePorts(portStr string) []int {
	if portStr == "" {
		return []int{80}
	}
	parts := strings.Split(portStr, ",")
	ports := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if port, err := strconv.Atoi(p); err == nil && port > 0 && port < 65536 {
			ports = append(ports, port)
		}
	}
	if len(ports) == 0 {
		return []int{80}
	}
	return ports
}

// parseTargetsText splits free-form textarea input (newlines and/or commas,
// with "#" comments) into a raw target list, then expands any CIDR ranges.
func parseTargetsText(raw string) []string {
	raw = strings.ReplaceAll(raw, ",", "\n")
	var targets []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "http://")
		line = strings.TrimPrefix(line, "https://")
		targets = append(targets, line)
	}
	return expandCIDR(targets)
}

// ---------------------------------------------------------------------------
// Scan session bookkeeping
// ---------------------------------------------------------------------------

type Finding struct {
	Host      string   `json:"host"`
	Brands    []string `json:"brands"`
	Timestamp string   `json:"timestamp"`
}

type ScanSession struct {
	ID        string
	Total     int
	Ports     []int
	Threads   int
	Retries   int
	StartedAt time.Time

	processed atomic.Int64
	cancelled atomic.Bool

	mu       sync.Mutex
	findings []Finding
	done     bool
	elapsed  float64
}

func (s *ScanSession) addFinding(f Finding) {
	s.mu.Lock()
	s.findings = append(s.findings, f)
	s.mu.Unlock()
}

func (s *ScanSession) snapshot(from int) (findings []Finding, total int, processed int64, done bool, elapsed float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if from < len(s.findings) {
		findings = append(findings, s.findings[from:]...)
	}
	return findings, len(s.findings), s.processed.Load(), s.done, s.elapsed
}

func (s *ScanSession) markDone() {
	s.mu.Lock()
	s.done = true
	s.elapsed = time.Since(s.StartedAt).Seconds()
	s.mu.Unlock()
}

var (
	sessionsMu sync.Mutex
	sessions   = map[string]*ScanSession{}
)

func newSessionID() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func runScan(s *ScanSession, targets []string) {
	client := newHTTPClient()
	jobs := make(chan string, s.Threads*2)
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for target := range jobs {
			if s.cancelled.Load() {
				s.processed.Add(1)
				continue
			}
			for _, port := range s.Ports {
				if !isPortOpen(target, port, 1*time.Second) {
					continue
				}
				url := fmt.Sprintf("http://%s:%d", target, port)
				if !isAlive(client, url) {
					continue
				}
				brands := matchRules(client, url, s.Retries)
				if len(brands) > 0 {
					s.addFinding(Finding{
						Host:      fmt.Sprintf("%s:%d", target, port),
						Brands:    brands,
						Timestamp: time.Now().Format("15:04:05"),
					})
					break
				}
			}
			s.processed.Add(1)
		}
	}

	for i := 0; i < s.Threads; i++ {
		wg.Add(1)
		go worker()
	}
	for _, t := range targets {
		jobs <- t
	}
	close(jobs)
	wg.Wait()
	s.markDone()
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

type startScanRequest struct {
	Targets string `json:"targets"`
	Ports   string `json:"ports"`
	Threads int    `json:"threads"`
	Retries int    `json:"retries"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func handleStartScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req startScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	targets := parseTargetsText(req.Targets)
	if len(targets) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no valid targets supplied"})
		return
	}
	if len(targets) > maxExpandedTargets {
		targets = targets[:maxExpandedTargets]
	}

	threads := req.Threads
	if threads <= 0 {
		threads = 50
	}
	if threads > 500 {
		threads = 500
	}
	retries := req.Retries
	if retries < 0 {
		retries = 0
	}
	if retries > 10 {
		retries = 10
	}
	ports := parsePorts(req.Ports)

	session := &ScanSession{
		ID:        newSessionID(),
		Total:     len(targets),
		Ports:     ports,
		Threads:   threads,
		Retries:   retries,
		StartedAt: time.Now(),
	}

	sessionsMu.Lock()
	sessions[session.ID] = session
	sessionsMu.Unlock()

	go runScan(session, targets)

	writeJSON(w, http.StatusOK, map[string]any{
		"id":      session.ID,
		"total":   session.Total,
		"ports":   ports,
		"threads": threads,
	})
}

func getSession(r *http.Request) *ScanSession {
	id := r.PathValue("id")
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	return sessions[id]
}

func handleStream(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	if session == nil {
		http.Error(w, "unknown scan id", http.StatusNotFound)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	send := func(v any) {
		b, _ := json.Marshal(v)
		fmt.Fprintf(w, "data: %s\n\n", b)
		flusher.Flush()
	}

	ticker := time.NewTicker(150 * time.Millisecond)
	defer ticker.Stop()

	from := 0
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			findings, foundTotal, processed, done, elapsed := session.snapshot(from)
			from = foundTotal
			for _, f := range findings {
				send(map[string]any{"type": "found", "host": f.Host, "brands": f.Brands, "timestamp": f.Timestamp})
			}
			send(map[string]any{
				"type":      "progress",
				"processed": processed,
				"total":     session.Total,
				"found":     foundTotal,
			})
			if done {
				rate := 0.0
				if elapsed > 0 {
					rate = float64(session.Total) / elapsed
				}
				send(map[string]any{
					"type":      "done",
					"processed": session.Total,
					"total":     session.Total,
					"found":     foundTotal,
					"elapsed":   elapsed,
					"rate":      rate,
				})
				return
			}
		}
	}
}

func handleCancel(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	if session == nil {
		http.Error(w, "unknown scan id", http.StatusNotFound)
		return
	}
	session.cancelled.Store(true)
	writeJSON(w, http.StatusOK, map[string]string{"status": "cancelling"})
}

func handleExport(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	if session == nil {
		http.Error(w, "unknown scan id", http.StatusNotFound)
		return
	}
	findings, _, _, _, _ := session.snapshot(0)
	format := r.URL.Query().Get("format")

	if format == "json" {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=camtron-results.json")
		json.NewEncoder(w).Encode(findings)
		return
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=camtron-results.csv")
	cw := csv.NewWriter(w)
	cw.Write([]string{"Target", "Brands", "Time"})
	for _, f := range findings {
		cw.Write([]string{f.Host, strings.Join(f.Brands, ", "), f.Timestamp})
	}
	cw.Flush()
}

func main() {
	addr := flag.String("addr", ":8787", "address to listen on")
	flag.Parse()

	sub, err := fs.Sub(embeddedFrontend, "frontend")
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(sub)))
	mux.HandleFunc("POST /api/scan", handleStartScan)
	mux.HandleFunc("GET /api/scan/{id}/stream", handleStream)
	mux.HandleFunc("POST /api/scan/{id}/cancel", handleCancel)
	mux.HandleFunc("GET /api/scan/{id}/export", handleExport)

	fmt.Fprintf(os.Stderr, "CamTRON web UI listening on http://localhost%s\n", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
