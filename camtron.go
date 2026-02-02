package main

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/net/html"
)

const maxBodySize = 2 << 20 // 2MB

// Styles
var (
	cyan    = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
	green   = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	yellow  = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	purple  = lipgloss.NewStyle().Foreground(lipgloss.Color("5"))
	red     = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
	gray    = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	faint = lipgloss.NewStyle().Faint(true)
	banner  = lipgloss.NewStyle().BorderStyle(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("6")).Padding(0, 2)
)

// Rule defines a fingerprint signature for a camera brand.
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

// scanResult holds a detection for a single target.
type scanResult struct {
	host   string
	brands []string
}

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

// expandCIDR expands CIDR notation to individual host IPs, skipping
// network and broadcast addresses for prefixes with more than 2 hosts.
func expandCIDR(targets []string) []string {
	var out []string
	for _, t := range targets {
		if !strings.Contains(t, "/") {
			out = append(out, t)
			continue
		}
		_, ipnet, err := net.ParseCIDR(t)
		if err != nil {
			continue
		}
		ones, bits := ipnet.Mask.Size()
		var all []string
		for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
			all = append(all, ip.String())
		}
		if (bits-ones) > 1 && len(all) > 2 {
			all = all[1 : len(all)-1]
		}
		out = append(out, all...)
	}
	return out
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func normalizeURL(target string) string {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		return "http://" + target
	}
	return target
}

func displayHost(u string) string {
	u = strings.TrimPrefix(u, "http://")
	u = strings.TrimPrefix(u, "https://")
	return u
}

// fetch performs a GET request and returns the response and body.
func fetch(client *http.Client, url string) (*http.Response, []byte, error) {
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

// isAlive does a quick HEAD to check if the target responds.
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

func buildRuleURL(base string, path string) string {
	if strings.HasSuffix(base, "/") {
		return base + strings.TrimPrefix(path, "/")
	}
	if path == "" || path == "/" {
		return base
	}
	return base + "/" + strings.TrimPrefix(path, "/")
}

// scanTarget fingerprints a single target against all rules.
func scanTarget(client *http.Client, target string) scanResult {
	url := normalizeURL(target)
	host := displayHost(url)

	if !isAlive(client, url) {
		return scanResult{}
	}

	// Group rules by path to avoid duplicate fetches.
	type pathData struct {
		resp *http.Response
		body []byte
		ok   bool
	}
	pathCache := make(map[string]*pathData)
	var cacheMu sync.Mutex

	getPath := func(path string) *pathData {
		fullURL := buildRuleURL(url, path)

		cacheMu.Lock()
		if pd, found := pathCache[fullURL]; found {
			cacheMu.Unlock()
			return pd
		}
		// Mark as in-progress to avoid duplicate fetches.
		pd := &pathData{}
		pathCache[fullURL] = pd
		cacheMu.Unlock()

		resp, body, err := fetch(client, fullURL)
		pd.resp = resp
		pd.body = body
		pd.ok = err == nil
		return pd
	}

	var detected []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, 5)

	for _, rule := range rules {
		wg.Add(1)
		go func(r Rule) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			pd := getPath(r.Path)
			if !pd.ok {
				return
			}
			if evaluateCondition(pd.resp, pd.body, r) {
				mu.Lock()
				if !slices.Contains(detected, r.Brand) {
					detected = append(detected, r.Brand)
				}
				mu.Unlock()
			}
		}(rule)
	}

	wg.Wait()

	if len(detected) > 0 {
		return scanResult{host: host, brands: detected}
	}
	return scanResult{}
}

// evaluateCondition checks a single rule's conditions against the
// HTTP response.
func evaluateCondition(resp *http.Response, body []byte, rule Rule) bool {
	if rule.Exclude != "" {
		ev := normalize(rule.Exclude, rule.CaseSensitive)
		if strings.Contains(normalize(string(body), rule.CaseSensitive), ev) {
			return false
		}
	}
	for _, cond := range strings.Split(rule.Condition, "&&") {
		parts := strings.SplitN(cond, "=", 2)
		if len(parts) != 2 {
			return false
		}
		key := strings.TrimSpace(parts[0])
		val := strings.Trim(parts[1], "` ")
		val = normalize(val, rule.CaseSensitive)

		switch key {
		case "title":
			if !strings.Contains(normalize(extractTitle(body), rule.CaseSensitive), val) {
				return false
			}
		case "body":
			if !strings.Contains(normalize(string(body), rule.CaseSensitive), val) {
				return false
			}
		case "headers":
			if !matchHeaders(resp, val, rule.CaseSensitive) {
				return false
			}
		case "md5":
			if fmt.Sprintf("%x", md5.Sum(body)) != val {
				return false
			}
		case "status_code":
			if fmt.Sprintf("%d", resp.StatusCode) != val {
				return false
			}
		default:
			return false
		}
	}
	return true
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
	var find func(*html.Node) string
	find = func(n *html.Node) string {
		if n.Type == html.ElementNode && n.Data == "title" && n.FirstChild != nil {
			return n.FirstChild.Data
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if t := find(c); t != "" {
				return t
			}
		}
		return ""
	}
	return find(doc)
}

func loadTargetsFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var targets []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		if line := strings.TrimSpace(s.Text()); line != "" {
			targets = append(targets, line)
		}
	}
	return targets, s.Err()
}

func printBanner() {
	content := green.Render("CamTRON - Camera Scanner") + "\n" +
		gray.Render("Automated Detection of Surveillance Devices") + "\n" +
		green.Render("Coded By - K3ysTr0K3R")
	fmt.Fprintln(os.Stderr, banner.Render(content))
	fmt.Fprintln(os.Stderr)
}

func main() {
	log.SetOutput(io.Discard)

	printBanner()

	urlFlag := flag.String("u", "", "Scan a single URL")
	ipFlag := flag.String("ip", "", "Scan a single IP/CIDR")
	fileFlag := flag.String("f", "", "File with targets (one per line)")
	threadsFlag := flag.Int("t", 50, "Number of concurrent workers")
	outputFlag := flag.String("o", "", "Output CSV file (optional)")
	appendFlag := flag.Bool("append", false, "Append to output CSV instead of overwrite")
	flag.Parse()

	var targets []string
	if *urlFlag != "" {
		targets = append(targets, *urlFlag)
	}
	if *ipFlag != "" {
		targets = append(targets, *ipFlag)
	}
	if *fileFlag != "" {
		loaded, err := loadTargetsFromFile(*fileFlag)
		if err != nil {
			fmt.Fprintln(os.Stderr, red.Render(fmt.Sprintf("Error opening file: %v", err)))
			return
		}
		targets = append(targets, loaded...)
	}

	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, red.Render("Please specify -u, -ip, or -f"))
		flag.Usage()
		return
	}

	targets = expandCIDR(targets)
	total := len(targets)

	fmt.Fprintln(os.Stderr, cyan.Render(fmt.Sprintf("Loaded %d targets, scanning with %d workers", total, *threadsFlag)))

	var writer *csv.Writer
	if *outputFlag != "" {
		var csvFile *os.File
		var err error
		if *appendFlag {
			csvFile, err = os.OpenFile(*outputFlag, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		} else {
			csvFile, err = os.Create(*outputFlag)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, red.Render(fmt.Sprintf("Error opening output: %v", err)))
			return
		}
		defer csvFile.Close()
		writer = csv.NewWriter(csvFile)
		if !*appendFlag {
			writer.Write([]string{"Target", "Brands"})
			writer.Flush()
		}
	}

	client := newHTTPClient()
	bar := progress.New(progress.WithScaledGradient("#6C8EBF", "#82AAFF"), progress.WithWidth(40))

	var processed atomic.Int64
	var found atomic.Int64
	startTime := time.Now()

	// Progress ticker goroutine
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(150 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				p := processed.Load()
				f := found.Load()
				pct := float64(p) / float64(total)
				fmt.Fprintf(os.Stderr, "\r\033[K  %s %s",
					bar.ViewAs(pct),
					faint.Render(fmt.Sprintf("%d/%d | found: %d", p, total, f)))
			}
		}
	}()

	// Worker pool with simple fan-out
	jobs := make(chan string, *threadsFlag*2)
	var resultsMu sync.Mutex

	var wg sync.WaitGroup
	for i := 0; i < *threadsFlag; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				result := scanTarget(client, target)
				processed.Add(1)

				if result.host == "" {
					continue
				}
				found.Add(1)

				resultsMu.Lock()
				// Clear progress line, print result, progress will redraw
				fmt.Fprint(os.Stderr, "\r\033[K")
				fmt.Fprintf(os.Stdout, "%s %s %s\n",
					green.Render("[+]"),
					yellow.Render(result.host),
					purple.Render(strings.Join(result.brands, ", ")))

				if writer != nil {
					writer.Write([]string{result.host, strings.Join(result.brands, ", ")})
					writer.Flush()
				}
				resultsMu.Unlock()
			}
		}()
	}

	// Feed targets
	for _, t := range targets {
		jobs <- t
	}
	close(jobs)
	wg.Wait()
	close(done)

	// Final progress
	fmt.Fprintf(os.Stderr, "\r\033[K  %s %s\n",
		bar.ViewAs(1.0),
		faint.Render(fmt.Sprintf("%d/%d | found: %d", total, total, found.Load())))

	elapsed := time.Since(startTime)
	rate := float64(total) / elapsed.Seconds()

	if *outputFlag != "" {
		fmt.Fprintln(os.Stderr, cyan.Render(fmt.Sprintf("Results saved to %s", *outputFlag)))
	}
	fmt.Fprintln(os.Stderr, cyan.Render(fmt.Sprintf(
		"Scan completed: %d devices from %d targets in %.2fs (%.1f/s)",
		found.Load(), total, elapsed.Seconds(), rate)))
}
