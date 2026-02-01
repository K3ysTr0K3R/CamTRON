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
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
	colorGray   = "\033[90m"
)

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

type scanResult struct {
	host   string
	brands []string
}

type ProcessedTarget struct {
	URL      string
	IsIP     bool
	Resolved string
}

type DNSCache struct {
	cache map[string]string
	mutex sync.RWMutex
}

func NewDNSCache() *DNSCache {
	return &DNSCache{
		cache: make(map[string]string),
	}
}

func (d *DNSCache) Resolve(hostname string) (string, bool) {
	d.mutex.RLock()
	ip, found := d.cache[hostname]
	d.mutex.RUnlock()
	return ip, found
}

func (d *DNSCache) Set(hostname, ip string) {
	d.mutex.Lock()
	d.cache[hostname] = ip
	d.mutex.Unlock()
}

func getHTTPClient() *http.Client {
	transport := &http.Transport{
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
			DualStack: true,
		}).DialContext,
	}
	
	return &http.Client{
		Timeout:   2 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func expandTargets(targets []string) []string {
	var expanded []string
	for _, t := range targets {
		if strings.Contains(t, "/") {
			_, ipnet, err := net.ParseCIDR(t)
			if err == nil {
				for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
					expanded = append(expanded, ip.String())
				}
			}
		} else {
			expanded = append(expanded, t)
		}
	}
	return expanded
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func preprocessTargets(targets []string) []ProcessedTarget {
	processed := make([]ProcessedTarget, 0, len(targets))
	
	for _, target := range targets {
		pt := ProcessedTarget{URL: target}
		
		if ip := net.ParseIP(target); ip != nil {
			pt.IsIP = true
			pt.Resolved = target
		}
		
		if !strings.HasPrefix(pt.URL, "http://") && !strings.HasPrefix(pt.URL, "https://") {
			pt.URL = "http://" + pt.URL
		}
		
		processed = append(processed, pt)
	}
	
	return processed
}

func evaluateCondition(resp *http.Response, body []byte, rule Rule) bool {
	if rule.Exclude != "" {
		excludeValue := rule.Exclude
		if !rule.CaseSensitive {
			excludeValue = strings.ToLower(excludeValue)
		}
		if strings.Contains(prepareString(string(body), rule.CaseSensitive), excludeValue) {
			return false
		}
	}

	conditions := strings.Split(rule.Condition, "&&")
	for _, c := range conditions {
		parts := strings.SplitN(c, "=", 2)
		if len(parts) != 2 {
			return false
		}
		key := strings.TrimSpace(parts[0])
		value := strings.Trim(parts[1], "` ")

		if !rule.CaseSensitive {
			value = strings.ToLower(value)
		}

		switch key {
		case "title":
			title := extractTitle(body)
			if !strings.Contains(prepareString(title, rule.CaseSensitive), value) {
				return false
			}
		case "body":
			if !strings.Contains(prepareString(string(body), rule.CaseSensitive), value) {
				return false
			}
		case "headers":
			headerKey := strings.Split(value, ":")[0]
			if headerValues, ok := resp.Header[headerKey]; ok {
				found := false
				for _, hv := range headerValues {
					if strings.Contains(prepareString(hv, rule.CaseSensitive), value) {
						found = true
						break
					}
				}
				if !found {
					return false
				}
			} else {
				return false
			}
		case "md5":
			sum := fmt.Sprintf("%x", md5.Sum(body))
			if sum != value {
				return false
			}
		case "status_code":
			if fmt.Sprintf("%d", resp.StatusCode) != value {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func prepareString(s string, caseSensitive bool) string {
	if caseSensitive {
		return s
	}
	return strings.ToLower(s)
}

func extractTitle(body []byte) string {
	r := strings.NewReader(string(body))
	doc, err := html.Parse(r)
	if err != nil {
		return ""
	}
	var f func(*html.Node) string
	f = func(n *html.Node) string {
		if n.Type == html.ElementNode && n.Data == "title" && n.FirstChild != nil {
			return n.FirstChild.Data
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if t := f(c); t != "" {
				return t
			}
		}
		return ""
	}
	return f(doc)
}

func scanTarget(target ProcessedTarget) (string, []string) {
	client := getHTTPClient()
	orig := target.URL
	
	displayTarget := strings.TrimPrefix(orig, "http://")
	displayTarget = strings.TrimPrefix(displayTarget, "https://")
	
	ctxHead, cancelHead := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancelHead()
	
	reqHead, err := http.NewRequestWithContext(ctxHead, "HEAD", target.URL, nil)
	if err != nil {
		return "", nil
	}
	reqHead.Header.Set("User-Agent", "Mozilla/5.0")
	
	resp, err := client.Do(reqHead)
	if err != nil {
		return "", nil
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	
	var detected []string
	var detectedMutex sync.Mutex
	var wg sync.WaitGroup
	
	ruleWorkers := 3
	if len(rules) < 3 {
		ruleWorkers = len(rules)
	}
	
	ruleChan := make(chan Rule, len(rules))
	
	for i := 0; i < ruleWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for rule := range ruleChan {
				fullURL := target.URL
				if !strings.HasSuffix(target.URL, "/") && rule.Path != "" {
					fullURL += "/"
				}
				fullURL += strings.TrimPrefix(rule.Path, "/")
				
				ctxRule, cancelRule := context.WithTimeout(context.Background(), 2*time.Second)
				req, err := http.NewRequestWithContext(ctxRule, "GET", fullURL, nil)
				if err != nil {
					cancelRule()
					continue
				}
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36")
				
				resp, err := client.Do(req)
				cancelRule()
				if err != nil {
					continue
				}
				
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				
				if evaluateCondition(resp, body, rule) {
					detectedMutex.Lock()
					if !contains(detected, rule.Brand) {
						detected = append(detected, rule.Brand)
					}
					detectedMutex.Unlock()
				}
			}
		}()
	}
	
	for _, rule := range rules {
		ruleChan <- rule
	}
	close(ruleChan)
	wg.Wait()
	
	if len(detected) > 0 {
		return displayTarget, detected
	}
	return "", nil
}

func contains(arr []string, str string) bool {
	for _, a := range arr {
		if a == str {
			return true
		}
	}
	return false
}

func printBanner() {
        fmt.Fprintln(os.Stderr, colorCyan+"┌───────────────────────────────────────────────────────────────┐")
	fmt.Fprintln(os.Stderr, "│"+colorGreen+"                   CamTRON - Camera Scanner"+colorCyan+"                    │")
	fmt.Fprintln(os.Stderr, "│"+colorGray+"           Automated Detection of Surveillance Devices"+colorCyan+"         │")
        fmt.Fprintln(os.Stderr, "│"+colorGreen+"                    Coded By - K3ysTr0K3R"+colorCyan+"                      │")
        fmt.Fprintln(os.Stderr, "└───────────────────────────────────────────────────────────────┘"+colorReset)
	fmt.Fprintln(os.Stderr)
}

type outputManager struct {
	mu sync.Mutex
}

func (o *outputManager) printProgress(processed, total, found int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	
	percent := float64(processed) / float64(total) * 100.0
	
	fmt.Fprintf(os.Stderr, "\r\033[K"+colorCyan+"[%s] "+colorGreen+"Progress: %d/%d (%.1f%%) | Found: %d"+colorReset,
		time.Now().Format("15:04:05.000"),
		processed,
		total,
		percent,
		found)
}

func (o *outputManager) printResult(result scanResult) {
	o.mu.Lock()
	defer o.mu.Unlock()
	
	fmt.Fprint(os.Stderr, "\r\033[K")
	
	fmt.Printf(
		colorCyan+"[%s] "+colorGreen+"[+] "+colorYellow+"%s"+colorReset+
			colorWhite+" : "+colorPurple+"%s"+colorReset+"\n",
		time.Now().Format("15:04:05.000"),
		result.host,
		strings.Join(result.brands, ", "),
	)
}

func (o *outputManager) finalProgress(total, found int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	
	fmt.Fprintf(os.Stderr, "\r\033[K"+colorCyan+"[%s] "+colorGreen+"Progress: %d/%d (100.0%%) | Found: %d"+colorReset+"\n",
		time.Now().Format("15:04:05.000"),
		total,
		total,
		found)
}

func main() {
	log.SetOutput(io.Discard)
	
	os.Setenv("GODEBUG", "http2client=0")
	
	printBanner()

	urlFlag := flag.String("u", "", "Scan a single URL")
	ipFlag := flag.String("ip", "", "Scan a single IP/CIDR")
	fileFlag := flag.String("f", "", "File with targets (one per line)")
	threadsFlag := flag.Int("t", 50, "Threads (increased for file scanning)")
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
		file, err := os.Open(*fileFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, colorRed+"[%s] Error opening file: %v\n"+colorReset, time.Now().Format("15:04:05.000"), err)
			return
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				targets = append(targets, line)
			}
		}
		file.Close()
	}

	if len(targets) == 0 {
		fmt.Fprintf(os.Stderr, colorRed+"[!] Please specify -u, -ip, or -f\n"+colorReset)
		flag.Usage()
		return
	}

	expandedTargets := expandTargets(targets)
	processedTargets := preprocessTargets(expandedTargets)
	totalTargets := len(processedTargets)
	
	fmt.Fprintf(os.Stderr, colorCyan+"[%s] Loaded %d scan targets\n"+colorReset, 
		time.Now().Format("15:04:05.000"), totalTargets)
	fmt.Fprintf(os.Stderr, colorCyan+"[%s] Using %d threads for scanning\n"+colorReset,
		time.Now().Format("15:04:05.000"), *threadsFlag)

	var writer *csv.Writer
	var csvFile *os.File
	if *outputFlag != "" {
		var err error
		if *appendFlag {
			csvFile, err = os.OpenFile(*outputFlag, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		} else {
			csvFile, err = os.Create(*outputFlag)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, colorRed+"[%s] Error opening output file: %v\n"+colorReset, 
				time.Now().Format("15:04:05.000"), err)
			return
		}
		writer = csv.NewWriter(csvFile)
		if !*appendFlag {
			writer.Write([]string{"Target", "Brands"})
			writer.Flush()
		}
		defer csvFile.Close()
	}

	dnsCache := NewDNSCache()
	_ = dnsCache

	output := &outputManager{}
	
	type job struct {
		target ProcessedTarget
		index  int
	}
	
	jobs := make(chan job, *threadsFlag*10)
	results := make(chan scanResult, *threadsFlag*10)
	
	var wgWorkers sync.WaitGroup
	for i := 0; i < *threadsFlag; i++ {
		wgWorkers.Add(1)
		go func(workerID int) {
			defer wgWorkers.Done()
			for job := range jobs {
				host, brands := scanTarget(job.target)
				if host != "" {
					results <- scanResult{host: host, brands: brands}
				} else {
					results <- scanResult{}
				}
			}
		}(i)
	}
	
	var wgCollector sync.WaitGroup
	wgCollector.Add(1)
	
	startTime := time.Now()
	
	var processedCount int
	var foundCount int
	
	progressTicker := time.NewTicker(100 * time.Millisecond)
	defer progressTicker.Stop()
	
	go func() {
		defer wgCollector.Done()
		
		lastUpdate := time.Now()
		
		for {
			select {
			case result, ok := <-results:
				if !ok {
					return
				}
				
				processedCount++
				
				if result.host != "" {
					foundCount++
					
					output.printResult(result)
					
					if writer != nil {
						writer.Write([]string{result.host, strings.Join(result.brands, ", ")})
						writer.Flush()
					}
				}
				
				if time.Since(lastUpdate) > 100*time.Millisecond || processedCount == totalTargets {
					output.printProgress(processedCount, totalTargets, foundCount)
					lastUpdate = time.Now()
				}
				
				if processedCount >= totalTargets {
					output.finalProgress(totalTargets, foundCount)
					return
				}
				
			case <-progressTicker.C:
				if processedCount < totalTargets {
					output.printProgress(processedCount, totalTargets, foundCount)
				}
			}
		}
	}()
	
	go func() {
		for i, target := range processedTargets {
			jobs <- job{target: target, index: i}
		}
		close(jobs)
	}()
	
	wgWorkers.Wait()
	close(results)
	
	wgCollector.Wait()
	
	elapsed := time.Since(startTime)
	rate := float64(totalTargets) / elapsed.Seconds()
	
	if *outputFlag != "" {
		fmt.Fprintf(os.Stderr, colorCyan+"\n[%s] Results saved to "+colorYellow+"%s"+colorReset+"\n",
			time.Now().Format("15:04:05.000"),
			*outputFlag,
		)
	}
	
	fmt.Fprintf(os.Stderr,
		colorCyan+"[%s] Scan completed: "+colorGreen+"%d"+colorCyan+" devices found from "+colorGreen+"%d"+colorCyan+" targets\n"+colorReset,
		time.Now().Format("15:04:05.000"),
		foundCount,
		totalTargets,
	)
	
	fmt.Fprintf(os.Stderr,
		colorCyan+"[%s] Scan time: "+colorGreen+"%.2f seconds"+colorCyan+" | Rate: "+colorGreen+"%.1f targets/second\n"+colorReset,
		time.Now().Format("15:04:05.000"),
		elapsed.Seconds(),
		rate,
	)
}
