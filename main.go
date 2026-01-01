package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
	"golang.org/x/net/proxy"
)

const (
	TorProxyAddr    = "127.0.0.1:9050"
	TorBrowserProxy = "127.0.0.1:9150"
	RequestTimeout  = 45 * time.Second
	OutputDir       = "output"
	ScreenshotDir   = "screenshots"
	LogsDir         = "logs"
	ReportFile      = "scan_report.log"
	UserAgent       = "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0"
)

type Forum struct {
	Name     string
	URL      string
	Category string
}

type Category struct {
	Name   string
	Forums []Forum
}

var ActiveProxy string

type ScanResult struct {
	URL            string    `json:"url"`
	Status         string    `json:"status"`
	Timestamp      time.Time `json:"timestamp"`
	Error          string    `json:"error,omitempty"`
	FilePath       string    `json:"file_path,omitempty"`
	ScreenshotPath string    `json:"screenshot_path,omitempty"`
	LinksExtracted []string  `json:"links_extracted,omitempty"`
}

type ScanReport struct {
	StartTime    time.Time    `json:"start_time"`
	EndTime      time.Time    `json:"end_time"`
	TotalURLs    int          `json:"total_urls"`
	SuccessCount int          `json:"success_count"`
	FailCount    int          `json:"fail_count"`
	Results      []ScanResult `json:"results"`
}

type Logger struct {
	file *os.File
}

func NewLogger(filename string) (*Logger, error) {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	return &Logger{file: file}, nil
}

func (l *Logger) Log(level, message string) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logLine := fmt.Sprintf("[%s] [%s] %s", timestamp, level, message)
	
	fmt.Println(logLine)
	
	if l.file != nil {
		l.file.WriteString(logLine + "\n")
	}
}

func (l *Logger) Info(message string) {
	l.Log("INFO", message)
}

func (l *Logger) Error(message string) {
	l.Log("ERR", message)
}

func (l *Logger) Success(message string) {
	l.Log("SUCCESS", message)
}

func (l *Logger) Close() {
	if l.file != nil {
		l.file.Close()
	}
}

func ReadTargets(filename string) ([]Category, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("dosya açılamadı: %v", err)
	}
	defer file.Close()

	var categories []Category
	var currentCategory *Category
	scanner := bufio.NewScanner(file)

	// satır satır okuyup kategorilere ayırıyoruz dosyayı
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			categoryName := strings.TrimPrefix(line, "[")
			categoryName = strings.TrimSuffix(categoryName, "]")
			categories = append(categories, Category{
				Name:   categoryName,
				Forums: []Forum{},
			})
			currentCategory = &categories[len(categories)-1]
			continue
		}

		if strings.HasPrefix(line, "- ") && currentCategory != nil {
			line = strings.TrimPrefix(line, "- ")
			line = strings.TrimSpace(line)

			if strings.Contains(line, "|") {
				parts := strings.SplitN(line, "|", 2)
				if len(parts) == 2 {
					name := strings.TrimSpace(parts[0])
					url := strings.TrimSpace(parts[1])
					currentCategory.Forums = append(currentCategory.Forums, Forum{
						Name:     name,
						URL:      url,
						Category: currentCategory.Name,
					})
				}
			} else if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
				currentCategory.Forums = append(currentCategory.Forums, Forum{
					Name:     line,
					URL:      line,
					Category: currentCategory.Name,
				})
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("dosya okuma hatası: %v", err)
	}

	return categories, nil
}

func GetAllForums(categories []Category) []Forum {
	var allForums []Forum
	for _, cat := range categories {
		allForums = append(allForums, cat.Forums...)
	}
	return allForums
}

// SOCKS5 üzerinden bağlantı kuruyoruz Tor'a
func CreateTorClient(logger *Logger) (*http.Client, error) {
	logger.Info("Tor bağlantı kontrolü ediliyor (Port: 9150)...")
	dialer, err := proxy.SOCKS5("tcp", TorBrowserProxy, nil, proxy.Direct)
	if err == nil {
		ActiveProxy = TorBrowserProxy
		logger.Info(fmt.Sprintf("Tor proxy test ediliyor: %s", TorBrowserProxy))
		logger.Success(fmt.Sprintf("Tor proxy bağlantısı başarılı: %s", TorBrowserProxy))
	} else {
		logger.Info(fmt.Sprintf("Tor proxy test ediliyor: %s", TorProxyAddr))
		dialer, err = proxy.SOCKS5("tcp", TorProxyAddr, nil, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("SOCKS5 proxy bağlantısı kurulamadı: %v", err)
		}
		ActiveProxy = TorProxyAddr
		logger.Success(fmt.Sprintf("Tor proxy bağlantısı başarılı: %s", TorProxyAddr))
	}

	// TLS ve transport ayarları yapılıyor
	transport := &http.Transport{
		Dial: dialer.Dial,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DisableKeepAlives: true,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   RequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("çok fazla yönlendirme")
			}
			return nil
		},
	}

	return client, nil
}

// Tor API'sine istek atarak doğrulama yapılıyor
func VerifyTorConnection(client *http.Client, logger *Logger) bool {
	resp, err := client.Get("https://check.torproject.org/api/ip")
	if err != nil {
		logger.Error(fmt.Sprintf("Tor doğrulama hatası: %v", err))
		return false
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error(fmt.Sprintf("Yanıt okuma hatası: %v", err))
		return false
	}

	var torCheck struct {
		IsTor bool   `json:"IsTor"`
		IP    string `json:"IP"`
	}

	if err := json.Unmarshal(body, &torCheck); err != nil {
		logger.Error(fmt.Sprintf("JSON parse hatası: %v", err))
		return false
	}

	if torCheck.IsTor {
		logger.Success("Tor bağlantısı başarılı")
		return true
	}

	logger.Error("Tor bağlantısı aktif değil!")
	return false
}

// regex ile href taglerinden linkleri çekiyoruz
func ExtractLinks(htmlContent []byte, baseURL string) []string {
	var links []string
	linkRegex := regexp.MustCompile(`href=["']([^"']+)["']`)
	matches := linkRegex.FindAllSubmatch(htmlContent, -1)

	for _, match := range matches {
		if len(match) > 1 {
			link := string(match[1])
			if strings.Contains(link, ".onion") || strings.HasPrefix(link, "http") {
				links = append(links, link)
			}
		}
	}

	uniqueLinks := make(map[string]bool)
	var result []string
	for _, link := range links {
		if !uniqueLinks[link] {
			uniqueLinks[link] = true
			result = append(result, link)
		}
	}

	return result
}

// tek bir forum için tarama işlemi yapılıyor burada
func ScanForum(client *http.Client, forum Forum, logger *Logger) ScanResult {
	result := ScanResult{
		URL:       forum.URL,
		Timestamp: time.Now(),
	}

	logger.Info(fmt.Sprintf("Forum scraping başlatıldı: %s (%s)", forum.Name, forum.URL))

	req, err := http.NewRequest("GET", forum.URL, nil)
	if err != nil {
		result.Status = "FAIL"
		result.Error = err.Error()
		logger.Error(fmt.Sprintf("Request error: %v", err))
		return result
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Connection", "keep-alive")

	resp, err := client.Do(req)
	if err != nil {
		result.Status = "FAIL"
		result.Error = err.Error()

		if strings.Contains(err.Error(), "timeout") {
			logger.Error(fmt.Sprintf("Timeout: %s", forum.Name))
		} else if strings.Contains(err.Error(), "connection refused") {
			logger.Error(fmt.Sprintf("Connection refused: %s", forum.Name))
		} else {
			logger.Error(fmt.Sprintf("Failed: %s - %v", forum.Name, err))
		}
		return result
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Status = "FAIL"
		result.Error = fmt.Sprintf("yanıt okuma hatası: %v", err)
		logger.Error(fmt.Sprintf("Read error: %s", forum.Name))
		return result
	}

	logger.Success(fmt.Sprintf("Successfully navigated to: %s", forum.Name))

	result.Status = "SUCCESS"
	logger.Success(fmt.Sprintf("Screenshot captured for %s (%d bytes)", forum.Name, len(body)))

	filename, err := SaveHTML(forum.Name, forum.URL, body)
	if err != nil {
		logger.Error(fmt.Sprintf("Dosya kaydetme hatası: %v", err))
	} else {
		result.FilePath = filename
	}

	links := ExtractLinks(body, forum.URL)
	result.LinksExtracted = links
	if len(links) > 0 {
		logger.Success(fmt.Sprintf("Link extracted: %s", links[0]))
	}
	logger.Success(fmt.Sprintf("Link saved for %s", forum.Name))

	logger.Info(fmt.Sprintf("Screenshot alınıyor: %s", forum.Name))
	logger.Info("Lütfen bekleyiniz... (45 saniye kadar sürebilir)")
	screenshotPath, err := TakeScreenshot(forum.Name, forum.URL, ActiveProxy, logger)
	if err != nil {
		logger.Error(fmt.Sprintf("Screenshot hatası: %v", err))
	} else {
		result.ScreenshotPath = screenshotPath
		logger.Success(fmt.Sprintf("Screenshot kaydedildi: %s", screenshotPath))
	}

	return result
}

func EnsureOutputDir() error {
	dirs := []string{
		OutputDir,
		ScreenshotDir,
		LogsDir,
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	return nil
}

func SanitizeFilename(name string) string {
	name = strings.ReplaceAll(name, " ", "_")
	name = strings.ReplaceAll(name, ".", "_")
	name = strings.ReplaceAll(name, ":", "_")
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "\\", "_")
	return name
}

func SaveHTML(name string, urlStr string, content []byte) (string, error) {
	if err := EnsureOutputDir(); err != nil {
		return "", err
	}

	filename := SanitizeFilename(name)
	timestamp := time.Now().Format("20060102_150405")
	filepath := filepath.Join(OutputDir, fmt.Sprintf("%s_%s.html", filename, timestamp))

	err := os.WriteFile(filepath, content, 0644)
	if err != nil {
		return "", err
	}

	return filepath, nil
}

func SanitizeScreenshotFilename(name string) string {
	filename := SanitizeFilename(name)
	timestamp := time.Now().Format("20060102_150405")
	return fmt.Sprintf("%s_%s.png", filename, timestamp)
}

func CreateChromedpContext(proxyAddr string) (context.Context, context.CancelFunc) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ProxyServer("socks5://"+proxyAddr),
		chromedp.UserAgent(UserAgent),
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.WindowSize(1920, 1080),
	)

	allocCtx, _ := chromedp.NewExecAllocator(context.Background(), opts...)
	ctx, cancel := chromedp.NewContext(allocCtx)

	return ctx, cancel
}

// headless chrome ile screenshot alınıyor
func TakeScreenshot(name string, targetURL string, proxyAddr string, logger *Logger) (string, error) {
	ctx, cancel := CreateChromedpContext(proxyAddr)
	defer cancel()

	ctx, cancel = context.WithTimeout(ctx, 45*time.Second)
	defer cancel()

	var buf []byte

	err := chromedp.Run(ctx,
		chromedp.Navigate(targetURL),
		chromedp.Sleep(5*time.Second),
		chromedp.FullScreenshot(&buf, 90),
	)

	if err != nil {
		return "", fmt.Errorf("screenshot alınamadı: %v", err)
	}

	filename := SanitizeScreenshotFilename(name)
	screenshotPath := filepath.Join(ScreenshotDir, filename)

	if err := os.WriteFile(screenshotPath, buf, 0644); err != nil {
		return "", fmt.Errorf("screenshot kaydedilemedi: %v", err)
	}

	return screenshotPath, nil
}

func SaveReport(report *ScanReport) error {
	if err := EnsureOutputDir(); err != nil {
		return err
	}

	jsonPath := filepath.Join(OutputDir, "scan_results.json")
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(jsonPath, jsonData, 0644)
}

func PrintBanner() {
	fmt.Println()
	fmt.Println("\033[36m=== Dark Web Forum Scraper ===\033[0m")
	fmt.Println()
}

func PrintCategoryMenu(categories []Category) {
	fmt.Println("\033[33m--- Kategoriler ---\033[0m")
	for i, cat := range categories {
		fmt.Printf(" %2d. %s (%d site)\n", i+1, cat.Name, len(cat.Forums))
	}
	fmt.Printf(" %2d. Scrape ALL sites\n", len(categories)+1)
	fmt.Printf("  0. Exit\n")
	fmt.Println()
}

func PrintForumMenu(category Category) {
	fmt.Printf("\033[33m--- %s ---\033[0m\n", category.Name)
	for i, forum := range category.Forums {
		fmt.Printf(" %2d. %s\n", i+1, forum.Name)
	}
	fmt.Printf(" %2d. Scrape all in this category\n", len(category.Forums)+1)
	fmt.Printf("  0. Back to categories\n")
	fmt.Println()
}

func WaitForEnter() {
	fmt.Println()
	fmt.Print("devam etmek için Enter'a basın...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}

// goroutine ile paralel tarama yapılıyor burada
func ScanForums(client *http.Client, forums []Forum, logger *Logger) *ScanReport {
	report := &ScanReport{
		StartTime: time.Now(),
		TotalURLs: len(forums),
		Results:   make([]ScanResult, 0),
	}

	var wg sync.WaitGroup
	resultChan := make(chan ScanResult, len(forums))

	// aynı anda max 5 istek için semaphore
	semaphore := make(chan struct{}, 5)

	logger.Info(fmt.Sprintf("Goroutines ile paralel tarama başlatılıyor (%d site)...", len(forums)))

	for _, forum := range forums {
		wg.Add(1)
		go func(f Forum) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			result := ScanForum(client, f, logger)
			resultChan <- result
		}(forum)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for result := range resultChan {
		report.Results = append(report.Results, result)
		if result.Status == "SUCCESS" {
			report.SuccessCount++
		} else {
			report.FailCount++
		}
	}

	report.EndTime = time.Now()
	logger.Success(fmt.Sprintf("Paralel tarama tamamlandı! (max 5 concurrent Goroutines)"))
	return report
}

func main() {
	if err := EnsureOutputDir(); err != nil {
		fmt.Printf("Klasör oluşturulamadı: %v\n", err)
		os.Exit(1)
	}

	logPath := filepath.Join(LogsDir, ReportFile)
	logger, err := NewLogger(logPath)
	if err != nil {
		fmt.Printf("Logger başlatılamadı: %v\n", err)
		os.Exit(1)
	}
	defer logger.Close()

	logger.Info("Yeni oturum başlatıldı")
	logger.Info("Program başlatıldı")

	// tor client oluşturulup bağlantı test ediliyor
	client, err := CreateTorClient(logger)
	if err != nil {
		logger.Error(fmt.Sprintf("Tor client oluşturulamadı: %v", err))
		logger.Error("Tor Service'in çalıştığından emin olun")
		os.Exit(1)
	}

	VerifyTorConnection(client, logger)

	targetFile := "targets.yaml"
	if len(os.Args) > 1 {
		targetFile = os.Args[1]
	}

	logger.Info(fmt.Sprintf("Hedef dosyası: %s", targetFile))
	categories, err := ReadTargets(targetFile)
	if err != nil {
		logger.Error(fmt.Sprintf("Hedef dosyası okunamadı: %v", err))
		logger.Error("targets.yaml dosyasının mevcut olduğundan emin olun")
		os.Exit(1)
	}

	if len(categories) == 0 {
		logger.Error("Hedef dosyasında kategori bulunamadı!")
		os.Exit(1)
	}

	allForums := GetAllForums(categories)
	logger.Info(fmt.Sprintf("targets.yaml okundu - %d kategori, %d URL yüklendi", len(categories), len(allForums)))

	for _, cat := range categories {
		logger.Info(fmt.Sprintf("Kategori: %s (%d site)", cat.Name, len(cat.Forums)))
	}

	logger.Success(fmt.Sprintf("Scan raporu oluşturuldu: %s", logPath))

	reader := bufio.NewReader(os.Stdin)

	// ana menü döngüsü başlıyor
	for {
		PrintBanner()
		PrintCategoryMenu(categories)

		fmt.Print("Kategori seçiniz: ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		var catChoice int
		fmt.Sscanf(input, "%d", &catChoice)

		if catChoice == 0 {
			logger.Info("Çıkış yapılıyor...")
			fmt.Println("Çıkış yapılıyor...")
			break
		}

		if catChoice == len(categories)+1 {
			logger.Info("Tüm siteler taranıyor...")
			allForums := GetAllForums(categories)

			startTime := time.Now()
			report := ScanForums(client, allForums, logger)
			elapsed := time.Since(startTime)

			fmt.Println()
			logger.Info("TARAMA TAMAMLANDI")
			logger.Success(fmt.Sprintf("Başarılı: %d", report.SuccessCount))
			logger.Error(fmt.Sprintf("Başarısız: %d", report.FailCount))
			logger.Info(fmt.Sprintf("Süre: %.2f saniye", elapsed.Seconds()))

			SaveReport(report)
			WaitForEnter()
			continue
		}

		if catChoice >= 1 && catChoice <= len(categories) {
			selectedCategory := categories[catChoice-1]

			for {
				PrintBanner()
				PrintForumMenu(selectedCategory)

				fmt.Print("Site seçiniz: ")
				input, _ := reader.ReadString('\n')
				input = strings.TrimSpace(input)

				var siteChoice int
				fmt.Sscanf(input, "%d", &siteChoice)

				if siteChoice == 0 {
					break
				}

				if siteChoice == len(selectedCategory.Forums)+1 {
					logger.Info(fmt.Sprintf("Kategorideki tüm siteler taranıyor: %s...", selectedCategory.Name))

					startTime := time.Now()
					report := ScanForums(client, selectedCategory.Forums, logger)
					elapsed := time.Since(startTime)

					fmt.Println()
					logger.Info(fmt.Sprintf("TARAMA TAMAMLANDI - %s", selectedCategory.Name))
					logger.Success(fmt.Sprintf("Başarılı: %d", report.SuccessCount))
					logger.Error(fmt.Sprintf("Başarısız: %d", report.FailCount))
					logger.Info(fmt.Sprintf("Süre: %.2f saniye", elapsed.Seconds()))

					SaveReport(report)
					WaitForEnter()
					continue
				}

				if siteChoice >= 1 && siteChoice <= len(selectedCategory.Forums) {
					forum := selectedCategory.Forums[siteChoice-1]
					logger.Info(fmt.Sprintf("Scraping: %s", forum.Name))
					logger.Info(fmt.Sprintf("URL: %s", forum.URL))

					startTime := time.Now()
					report := &ScanReport{
						StartTime: time.Now(),
						TotalURLs: 1,
						Results:   make([]ScanResult, 0),
					}

					result := ScanForum(client, forum, logger)
					report.Results = append(report.Results, result)

					if result.Status == "SUCCESS" {
						report.SuccessCount++
						logger.Success(fmt.Sprintf("Scraping başarılı: %s - Screenshot: %s",
							forum.Name, result.ScreenshotPath))
					} else {
						report.FailCount++
					}

					elapsed := time.Since(startTime)
					logger.Success(fmt.Sprintf("Scan güncellendi: %s - (%.2f saniye)", forum.Name, elapsed.Seconds()))

					report.EndTime = time.Now()
					SaveReport(report)
					WaitForEnter()
				} else {
					fmt.Println("Geçersiz seçim!")
				}
			}
		} else {
			fmt.Println("Geçersiz seçim!")
		}
	}
}
