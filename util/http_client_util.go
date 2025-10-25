package util

import (
	"context"
	"crypto/tls"
	"math/rand"
	"net"
	"net/http"
	"time"
)

var dialer = &net.Dialer{
	Timeout:   30 * time.Second,
	KeepAlive: 30 * time.Second,
}

// 浏览器指纹配置
type BrowserProfile struct {
	UserAgent       string
	SecChUa         string
	SecChUaPlatform string
	SecChUaMobile   string
}

// 真实浏览器配置池（UA 和对应的 Sec-CH-UA 必须匹配）
var browserProfiles = []BrowserProfile{
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		SecChUa:         `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`,
		SecChUaPlatform: `"Windows"`,
		SecChUaMobile:   "?0",
	},
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
		SecChUa:         `"Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"`,
		SecChUaPlatform: `"Windows"`,
		SecChUaMobile:   "?0",
	},
	{
		UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		SecChUa:         `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`,
		SecChUaPlatform: `"macOS"`,
		SecChUaMobile:   "?0",
	},
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		SecChUa:         "", // Firefox 不发送这些头
		SecChUaPlatform: "",
		SecChUaMobile:   "",
	},
	{
		UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
		SecChUa:         "",
		SecChUaPlatform: "",
		SecChUaMobile:   "",
	},
	{
		UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
		SecChUa:         "", // Safari 不发送这些头
		SecChUaPlatform: "",
		SecChUaMobile:   "",
	},
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
		SecChUa:         `"Not_A Brand";v="8", "Chromium";v="120", "Microsoft Edge";v="120"`,
		SecChUaPlatform: `"Windows"`,
		SecChUaMobile:   "?0",
	},
}

// 获取随机浏览器配置
func getRandomBrowserProfile() BrowserProfile {
	return browserProfiles[rand.Intn(len(browserProfiles))]
}

func createRealisticTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		// 模拟真实浏览器的 Cipher Suites 顺序
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}
}

// 自定义 RoundTripper 来添加随机 UA
type browserSimulatorTransport struct {
	base http.RoundTripper
}

func (t *browserSimulatorTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// 获取随机浏览器配置
	profile := getRandomBrowserProfile()

	// 设置 User-Agent（如果没有手动设置）
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", profile.UserAgent)
	}

	// 设置基础请求头（模拟真实浏览器）
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	}
	if req.Header.Get("Accept-Language") == "" {
		req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8,en-US;q=0.7")
	}
	if req.Header.Get("Accept-Encoding") == "" {
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	}

	// Chrome 特有的 Client Hints（只有 Chrome/Edge 才发送）
	if profile.SecChUa != "" {
		req.Header.Set("Sec-CH-UA", profile.SecChUa)
		req.Header.Set("Sec-CH-UA-Mobile", profile.SecChUaMobile)
		req.Header.Set("Sec-CH-UA-Platform", profile.SecChUaPlatform)
	}

	// Fetch Metadata 请求头（现代浏览器都会发送）
	if req.Header.Get("Sec-Fetch-Dest") == "" {
		req.Header.Set("Sec-Fetch-Dest", "document")
	}
	if req.Header.Get("Sec-Fetch-Mode") == "" {
		req.Header.Set("Sec-Fetch-Mode", "navigate")
	}
	if req.Header.Get("Sec-Fetch-Site") == "" {
		// 首次访问通常是 none，如果有 Referer 则是 same-origin 或 cross-site
		if req.Header.Get("Referer") == "" {
			req.Header.Set("Sec-Fetch-Site", "none")
		} else {
			req.Header.Set("Sec-Fetch-Site", "same-origin")
		}
	}
	if req.Header.Get("Sec-Fetch-User") == "" && req.Method == "GET" {
		req.Header.Set("Sec-Fetch-User", "?1")
	}

	// 设置连接相关头
	if req.Header.Get("Connection") == "" {
		req.Header.Set("Connection", "keep-alive")
	}

	// DNT (Do Not Track) - 部分用户会启用
	if rand.Float32() < 0.3 { // 30% 的概率启用
		req.Header.Set("DNT", "1")
	}

	// Upgrade-Insecure-Requests（HTTPS 升级请求）
	if req.URL.Scheme == "https" && req.Header.Get("Upgrade-Insecure-Requests") == "" {
		req.Header.Set("Upgrade-Insecure-Requests", "1")
	}

	// Cache-Control（部分浏览器会发送）
	if req.Header.Get("Cache-Control") == "" && rand.Float32() < 0.2 {
		req.Header.Set("Cache-Control", "max-age=0")
	}

	return t.base.RoundTrip(req)
}

var defaultTransport = &browserSimulatorTransport{
	base: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       createRealisticTLSConfig(),
		// 模拟浏览器的连接行为
		MaxIdleConnsPerHost: 10,
		MaxConnsPerHost:     0, // 0 表示无限制
		DisableCompression:  false,
	},
}

// CreateHTTPClient Create Default HTTP Client
func CreateHTTPClient() *http.Client {
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: defaultTransport,
		// 自动处理重定向（最多 10 次）
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

var noProxyTcp4Transport = &browserSimulatorTransport{
	base: &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", address)
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       createRealisticTLSConfig(),
	},
}

var noProxyTcp6Transport = &browserSimulatorTransport{
	base: &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp6", address)
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       createRealisticTLSConfig(),
	},
}

// CreateNoProxyHTTPClient Create NoProxy HTTP Client
func CreateNoProxyHTTPClient(network string) *http.Client {
	if network == "tcp6" {
		return &http.Client{
			Timeout:   30 * time.Second,
			Transport: noProxyTcp6Transport,
		}
	}

	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: noProxyTcp4Transport,
	}
}

// SetInsecureSkipVerify 将所有 http.Transport 的 InsecureSkipVerify 设置为指定值
// 注意：此函数应该在程序启动时、创建任何 HTTP 客户端之前调用
func SetInsecureSkipVerify() {
	transports := []*http.Transport{
		defaultTransport.base.(*http.Transport),
		noProxyTcp4Transport.base.(*http.Transport),
		noProxyTcp6Transport.base.(*http.Transport),
	}

	for _, transport := range transports {
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = createRealisticTLSConfig()
		}
		transport.TLSClientConfig.InsecureSkipVerify = true
	}
}

// SetReferer 便捷函数：为请求设置 Referer（模拟从某个页面跳转过来）
func SetReferer(req *http.Request, referer string) {
	req.Header.Set("Referer", referer)
	// 有 Referer 时，调整 Sec-Fetch-Site
	if referer != "" {
		req.Header.Set("Sec-Fetch-Site", "same-origin")
	}
}

// AddCookies 便捷函数：添加 Cookie（模拟已登录状态）
func AddCookies(req *http.Request, cookies map[string]string) {
	for name, value := range cookies {
		req.AddCookie(&http.Cookie{
			Name:  name,
			Value: value,
		})
	}
}
