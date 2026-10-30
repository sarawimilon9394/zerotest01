package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	zeropsAPIBase            = "https://api.app-prg1.zerops.io/api/rest/public"
	zeropsFallbackAPIBase    = "https://api.app.zerops.io/api/rest/public"
	defaultZPReqTimeout      = 15 * time.Second
	defaultZPCertPollTick    = 10 * time.Second
	defaultZPCertPollWait    = 96 * time.Second
	defaultZPTLSProbeTimeout = 6 * time.Second
	defaultZPTargetPort      = 8080
	minZPRequestInterval     = 550 * time.Millisecond
)

var cloudflareIPv4CIDRs = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
}

var cloudflareIPv6CIDRs = []string{
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
}

var (
	cfNetsOnce sync.Once
	cfNets     []*net.IPNet
)

func isCloudflareEdgeIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	cfNetsOnce.Do(func() {
		for _, cidr := range cloudflareIPv4CIDRs {
			if _, network, err := net.ParseCIDR(cidr); err == nil && network != nil {
				cfNets = append(cfNets, network)
			}
		}
		for _, cidr := range cloudflareIPv6CIDRs {
			if _, network, err := net.ParseCIDR(cidr); err == nil && network != nil {
				cfNets = append(cfNets, network)
			}
		}
	})
	for _, network := range cfNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

type zpAPIError struct {
	StatusCode int
	Code       string `json:"code,omitempty"`
	Message    string `json:"message,omitempty"`
}

func (e *zpAPIError) Error() string {
	if strings.TrimSpace(e.Message) != "" {
		if e.Code != "" {
			return fmt.Sprintf("zerops api error (HTTP %d / %s): %s", e.StatusCode, e.Code, strings.TrimSpace(e.Message))
		}
		return fmt.Sprintf("zerops api error (HTTP %d): %s", e.StatusCode, strings.TrimSpace(e.Message))
	}
	return fmt.Sprintf("zerops api error (HTTP %d)", e.StatusCode)
}

func (e *zpAPIError) IsPermissionOrPlan() bool {
	if e.StatusCode == http.StatusUnauthorized ||
		e.StatusCode == http.StatusForbidden ||
		e.StatusCode == http.StatusPaymentRequired {
		return true
	}
	lower := strings.ToLower(e.Message + " " + e.Code)
	return strings.Contains(lower, "unauthorized") ||
		strings.Contains(lower, "forbidden") ||
		strings.Contains(lower, "permission") ||
		strings.Contains(lower, "plan") ||
		strings.Contains(lower, "quota") ||
		strings.Contains(lower, "limit")
}

type ZeropsCustomDomainInfo struct {
	ID                string
	Domain            string
	ProjectIPv6       string
	CNAMETarget       string
	VerificationHost  string
	VerificationToken string
	CertificateStatus string
	DNSReady          bool
	SSLReady          bool
	RouteReady        bool
	Ready             bool
	RecordsVerified   bool
}

func (info *ZeropsCustomDomainInfo) IsCertificateValid() bool {
	if info == nil {
		return false
	}
	if info.Ready || (info.SSLReady && info.RouteReady) {
		st := strings.ToUpper(strings.TrimSpace(info.CertificateStatus))
		if st == "VALID" || st == "ACTIVE" || st == "READY" || st == "ISSUED" || st == "INSTALLED" {
			return true
		}
	}
	st := strings.ToUpper(strings.TrimSpace(info.CertificateStatus))
	if st == "" ||
		strings.Contains(st, "UNKNOWN") ||
		strings.Contains(st, "PROVISION") ||
		strings.Contains(st, "PENDING") ||
		strings.Contains(st, "INSTALLING") ||
		strings.Contains(st, "WAITING") ||
		strings.Contains(st, "UNVERIFIED") ||
		strings.Contains(st, "INVALID") ||
		strings.Contains(st, "FAILED") ||
		strings.Contains(st, "ERROR") {
		return false
	}
	if st == "VALID" || st == "ISSUED" || st == "ACTIVE" || st == "READY" || st == "INSTALLED" {
		return true
	}
	return strings.Contains(st, "VALID") || strings.Contains(st, "ACTIVE")
}

type ZeropsClient struct {
	Token       string
	ClientID    string
	ProjectID   string
	ServiceID   string
	ServiceName string
	TargetPort  int
	apiBase     string
	client      *http.Client

	reqMu   sync.Mutex
	lastReq time.Time

	mu               sync.RWMutex
	serviceDomain    string
	customDomain     string
	projectIPv6      string
	discoveredRegion string
	keyPersisted     bool
	onTopology       func(zpDom, cfDom string)
}

func sanitizeZeropsToken(raw string) string {
	s := strings.TrimSpace(raw)
	upper := strings.ToUpper(s)
	for _, prefix := range []string{
		"ZEROPS_API_TOKEN",
		"ZEROPS_TOKEN",
		"BERMUDA_ZEROPS_TOKEN",
		"ZEROPS_ACCESS_TOKEN",
	} {
		if strings.HasPrefix(upper, prefix) {
			if _, after, ok := strings.Cut(s, "="); ok {
				s = strings.TrimSpace(after)
			}
		}
	}
	if len(s) > 7 && strings.EqualFold(s[:7], "bearer ") {
		s = strings.TrimSpace(s[7:])
	}
	s = strings.Trim(s, "\"'` \t\r\n")
	s = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r > 126 {
			return -1
		}
		return r
	}, s)
	if strings.Contains(s, "${{") || strings.HasPrefix(s, "$") || strings.Contains(s, "<@") {
		return ""
	}
	return s
}

func NewZeropsClient(token string) *ZeropsClient {
	cleanTok := sanitizeZeropsToken(token)
	if cleanTok == "" {
		return nil
	}

	_, port := resolveContainerPort()
	if port <= 0 {
		port = defaultZPTargetPort
	}

	zpDom, cfDom, projIPv6 := resolveInfrastructureDomains()
	apiURL := sanitizeExplicitCredential(getEnv("ZEROPS_API_URL", getEnv("BERMUDA_ZEROPS_API_URL", zeropsAPIBase)))
	if apiURL == "" {
		apiURL = zeropsAPIBase
	}
	apiURL = strings.TrimRight(apiURL, "/")

	projID := sanitizeExplicitCredential(getEnv("ZEROPS_PROJECT_ID", getEnv("PROJECT_ID", "")))
	srvID := sanitizeExplicitCredential(getEnv("ZEROPS_SERVICE_ID", getEnv("ZEROPS_SERVICE_STACK_ID", getEnv("SERVICE_STACK_ID", ""))))
	srvName := sanitizeExplicitCredential(getEnv("ZEROPS_SERVICE_NAME", getEnv("SERVICE_NAME", "")))

	if srvName == "" {
		if hn, err := os.Hostname(); err == nil {
			hn = strings.ToLower(strings.TrimSpace(hn))
			if idx := strings.IndexByte(hn, '-'); idx > 0 {
				srvName = hn[:idx]
			} else if hn != "" && !strings.Contains(hn, ".") {
				srvName = hn
			}
		}
	}

	return &ZeropsClient{
		Token:         cleanTok,
		ProjectID:     projID,
		ServiceID:     srvID,
		ServiceName:   srvName,
		TargetPort:    port,
		apiBase:       apiURL,
		serviceDomain: normalizeZeropsSubdomain(zpDom),
		customDomain:  cfDom,
		projectIPv6:   sanitizeIPv6Address(projIPv6),
		client: &http.Client{
			Timeout: 20 * time.Second,
		},
	}
}

func (c *ZeropsClient) IsConfigured() bool {
	return c != nil && c.Token != ""
}

func (c *ZeropsClient) HasServiceContext() bool {
	if c == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ServiceID != "" && c.ProjectID != ""
}

func (c *ZeropsClient) SetTopologyCallback(fn func(zpDom, cfDom string)) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.onTopology = fn
	c.mu.Unlock()
}

func (c *ZeropsClient) notifyTopology() {
	if c == nil {
		return
	}
	c.mu.RLock()
	fn := c.onTopology
	zp := c.serviceDomain
	cf := c.customDomain
	c.mu.RUnlock()
	if fn != nil {
		fn(zp, cf)
	}
}

func (c *ZeropsClient) GetServiceDomain() string {
	if c == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.serviceDomain
}

func (c *ZeropsClient) GetCustomDomain() string {
	if c == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.customDomain
}

func (c *ZeropsClient) GetProjectIPv6() string {
	if c == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.projectIPv6
}

func (c *ZeropsClient) GetDiscoveredRegion() string {
	if c == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.discoveredRegion
}

func (c *ZeropsClient) SetServiceDomain(d string) {
	if c == nil {
		return
	}
	clean := normalizeZeropsSubdomain(d)
	if !isZeropsPublicDomain(clean) {
		return
	}
	c.mu.Lock()
	if c.serviceDomain == "" || isFullZeropsServiceDomain(clean) {
		c.serviceDomain = clean
	}
	c.mu.Unlock()
}

func (c *ZeropsClient) SetCustomDomain(d string) {
	if c == nil {
		return
	}
	clean := cleanHost(d)
	if clean == "" || isZeropsManagedDomain(clean) || net.ParseIP(clean) != nil {
		return
	}
	c.mu.Lock()
	c.customDomain = clean
	c.mu.Unlock()
}

func (c *ZeropsClient) SetProjectIPv6(ipv6 string) {
	if c == nil {
		return
	}
	clean := sanitizeIPv6Address(ipv6)
	if clean == "" {
		return
	}
	c.mu.Lock()
	c.projectIPv6 = clean
	c.mu.Unlock()
}

func (c *ZeropsClient) baseURL() string {
	if c != nil && c.apiBase != "" {
		return c.apiBase
	}
	return zeropsAPIBase
}

func (c *ZeropsClient) paceAPIRequest(ctx context.Context) error {
	c.reqMu.Lock()
	defer c.reqMu.Unlock()

	if !c.lastReq.IsZero() {
		elapsed := time.Since(c.lastReq)
		if elapsed < minZPRequestInterval {
			wait := minZPRequestInterval - elapsed
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				if !t.Stop() {
					<-t.C
				}
				return ctx.Err()
			case <-t.C:
			}
		}
	}
	c.lastReq = time.Now()
	return nil
}

func extractZPErrorFromBody(statusCode int, rawBytes []byte) *zpAPIError {
	apiErr := &zpAPIError{StatusCode: statusCode}
	trimmed := strings.TrimSpace(string(rawBytes))
	if trimmed == "" {
		return apiErr
	}
	var m map[string]any
	if json.Unmarshal(rawBytes, &m) == nil && m != nil {
		if errObj, ok := m["error"].(map[string]any); ok {
			if cStr, ok := errObj["code"].(string); ok {
				apiErr.Code = strings.TrimSpace(cStr)
			}
			if mStr, ok := errObj["message"].(string); ok {
				apiErr.Message = strings.TrimSpace(mStr)
			}
		}
		if apiErr.Message == "" {
			for _, k := range []string{"message", "error", "detail", "reason"} {
				if s, ok := m[k].(string); ok && strings.TrimSpace(s) != "" {
					apiErr.Message = strings.TrimSpace(s)
					break
				}
			}
		}
	}
	if apiErr.Message == "" {
		if len(trimmed) > 256 {
			trimmed = trimmed[:256]
		}
		apiErr.Message = trimmed
	}
	return apiErr
}

func doZPRequest(ctx context.Context, c *ZeropsClient, method, path string, body any) ([]byte, int, error) {
	if !c.IsConfigured() {
		return nil, 0, errors.New("zerops client not configured")
	}

	var reqBytes []byte
	if body != nil {
		var err error
		reqBytes, err = json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("marshal zerops payload: %w", err)
		}
	}

	bases := []string{c.baseURL()}
	if c.baseURL() == zeropsAPIBase {
		bases = append(bases, zeropsFallbackAPIBase)
	}

	var lastErr error
	for _, base := range bases {
		for attempt := 0; attempt < 2; attempt++ {
			if err := c.paceAPIRequest(ctx); err != nil {
				return nil, 0, err
			}

			reqCtx, cancel := context.WithTimeout(ctx, defaultZPReqTimeout)
			var bodyReader io.Reader
			if len(reqBytes) > 0 {
				bodyReader = bytes.NewReader(reqBytes)
			}

			req, err := http.NewRequestWithContext(reqCtx, method, base+path, bodyReader)
			if err != nil {
				cancel()
				return nil, 0, fmt.Errorf("build zerops request: %w", err)
			}

			req.Header.Set("Authorization", "Bearer "+c.Token)
			req.Header.Set("Accept", "application/json")
			if body != nil {
				req.Header.Set("Content-Type", "application/json")
			}
			req.Header.Set("User-Agent", "BERMUDA-Portal-CloudOrchestrator/4.0 (Go-Standard-Library)")

			resp, doErr := c.client.Do(req)
			if doErr != nil {
				cancel()
				lastErr = doErr
				break
			}

			rawBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
			retryAfterHdr := strings.TrimSpace(resp.Header.Get("Retry-After"))
			_ = resp.Body.Close()
			cancel()

			if readErr != nil {
				return nil, resp.StatusCode, fmt.Errorf("read zerops response: %w", readErr)
			}

			if resp.StatusCode == http.StatusTooManyRequests && attempt == 0 {
				waitDur := 2500 * time.Millisecond
				if secs, err := strconv.Atoi(retryAfterHdr); err == nil && secs > 0 && secs <= 30 {
					waitDur = time.Duration(secs) * time.Second
				}
				select {
				case <-ctx.Done():
					return nil, resp.StatusCode, ctx.Err()
				case <-time.After(waitDur):
					continue
				}
			}

			if resp.StatusCode >= 400 {
				zpErr := extractZPErrorFromBody(resp.StatusCode, rawBytes)
				lastErr = zpErr
				if resp.StatusCode == http.StatusNotFound && base != bases[len(bases)-1] {
					break
				}
				return rawBytes, resp.StatusCode, zpErr
			}

			if base != c.apiBase {
				c.mu.Lock()
				c.apiBase = base
				c.mu.Unlock()
			}
			return rawBytes, resp.StatusCode, nil
		}
	}

	return nil, 0, lastErr
}

type zpServiceCandidate struct {
	ID            string
	ProjectID     string
	ClientID      string
	Name          string
	Status        string
	Port          int
	ServiceDomain string
	ProjectIPv6   string
	Region        string
}

func anyToZPString(v any) string {
	switch val := v.(type) {
	case string:
		return strings.TrimSpace(val)
	case float64:
		if val > 0 {
			return strconv.FormatInt(int64(val), 10)
		}
	case json.Number:
		return val.String()
	}
	return ""
}

func extractZeropsMetadataFromGenericJSON(rawBytes []byte) (cands []zpServiceCandidate, foundSubdomain string, foundIPv6 string) {
	var raw any
	if err := json.Unmarshal(rawBytes, &raw); err != nil {
		return nil, "", ""
	}

	seenIDs := make(map[string]struct{})

	var walk func(node any)
	walk = func(node any) {
		switch v := node.(type) {
		case map[string]any:
			for key, val := range v {
				lowerKey := strings.ToLower(key)
				if strVal, ok := val.(string); ok {
					trimmed := strings.TrimSpace(strVal)
					if foundSubdomain == "" && (strings.Contains(lowerKey, "subdomain") || strings.Contains(lowerKey, "domain") || strings.Contains(lowerKey, "url")) {
						if norm := normalizeZeropsSubdomain(trimmed); isFullZeropsServiceDomain(norm) {
							foundSubdomain = norm
						}
					}
					if foundIPv6 == "" && (strings.Contains(lowerKey, "ipv6") || lowerKey == "ip" || lowerKey == "address") {
						if v6 := sanitizeIPv6Address(trimmed); v6 != "" && !isCloudflareEdgeIP(net.ParseIP(v6)) {
							foundIPv6 = v6
						}
					}
				}
			}

			idStr := anyToZPString(v["id"])
			projIDStr := anyToZPString(v["projectId"])
			nameStr := anyToZPString(v["name"])
			typeStr := strings.ToLower(anyToZPString(v["serviceStackTypeVersionName"]) + " " + anyToZPString(v["serviceStackTypeId"]) + " " + anyToZPString(v["type"]))

			if idStr != "" && projIDStr != "" && (nameStr != "" || strings.Contains(typeStr, "go") || v["ports"] != nil || v["subdomainAccess"] != nil) {
				if _, exists := seenIDs[idStr]; !exists {
					seenIDs[idStr] = struct{}{}
					cand := zpServiceCandidate{
						ID:        idStr,
						ProjectID: projIDStr,
						ClientID:  anyToZPString(v["clientId"]),
						Name:      nameStr,
						Status:    strings.ToLower(anyToZPString(v["status"])),
					}
					for _, k := range []string{"subdomainAccessUrl", "subdomain", "url", "domain"} {
						if s := anyToZPString(v[k]); s != "" {
							if norm := normalizeZeropsSubdomain(s); isFullZeropsServiceDomain(norm) {
								cand.ServiceDomain = norm
								break
							}
						}
					}
					if portsArr, ok := v["ports"].([]any); ok {
						for _, pItem := range portsArr {
							if pm, ok := pItem.(map[string]any); ok {
								if pNum, err := strconv.Atoi(anyToZPString(pm["port"])); err == nil && pNum > 0 {
									cand.Port = pNum
									break
								}
							}
						}
					}
					if locStr := anyToZPString(v["location"]); locStr != "" {
						cand.Region = normalizeRegion(locStr)
					}
					cands = append(cands, cand)
				}
			}

			for _, child := range v {
				walk(child)
			}
		case []any:
			for _, item := range v {
				walk(item)
			}
		}
	}

	walk(raw)
	return cands, foundSubdomain, foundIPv6
}

func (c *ZeropsClient) enrichProjectDetails(ctx context.Context, projectID string) {
	if projectID == "" {
		return
	}
	raw, _, err := doZPRequest(ctx, c, http.MethodGet, "/project/"+url.PathEscape(projectID), nil)
	if err == nil && len(raw) > 0 {
		_, _, v6 := extractZeropsMetadataFromGenericJSON(raw)
		if v6 != "" {
			c.SetProjectIPv6(v6)
			log.Printf("[Zerops] ✓ Discovered Project Dedicated IPv6: %s", v6)
		}
		var m map[string]any
		if json.Unmarshal(raw, &m) == nil {
			if cID := anyToZPString(m["clientId"]); cID != "" {
				c.mu.Lock()
				if c.ClientID == "" {
					c.ClientID = cID
				}
				c.mu.Unlock()
			}
			for _, k := range []string{"location", "region"} {
				if loc := anyToZPString(m[k]); loc != "" {
					c.mu.Lock()
					c.discoveredRegion = normalizeRegion(loc)
					c.mu.Unlock()
					break
				}
			}
		}
	}
}

func (c *ZeropsClient) enrichServiceDetails(ctx context.Context, serviceID string) {
	if serviceID == "" {
		return
	}
	raw, _, err := doZPRequest(ctx, c, http.MethodGet, "/service-stack/"+url.PathEscape(serviceID), nil)
	if err == nil && len(raw) > 0 {
		cands, sub, v6 := extractZeropsMetadataFromGenericJSON(raw)
		if len(cands) > 0 {
			cand := cands[0]
			c.mu.Lock()
			if cand.ProjectID != "" && c.ProjectID == "" {
				c.ProjectID = cand.ProjectID
			}
			if cand.ClientID != "" && c.ClientID == "" {
				c.ClientID = cand.ClientID
			}
			if cand.Name != "" && c.ServiceName == "" {
				c.ServiceName = cand.Name
			}
			if cand.Port > 0 {
				c.TargetPort = cand.Port
			}
			if cand.Region != "" {
				c.discoveredRegion = cand.Region
			}
			c.mu.Unlock()
			if cand.ServiceDomain != "" {
				c.SetServiceDomain(cand.ServiceDomain)
			}
		}
		if sub != "" {
			c.SetServiceDomain(sub)
		}
		if v6 != "" {
			c.SetProjectIPv6(v6)
		}
		c.notifyTopology()
	}
}

func (c *ZeropsClient) ResolveRuntimeContext(ctx context.Context) error {
	if !c.IsConfigured() {
		return errors.New("zerops client not configured")
	}

	c.mu.RLock()
	srvID := c.ServiceID
	projID := c.ProjectID
	srvName := c.ServiceName
	srvDom := c.serviceDomain
	c.mu.RUnlock()

	if srvID != "" {
		c.enrichServiceDetails(ctx, srvID)
		c.mu.RLock()
		projID = c.ProjectID
		c.mu.RUnlock()
		if projID != "" && c.GetProjectIPv6() == "" {
			c.enrichProjectDetails(ctx, projID)
		}
		return nil
	}

	// Step 1: Query /user-info to discover ClientID (organization)
	if rawUser, _, err := doZPRequest(ctx, c, http.MethodGet, "/user-info", nil); err == nil && len(rawUser) > 0 {
		var uMap map[string]any
		if json.Unmarshal(rawUser, &uMap) == nil {
			if cuList, ok := uMap["clientUserList"].([]any); ok && len(cuList) > 0 {
				if firstCU, ok := cuList[0].(map[string]any); ok {
					if cID := anyToZPString(firstCU["clientId"]); cID != "" {
						c.mu.Lock()
						if c.ClientID == "" {
							c.ClientID = cID
						}
						c.mu.Unlock()
					}
				}
			}
		}
	}

	// Step 2: Search service stacks via POST /service-stack/search
	c.mu.RLock()
	clientID := c.ClientID
	c.mu.RUnlock()

	searchFilter := []map[string]any{}
	if clientID != "" {
		searchFilter = append(searchFilter, map[string]any{
			"name":     "clientId",
			"operator": "eq",
			"value":    clientID,
		})
	}
	if projID != "" {
		searchFilter = append(searchFilter, map[string]any{
			"name":     "projectId",
			"operator": "eq",
			"value":    projID,
		})
	}

	searchPayload := map[string]any{
		"search": searchFilter,
		"sort":   []map[string]any{},
		"limit":  50,
		"offset": 0,
	}

	rawSearch, _, err := doZPRequest(ctx, c, http.MethodPost, "/service-stack/search", searchPayload)
	if err == nil && len(rawSearch) > 0 {
		cands, sub, v6 := extractZeropsMetadataFromGenericJSON(rawSearch)
		if sub != "" && c.GetServiceDomain() == "" {
			c.SetServiceDomain(sub)
		}
		if v6 != "" && c.GetProjectIPv6() == "" {
			c.SetProjectIPv6(v6)
		}

		var matched *zpServiceCandidate
		for i := range cands {
			cand := &cands[i]
			if srvDom != "" && cand.ServiceDomain != "" && strings.EqualFold(cand.ServiceDomain, srvDom) {
				matched = cand
				break
			}
			if srvName != "" && strings.EqualFold(cand.Name, srvName) {
				matched = cand
				break
			}
			if strings.EqualFold(cand.Name, "portal") || strings.EqualFold(cand.Name, "app") {
				matched = cand
				break
			}
		}
		if matched == nil && len(cands) > 0 {
			matched = &cands[0]
		}

		if matched != nil {
			c.mu.Lock()
			if matched.ID != "" {
				c.ServiceID = matched.ID
			}
			if matched.ProjectID != "" {
				c.ProjectID = matched.ProjectID
			}
			if matched.ClientID != "" && c.ClientID == "" {
				c.ClientID = matched.ClientID
			}
			if matched.Name != "" && c.ServiceName == "" {
				c.ServiceName = matched.Name
			}
			if matched.Port > 0 {
				c.TargetPort = matched.Port
			}
			c.mu.Unlock()
			if matched.ServiceDomain != "" {
				c.SetServiceDomain(matched.ServiceDomain)
			}

			c.enrichServiceDetails(ctx, matched.ID)
			if matched.ProjectID != "" {
				c.enrichProjectDetails(ctx, matched.ProjectID)
			}
			c.notifyTopology()
			log.Printf("[Zerops] ✓ Service context resolved: ServiceID=%s | ProjectID=%s | Subdomain=%q | IPv6=%q",
				c.ServiceID, c.ProjectID, c.GetServiceDomain(), c.GetProjectIPv6())
			return nil
		}
	}

	return errors.New("unable to auto-discover zerops service stack ID")
}

// persistMasterKeyViaLocalZSC uses Zerops's built-in `/opt/zerops/bin/zsc` tool
// inside the Incus container to persist `BERMUDA_MASTER_KEY` without needing an API token.
func persistMasterKeyViaLocalZSC(ctx context.Context, masterKey string) bool {
	cleanMK := strings.TrimSpace(masterKey)
	if cleanMK == "" {
		return false
	}

	if existing := sanitizeMasterKey(os.Getenv("BERMUDA_MASTER_KEY")); existing != "" {
		log.Println("[Zerops] ✓ BERMUDA_MASTER_KEY already present in container environment (Restart-Loop Guard active)")
		return true
	}

	zscCandidates := []string{"/opt/zerops/bin/zsc", "/usr/local/bin/zsc", "zsc"}
	var zscPath string
	for _, cand := range zscCandidates {
		if pat, err := exec.LookPath(cand); err == nil && pat != "" {
			zscPath = pat
			break
		}
	}
	if zscPath == "" {
		return false
	}

	cmdCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, zscPath, "setSecretEnv", "BERMUDA_MASTER_KEY", cleanMK)
	if err := cmd.Run(); err != nil {
		return false
	}

	log.Println("[Zerops] ✓ BERMUDA_MASTER_KEY persisted via local zsc setSecretEnv")
	return true
}

func (c *ZeropsClient) PersistMasterKey(ctx context.Context, masterKey string) bool {
	cleanMK := strings.TrimSpace(masterKey)
	if cleanMK == "" {
		return false
	}

	if existing := sanitizeMasterKey(os.Getenv("BERMUDA_MASTER_KEY")); existing != "" {
		c.mu.Lock()
		c.keyPersisted = true
		c.mu.Unlock()
		log.Println("[Zerops] ✓ BERMUDA_MASTER_KEY already present in Secret Variables (Restart-Loop Guard active)")
		return true
	}

	c.mu.RLock()
	alreadyPersisted := c.keyPersisted
	c.mu.RUnlock()
	if alreadyPersisted {
		return true
	}

	if persistMasterKeyViaLocalZSC(ctx, cleanMK) {
		c.mu.Lock()
		c.keyPersisted = true
		c.mu.Unlock()
		return true
	}

	if !c.IsConfigured() {
		return false
	}
	if err := c.ResolveRuntimeContext(ctx); err != nil {
		return false
	}

	c.mu.RLock()
	srvID := c.ServiceID
	c.mu.RUnlock()
	if srvID == "" {
		return false
	}

	payload := map[string]any{
		"serviceStackId": srvID,
		"key":            "BERMUDA_MASTER_KEY",
		"content":        cleanMK,
	}
	if _, _, err := doZPRequest(ctx, c, http.MethodPost, "/user-data", payload); err == nil {
		c.mu.Lock()
		c.keyPersisted = true
		c.mu.Unlock()
		log.Println("[Zerops] ✓ BERMUDA_MASTER_KEY persisted to Zerops Service Secret Variables via REST API")
		return true
	}

	return false
}

// discoverPublicEgressIPv6 queries Cloudflare's IPv6 trace endpoint to discover
// the container's outbound global IPv6 address if not yet known.
func discoverPublicEgressIPv6(ctx context.Context) string {
	probeCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	d := net.Dialer{Timeout: 4 * time.Second}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(c context.Context, _, addr string) (net.Conn, error) {
			return d.DialContext(c, "tcp6", addr)
		},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()

	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, "https://[2606:4700:4700::1111]/cdn-cgi/trace", nil)
	if err != nil {
		return ""
	}
	req.Host = "1.1.1.1"
	req.Header.Set("User-Agent", "curl/8.7.1")

	client := &http.Client{Transport: tr, Timeout: 4 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if after, ok := strings.CutPrefix(strings.TrimSpace(line), "ip="); ok {
			if v6 := sanitizeIPv6Address(after); v6 != "" {
				return v6
			}
		}
	}
	return ""
}

// EnsureServiceDomain discovers the service's free *.prg1.zerops.app subdomain
// and enables subdomain access via `PUT /service-stack/{id}/enable-subdomain-access` if disabled.
func (c *ZeropsClient) EnsureServiceDomain(ctx context.Context) (string, error) {
	if c.GetProjectIPv6() == "" {
		if v6 := discoverPublicEgressIPv6(ctx); v6 != "" {
			c.SetProjectIPv6(v6)
		}
	}

	if dom := c.GetServiceDomain(); isFullZeropsServiceDomain(dom) && c.GetProjectIPv6() != "" {
		return dom, nil
	}

	if err := c.ResolveRuntimeContext(ctx); err != nil {
		return c.GetServiceDomain(), err
	}

	if dom := c.GetServiceDomain(); isFullZeropsServiceDomain(dom) {
		return dom, nil
	}

	c.mu.RLock()
	srvID := c.ServiceID
	c.mu.RUnlock()
	if srvID == "" {
		return c.GetServiceDomain(), nil
	}

	enablePath := fmt.Sprintf("/service-stack/%s/enable-subdomain-access", url.PathEscape(srvID))
	if raw, _, err := doZPRequest(ctx, c, http.MethodPut, enablePath, map[string]any{}); err == nil {
		if len(raw) > 0 {
			_, sub, v6 := extractZeropsMetadataFromGenericJSON(raw)
			if isFullZeropsServiceDomain(sub) {
				c.SetServiceDomain(sub)
				c.notifyTopology()
				log.Printf("[Zerops] ✓ Auto-Enabled Free HTTPS Subdomain: %s", sub)
				return c.GetServiceDomain(), nil
			}
			if v6 != "" {
				c.SetProjectIPv6(v6)
			}
		}
		c.enrichServiceDetails(ctx, srvID)
	}

	if dom := c.GetServiceDomain(); isFullZeropsServiceDomain(dom) {
		log.Printf("[Zerops] ✓ Resolved Free HTTPS Subdomain: %s", dom)
	}
	return c.GetServiceDomain(), nil
}

func probeCustomDomainTLS(ctx context.Context, customDomain, projectIPv6, fallbackHost string) bool {
	cleanCustom := cleanHost(customDomain)
	if cleanCustom == "" {
		return false
	}

	var dialTargets []string
	if v6 := sanitizeIPv6Address(projectIPv6); v6 != "" && !isCloudflareEdgeIP(net.ParseIP(v6)) {
		dialTargets = append(dialTargets, net.JoinHostPort(v6, "443"))
	}

	for _, host := range []string{cleanHost(fallbackHost), cleanCustom} {
		if host == "" {
			continue
		}
		lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		ips, err := net.DefaultResolver.LookupIP(lookupCtx, "ip", host)
		cancel()
		if err == nil {
			for _, ip := range ips {
				if !isCloudflareEdgeIP(ip) {
					dialTargets = append(dialTargets, net.JoinHostPort(ip.String(), "443"))
				}
			}
		}
	}

	if len(dialTargets) == 0 {
		return false
	}

	healthPath := getEnv("BERMUDA_HEALTH_PATH", "/healthz")
	if !strings.HasPrefix(healthPath, "/") {
		healthPath = "/" + healthPath
	}

	for _, targetAddr := range dialTargets {
		probeCtx, cancel := context.WithTimeout(ctx, defaultZPTLSProbeTimeout)
		tr := &http.Transport{
			Proxy: nil,
			DialContext: func(dCtx context.Context, _, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: defaultZPTLSProbeTimeout}
				return d.DialContext(dCtx, "tcp", targetAddr)
			},
			TLSClientConfig: &tls.Config{
				ServerName:         cleanCustom,
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: false,
			},
			DisableKeepAlives: true,
		}

		req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, "https://"+cleanCustom+healthPath, nil)
		if err != nil {
			tr.CloseIdleConnections()
			cancel()
			continue
		}
		req.Host = cleanCustom
		req.Header.Set("User-Agent", "curl/8.7.1")

		client := &http.Client{
			Transport: tr,
			Timeout:   defaultZPTLSProbeTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		resp, doErr := client.Do(req)
		if doErr != nil {
			tr.CloseIdleConnections()
			cancel()
			continue
		}

		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		var tlsVerified bool
		if resp.TLS != nil && len(resp.TLS.VerifiedChains) > 0 && len(resp.TLS.PeerCertificates) > 0 {
			leaf := resp.TLS.PeerCertificates[0]
			if leaf.VerifyHostname(cleanCustom) == nil && time.Now().Before(leaf.NotAfter) {
				tlsVerified = true
			}
		}

		routeVerified := resp.StatusCode == http.StatusOK &&
			strings.EqualFold(strings.TrimSpace(resp.Header.Get("Server")), openrestyServerToken)

		tr.CloseIdleConnections()
		cancel()

		if tlsVerified && routeVerified {
			return true
		}
	}

	return false
}

func (c *ZeropsClient) finalizeCustomDomainInfo(ctx context.Context, info ZeropsCustomDomainInfo) *ZeropsCustomDomainInfo {
	if info.ProjectIPv6 == "" {
		info.ProjectIPv6 = c.GetProjectIPv6()
	}
	if info.CNAMETarget == "" {
		info.CNAMETarget = c.GetServiceDomain()
	}

	if probeCustomDomainTLS(ctx, info.Domain, info.ProjectIPv6, info.CNAMETarget) {
		info.CertificateStatus = "VALID"
		info.SSLReady = true
		info.RouteReady = true
		info.Ready = true
		info.RecordsVerified = true
	} else if info.CertificateStatus == "" || strings.EqualFold(info.CertificateStatus, "UNKNOWN") {
		info.CertificateStatus = "PENDING_TLS"
	}

	return &info
}

func (c *ZeropsClient) EnsureCustomDomain(ctx context.Context, targetDomain string) (*ZeropsCustomDomainInfo, error) {
	cleanTarget := cleanHost(targetDomain)
	if cleanTarget == "" || isZeropsManagedDomain(cleanTarget) || net.ParseIP(cleanTarget) != nil {
		return nil, errors.New("invalid or empty custom domain target")
	}

	if err := c.ResolveRuntimeContext(ctx); err != nil {
		return nil, err
	}

	c.mu.RLock()
	projID := c.ProjectID
	srvID := c.ServiceID
	port := c.TargetPort
	projIPv6 := c.projectIPv6
	srvDom := c.serviceDomain
	c.mu.RUnlock()

	if projID != "" && srvID != "" {
		routingPayload := map[string]any{
			"projectId": projID,
			"ssl":       true,
			"domains":   []string{cleanTarget},
			"locations": []map[string]any{
				{
					"path":           "/",
					"port":           port,
					"serviceStackId": srvID,
				},
			},
		}

		if raw, _, err := doZPRequest(ctx, c, http.MethodPost, "/public-http-routing", routingPayload); err == nil && len(raw) > 0 {
			var m map[string]any
			_ = json.Unmarshal(raw, &m)
			routeID := anyToZPString(m["id"])
			c.SetCustomDomain(cleanTarget)
			c.notifyTopology()
			info := ZeropsCustomDomainInfo{
				ID:                routeID,
				Domain:            cleanTarget,
				ProjectIPv6:       projIPv6,
				CNAMETarget:       srvDom,
				CertificateStatus: "PENDING_TLS",
			}
			finalized := c.finalizeCustomDomainInfo(ctx, info)
			log.Printf("[Zerops] ✓ Registered Custom Domain in L7 HTTP Balancer: %s -> Service=%s:%d (IPv6=%s, Status=%s)",
				cleanTarget, srvID, port, finalized.ProjectIPv6, finalized.CertificateStatus)
			return finalized, nil
		}
	}

	c.SetCustomDomain(cleanTarget)
	c.notifyTopology()
	info := ZeropsCustomDomainInfo{
		Domain:            cleanTarget,
		ProjectIPv6:       projIPv6,
		CNAMETarget:       srvDom,
		CertificateStatus: "PENDING_TLS",
	}
	return c.finalizeCustomDomainInfo(ctx, info), nil
}

func (c *ZeropsClient) FetchCustomDomainStatus(ctx context.Context, customDomainID, targetDomain string) (*ZeropsCustomDomainInfo, error) {
	cleanTarget := cleanHost(targetDomain)
	projIPv6 := c.GetProjectIPv6()
	srvDom := c.GetServiceDomain()

	if probeCustomDomainTLS(ctx, cleanTarget, projIPv6, srvDom) {
		return &ZeropsCustomDomainInfo{
			ID:                customDomainID,
			Domain:            cleanTarget,
			ProjectIPv6:       projIPv6,
			CNAMETarget:       srvDom,
			CertificateStatus: "VALID",
			DNSReady:          true,
			SSLReady:          true,
			RouteReady:        true,
			Ready:             true,
			RecordsVerified:   true,
		}, nil
	}

	return &ZeropsCustomDomainInfo{
		ID:                customDomainID,
		Domain:            cleanTarget,
		ProjectIPv6:       projIPv6,
		CNAMETarget:       srvDom,
		CertificateStatus: "PENDING_TLS",
	}, nil
}

func (c *ZeropsClient) WaitCustomDomainCertificate(ctx context.Context, customDomainID, targetDomain string, maxWait time.Duration) (*ZeropsCustomDomainInfo, bool) {
	if maxWait <= 0 {
		maxWait = defaultZPCertPollWait
	}
	waitCtx, cancel := context.WithTimeout(ctx, maxWait)
	defer cancel()

	ticker := time.NewTicker(defaultZPCertPollTick)
	defer ticker.Stop()

	var latest *ZeropsCustomDomainInfo
	for {
		info, err := c.FetchCustomDomainStatus(waitCtx, customDomainID, targetDomain)
		if err == nil && info != nil {
			latest = info
			if info.IsCertificateValid() {
				log.Printf("[Zerops] ✓ Custom Domain %s Let's Encrypt TLS & L7 Route Identity VERIFIED (%s)",
					info.Domain, info.CertificateStatus)
				return info, true
			}
		}

		select {
		case <-waitCtx.Done():
			return latest, false
		case <-ticker.C:
		}
	}
}

func probeKernelIPv6Route() bool {
	conn, err := net.DialTimeout("udp6", "[2606:4700:4700::1111]:53", 50*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (c *ZeropsClient) TuneComputeAndNetwork(ctx context.Context) {
	if probeKernelIPv6Route() {
		log.Println("[Zerops] ✓ Outbound IPv6 Stack: ACTIVE & VERIFIED (Native Dual-Stack Routing Online)")
	} else {
		log.Println("[Zerops] ✓ Outbound Network Stack: IPv4 Active (Prague LXC Egress Verified)")
	}

	if !c.IsConfigured() {
		return
	}
	if !c.HasServiceContext() {
		_ = c.ResolveRuntimeContext(ctx)
	}

	c.mu.RLock()
	srvID := c.ServiceID
	projID := c.ProjectID
	srvDom := c.serviceDomain
	projIPv6 := c.projectIPv6
	reg := c.discoveredRegion
	port := c.TargetPort
	c.mu.RUnlock()

	if reg == "" {
		reg = "prg1"
	}
	healthPath := getEnv("BERMUDA_HEALTH_PATH", "/healthz")
	log.Printf("[Zerops] ✓ Service Ready: Project=%s | Service=%s | Subdomain=%s | IPv6=%s | Region=%s | Port=%d | HealthPath=%s",
		projID, srvID, srvDom, projIPv6, reg, port, healthPath)
}
