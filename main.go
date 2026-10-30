package main

import (
	"context"
	"errors"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	defaultPort               = "8080"
	compatAltPort             = "3000"
	compactSelfMemMB          = 44
	compactWorkerMemMB        = 148
	standardSelfMemMB         = 88
	standardWorkerMemMB       = 340
	defaultGOMAXPROCS         = 2
	gatewayMemPercent         = 14
	workerMemPercent          = 54
	compactTierThresholdMB    = 384
	httpDrainTimeout          = 8 * time.Second
	edgeKeepAlivePeriod       = 15 * time.Second
	drainPropagationWindow    = 400 * time.Millisecond
	startupOrchestrationDelay = 3 * time.Second
	dnsPropagationSettleDelay = 4 * time.Second
	tcpUserTimeoutOpt         = 18
)

var compactMemoryMode atomic.Bool

func isCompactMemoryTier() bool {
	return compactMemoryMode.Load()
}

func cgroupMemoryLimit() (uint64, bool) {
	candidates := []string{
		"/sys/fs/cgroup/memory.max",
		"/sys/fs/cgroup/memory/memory.limit_in_bytes",
	}
	for _, p := range candidates {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		s := strings.TrimSpace(string(data))
		if s == "" || s == "max" {
			continue
		}
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil || n == 0 || n >= 1<<50 {
			continue
		}
		return n, true
	}

	for _, envKey := range []string{"BERMUDA_CONTAINER_MEM_MB", "MEMORY_LIMIT", "SERVER_MEMORY"} {
		if raw := strings.TrimSpace(getEnv(envKey, "")); raw != "" {
			if mb, err := strconv.ParseUint(raw, 10, 64); err == nil && mb >= 128 && mb <= 65536 {
				return mb << 20, true
			}
		}
	}

	return 0, false
}

func deriveMemoryBudget() (gwMB, workerMB int, compact bool) {
	// Default calibrated for Zerops 0.5 GB - 1.0 GB RAM vertical autoscaling tier
	gwMB, workerMB, compact = standardSelfMemMB, standardWorkerMemMB, false

	limit, limited := cgroupMemoryLimit()
	if limited {
		totalMB := int(limit >> 20)
		if totalMB > compactTierThresholdMB {
			compact = false
			gwMB = totalMB * gatewayMemPercent / 100
			workerMB = totalMB * workerMemPercent / 100

			allowedMB := totalMB * 68 / 100
			if gwMB < 48 {
				gwMB = 48
			}
			if workerMB < 128 {
				workerMB = 128
			}
			if total := gwMB + workerMB; total > allowedMB && allowedMB >= 176 {
				gwMB = allowedMB * gatewayMemPercent / 68
				workerMB = allowedMB * workerMemPercent / 68
			}
		} else {
			compact = true
			gwMB = totalMB * 15 / 100
			workerMB = totalMB * 52 / 100
			if gwMB < 36 {
				gwMB = 36
			}
			if gwMB > 48 {
				gwMB = 48
			}
			if workerMB < 96 {
				workerMB = 96
			}
			if workerMB > 148 {
				workerMB = 148
			}
		}
	}

	if explicitLow := strings.ToLower(strings.TrimSpace(getEnv("BERMUDA_LOW_MEM", ""))); explicitLow == "true" || explicitLow == "1" {
		compact = true
		if gwMB > compactSelfMemMB {
			gwMB = compactSelfMemMB
		}
		if workerMB > compactWorkerMemMB {
			workerMB = compactWorkerMemMB
		}
	} else if explicitLow == "false" || explicitLow == "0" {
		compact = false
		if !limited {
			gwMB, workerMB = standardSelfMemMB, standardWorkerMemMB
		}
	}

	gwMB = getEnvInt("BERMUDA_SELF_MEM_MB", gwMB)
	workerMB = getEnvInt("BERMUDA_WORKER_MEM_MB", getEnvInt("BERMUDA_XRAY_MEM_MB", workerMB))
	compactMemoryMode.Store(compact)
	return gwMB, workerMB, compact
}

func applyMemoryCeiling(selfMB int, compact bool) {
	if selfMB < 36 {
		selfMB = 36
	}
	debug.SetMemoryLimit(int64(selfMB) << 20)
	if compact {
		debug.SetGCPercent(50)
	} else {
		debug.SetGCPercent(100)
	}
}

func cgroupCPUQuota() (float64, bool) {
	if data, err := os.ReadFile("/sys/fs/cgroup/cpu.max"); err == nil {
		f := strings.Fields(string(data))
		if len(f) == 2 && f[0] != "max" {
			q, e1 := strconv.ParseFloat(f[0], 64)
			p, e2 := strconv.ParseFloat(f[1], 64)
			if e1 == nil && e2 == nil && q > 0 && p > 0 {
				return q / p, true
			}
		}
	}
	qb, e1 := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
	pb, e2 := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
	if e1 == nil && e2 == nil {
		q, e3 := strconv.ParseFloat(strings.TrimSpace(string(qb)), 64)
		p, e4 := strconv.ParseFloat(strings.TrimSpace(string(pb)), 64)
		if e3 == nil && e4 == nil && q > 0 && p > 0 {
			return q / p, true
		}
	}
	return 0, false
}

func applyGOMAXPROCS() int {
	n := getEnvInt("BERMUDA_GOMAXPROCS", 0)
	if n == 0 {
		if q, ok := cgroupCPUQuota(); ok {
			n = int(math.Ceil(q))
		}
	}
	if n < 2 {
		n = defaultGOMAXPROCS
	}
	if cpus := runtime.NumCPU(); n > cpus && cpus > 0 {
		n = cpus
	}
	runtime.GOMAXPROCS(n)
	return n
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func cleanHost(h string) string {
	h = strings.TrimSpace(h)
	if strings.HasPrefix(h, "${{") || strings.HasPrefix(h, "$") || strings.HasPrefix(h, "<@") {
		return ""
	}
	h = strings.TrimPrefix(h, "https://")
	h = strings.TrimPrefix(h, "http://")
	if slashIdx := strings.IndexByte(h, '/'); slashIdx != -1 {
		h = h[:slashIdx]
	}
	h = strings.TrimRight(h, "/.")
	if strings.HasPrefix(h, "[") {
		if endIdx := strings.IndexByte(h, ']'); endIdx != -1 {
			h = h[1:endIdx]
		}
	} else if strings.Count(h, ":") == 1 {
		if idx := strings.IndexByte(h, ':'); idx != -1 {
			h = h[:idx]
		}
	}
	return strings.ToLower(strings.TrimSpace(h))
}

func sanitizeIPv6Address(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" || strings.HasPrefix(s, "${{") || strings.HasPrefix(s, "$") || strings.HasPrefix(s, "<@") {
		return ""
	}
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if slashIdx := strings.IndexByte(s, '/'); slashIdx != -1 {
		s = s[:slashIdx]
	}
	if strings.HasPrefix(s, "[") {
		if endIdx := strings.IndexByte(s, ']'); endIdx != -1 {
			s = s[1:endIdx]
		}
	}
	s = strings.Trim(s, "\"'` \t\r\n")
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return ""
	}
	return strings.ToLower(ip.String())
}

// isZeropsCnameAlias distinguishes Zerops shared balancer/API hosts
// (e.g. "prg1.zerops.app", "zerops.app", "api.app-prg1.zerops.io")
// from an application's own public subdomain (e.g. "portal-1ef2-8080.prg1.zerops.app").
func isZeropsCnameAlias(h string) bool {
	h = cleanHost(h)
	if h == "" {
		return false
	}
	if h == "zerops.app" || h == "zerops.io" || h == "app.zerops.io" ||
		strings.HasSuffix(h, ".zerops.io") {
		return true
	}
	if strings.HasSuffix(h, ".zerops.app") {
		sub := strings.TrimSuffix(h, ".zerops.app")
		// Bare region domain like "prg1.zerops.app" or "us-east1.zerops.app" has no service prefix dot
		if sub == "" || !strings.Contains(sub, ".") {
			if !strings.Contains(sub, "-") {
				return true
			}
			// Region codes like "us-east1" or "eu-central1" without a service slug
			if strings.HasPrefix(sub, "us-") || strings.HasPrefix(sub, "eu-") || strings.HasPrefix(sub, "ap-") {
				return true
			}
		}
	}
	return false
}

func isZeropsManagedDomain(h string) bool {
	h = cleanHost(h)
	if h == "" {
		return false
	}
	if !strings.Contains(h, ".") && net.ParseIP(h) == nil {
		return true
	}
	return isZeropsCnameAlias(h) ||
		strings.Contains(h, "zerops.app") ||
		strings.Contains(h, "zerops.io") ||
		strings.HasSuffix(h, ".zerops.internal") ||
		strings.HasSuffix(h, ".cluster.local") ||
		strings.HasSuffix(h, ".svc") ||
		strings.HasSuffix(h, ".internal") ||
		strings.HasSuffix(h, ".local")
}

func isZeropsPublicDomain(h string) bool {
	h = cleanHost(h)
	if h == "" || isZeropsCnameAlias(h) {
		return false
	}
	return strings.HasSuffix(h, ".zerops.app") &&
		!strings.HasSuffix(h, ".internal") &&
		!strings.HasSuffix(h, ".local") &&
		!strings.HasSuffix(h, ".cluster.local") &&
		!strings.HasSuffix(h, ".svc")
}

func isFullZeropsServiceDomain(h string) bool {
	h = cleanHost(h)
	if !isZeropsPublicDomain(h) {
		return false
	}
	sub := strings.TrimSuffix(h, ".zerops.app")
	// Standard format: "<hostname>-<hexId>-<port>.<region>" (e.g. "portal-1ef2-8080.prg1")
	if dotIdx := strings.IndexByte(sub, '.'); dotIdx > 0 {
		prefix := sub[:dotIdx]
		return prefix != "" && strings.Contains(prefix, "-")
	}
	return sub != "" && strings.Contains(sub, "-")
}

func normalizeZeropsSubdomain(raw string) string {
	clean := cleanHost(raw)
	if clean == "" || isZeropsCnameAlias(clean) || net.ParseIP(clean) != nil {
		return ""
	}
	if isZeropsPublicDomain(clean) {
		return clean
	}
	for _, regSuffix := range []string{".prg1", ".us-east1", ".sea1", ".fra1"} {
		if strings.HasSuffix(clean, regSuffix) {
			candidate := clean + ".zerops.app"
			if isZeropsPublicDomain(candidate) {
				return candidate
			}
		}
	}
	if !strings.Contains(clean, ".") && strings.Count(clean, "-") >= 1 {
		candidate := clean + ".prg1.zerops.app"
		if isZeropsPublicDomain(candidate) {
			return candidate
		}
	}
	return ""
}

func normalizeRegion(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case s == "prg1" || strings.Contains(s, "prg") || strings.Contains(s, "prague") || strings.Contains(s, "czech") || strings.Contains(s, "cz"):
		return "prg1"
	case strings.Contains(s, "eu-central") || strings.Contains(s, "de-fra") || strings.Contains(s, "frankfurt") || strings.Contains(s, "germany") || strings.Contains(s, "de"):
		return "de-fra1"
	case strings.Contains(s, "fi-hel") || strings.Contains(s, "helsinki") || strings.Contains(s, "finland") || strings.Contains(s, "hel"):
		return "fi-hel1"
	case strings.Contains(s, "nl-ams") || strings.Contains(s, "europe-west4") || strings.Contains(s, "amsterdam") || strings.Contains(s, "nl"):
		return "europe-west4"
	case strings.Contains(s, "ch-") || strings.Contains(s, "zurich") || strings.Contains(s, "switzerland"):
		return "ch-central"
	case strings.Contains(s, "uk-lon") || strings.Contains(s, "london") || strings.Contains(s, "uk"):
		return "uk-lon1"
	case strings.Contains(s, "us-east") || strings.Contains(s, "virginia") || strings.Contains(s, "nyc") || strings.Contains(s, "iad"):
		return "us-east4"
	case strings.Contains(s, "us-west") || strings.Contains(s, "sea") || strings.Contains(s, "seattle") || strings.Contains(s, "oregon") || strings.Contains(s, "california"):
		return "us-west"
	case strings.Contains(s, "sg-sin") || strings.Contains(s, "singapore") || strings.Contains(s, "asia") || strings.Contains(s, "sin"):
		return "asia-southeast1"
	default:
		return "prg1"
	}
}

func resolveContainerPort() (string, int) {
	for _, key := range []string{"PORT", "BERMUDA_LISTEN_PORT", "ZEROPS_PORT", "SERVER_PORT", "APP_PORT"} {
		if raw := strings.TrimSpace(getEnv(key, "")); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 65535 {
				return strconv.Itoa(n), n
			}
		}
	}
	return defaultPort, 8080
}

func resolveInfrastructureDomains() (zpDomain, customDomain, projectIPv6 string) {
	subEnv := cleanHost(getEnv("ZEROPS_SUBDOMAIN", getEnv("ZEROPS_PUBLIC_DOMAIN", getEnv("ZEROPS_DOMAIN", ""))))
	explicitZP := cleanHost(getEnv("BERMUDA_ZEROPS_DOMAIN", getEnv("PUBLIC_URL", "")))
	customEnv := cleanHost(getEnv("CUSTOM_DOMAIN", getEnv("BERMUDA_CUSTOM_DOMAIN", "")))
	ipv6Env := sanitizeIPv6Address(getEnv("ZEROPS_PROJECT_IPV6", getEnv("PROJECT_IPV6", getEnv("BERMUDA_PROJECT_IPV6", ""))))

	for _, candidate := range []string{subEnv, explicitZP} {
		if norm := normalizeZeropsSubdomain(candidate); norm != "" {
			zpDomain = norm
			break
		}
	}

	for _, candidate := range []string{customEnv, explicitZP, subEnv} {
		if candidate != "" && !isZeropsManagedDomain(candidate) && normalizeZeropsSubdomain(candidate) == "" && net.ParseIP(candidate) == nil {
			customDomain = candidate
			break
		}
	}

	projectIPv6 = ipv6Env
	return zpDomain, customDomain, projectIPv6
}

func bindDualListeners(listenCfg *net.ListenConfig, primaryPort string) ([]net.Listener, []string, error) {
	strictMode := strings.EqualFold(getEnv("BERMUDA_STRICT_PORT", "false"), "true")

	seenPorts := make(map[string]struct{}, 3)
	var portsToTry []string
	addPort := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if _, exists := seenPorts[p]; !exists {
			seenPorts[p] = struct{}{}
			portsToTry = append(portsToTry, p)
		}
	}

	addPort(primaryPort)
	if !strictMode {
		addPort(defaultPort)
		addPort(compatAltPort)
	}

	var listeners []net.Listener
	var boundAddrs []string
	var firstErr error

	for i, p := range portsToTry {
		addr := "0.0.0.0:" + p
		ln, err := listenCfg.Listen(context.Background(), "tcp", addr)
		if err != nil {
			if i == 0 {
				firstErr = err
				if strictMode {
					return nil, nil, err
				}
				log.Printf("[Gateway] Notice: Primary port :%s unavailable (%v); binding compatibility ports...", p, err)
			}
			continue
		}
		listeners = append(listeners, ln)
		boundAddrs = append(boundAddrs, ":"+p)
	}

	if len(listeners) == 0 {
		return nil, nil, firstErr
	}
	return listeners, boundAddrs, nil
}

func orchestrateCloudInfrastructure(
	ctx context.Context,
	sup *Supervisor,
	gw *Gateway,
	zp *ZeropsClient,
	cf *CloudflareClient,
	initialZP string,
	initialCF string,
	initialIPv6 string,
	region string,
) {
	for i := 0; i < 120 && !sup.IsReady(); i++ {
		if !sleepContext(ctx, 250*time.Millisecond) {
			return
		}
	}

	if !sleepContext(ctx, startupOrchestrationDelay) {
		return
	}

	zpDomain := normalizeZeropsSubdomain(initialZP)
	customDomain := cleanHost(initialCF)
	projectIPv6 := sanitizeIPv6Address(initialIPv6)

	if curZP, curCF, _ := sup.GetInfrastructureDomains(); zpDomain == "" || customDomain == "" {
		if zpDomain == "" && isZeropsPublicDomain(curZP) {
			zpDomain = curZP
		}
		if customDomain == "" && curCF != "" && !isZeropsManagedDomain(curCF) {
			customDomain = curCF
		}
	}
	if curIPv6 := sup.GetProjectIPv6(); projectIPv6 == "" && curIPv6 != "" {
		projectIPv6 = sanitizeIPv6Address(curIPv6)
	}

	topologyUpdated := false
	loggedAfterDiscovery := false

	syncDomains := func(newZP, newCF, newIPv6 string) {
		cleanZP := normalizeZeropsSubdomain(newZP)
		cleanCF := cleanHost(newCF)
		cleanV6 := sanitizeIPv6Address(newIPv6)

		if isZeropsPublicDomain(cleanZP) {
			if zpDomain == "" || (!isFullZeropsServiceDomain(zpDomain) && isFullZeropsServiceDomain(cleanZP)) {
				if zpDomain != cleanZP {
					zpDomain = cleanZP
					topologyUpdated = true
				}
			}
		}
		if cleanCF != "" && !isZeropsManagedDomain(cleanCF) && net.ParseIP(cleanCF) == nil {
			if customDomain == "" || strings.HasSuffix(cleanCF, "."+customDomain) {
				if customDomain != cleanCF {
					customDomain = cleanCF
					topologyUpdated = true
				}
			}
		}
		if cleanV6 != "" && cleanV6 != projectIPv6 {
			projectIPv6 = cleanV6
			topologyUpdated = true
		}

		sup.SetInfrastructureDomains(zpDomain, customDomain, region)
		sup.SetProjectIPv6(projectIPv6)
		gw.SetInfrastructureDomains(zpDomain, customDomain, region)
		gw.SetProjectIPv6(projectIPv6)

		if cf != nil {
			if zpDomain != "" {
				cf.SetZeropsOrigin(zpDomain)
			}
			if projectIPv6 != "" {
				cf.SetZeropsProjectIPv6(projectIPv6)
			}
			if customDomain != "" {
				cf.SetPreferredDomain(customDomain)
			}
		}
		if zp != nil {
			if zpDomain != "" {
				zp.SetServiceDomain(zpDomain)
			}
			if customDomain != "" {
				zp.SetCustomDomain(customDomain)
			}
			if projectIPv6 != "" {
				zp.SetProjectIPv6(projectIPv6)
			}
		}
	}

	if zp != nil && zp.IsConfigured() {
		if srvDom, err := zp.EnsureServiceDomain(ctx); err == nil && srvDom != "" {
			syncDomains(srvDom, "", zp.GetProjectIPv6())
		} else if err != nil {
			log.Printf("[Zerops] Notice: Service topology lookup: %v", err)
		}

		if discV6 := zp.GetProjectIPv6(); discV6 != "" {
			syncDomains(zp.GetServiceDomain(), zp.GetCustomDomain(), discV6)
		}

		if reg := zp.GetDiscoveredRegion(); reg != "" {
			region = normalizeRegion(reg)
			sup.SetInfrastructureDomains(zpDomain, customDomain, region)
			gw.SetInfrastructureDomains(zpDomain, customDomain, region)
		}

		if sup.IsMasterKeyAutoGenerated() && !strings.EqualFold(getEnv("BERMUDA_PERSIST_KEY", "true"), "false") {
			zp.PersistMasterKey(ctx, sup.MasterKey())
			if !sleepContext(ctx, 1500*time.Millisecond) {
				return
			}
		}
	} else if sup.IsMasterKeyAutoGenerated() && !strings.EqualFold(getEnv("BERMUDA_PERSIST_KEY", "true"), "false") {
		// Even without ZEROPS_API_TOKEN, attempt local container persistence via `/opt/zerops/bin/zsc`
		persistMasterKeyViaLocalZSC(ctx, sup.MasterKey())
	}

	if cf != nil && cf.Token != "" {
		probeCtx, probeCancel := context.WithTimeout(ctx, 12*time.Second)
		if cfDom, err := cf.FetchZoneDomain(probeCtx); err == nil && cfDom != "" {
			syncDomains(cf.GetZeropsOrigin(), cfDom, cf.GetZeropsProjectIPv6())
		} else if err != nil {
			log.Printf("[Cloudflare] Notice: Zone domain discovery: %v", err)
		}
		probeCancel()
	}

	if topologyUpdated && ctx.Err() == nil {
		log.Printf("[Runtime] Synchronized Topology: ZeropsDomain=%q | CloudflareDomain=%q | ProjectIPv6=%q | Region=%q",
			zpDomain, customDomain, projectIPv6, region)
		sup.LogProvisioningLink("")
		loggedAfterDiscovery = true
	}

	var customDomInfo *ZeropsCustomDomainInfo
	var dnsRecordID string
	var cfDNSProvisioned bool

	if customDomain != "" {
		if zp != nil && zp.IsConfigured() {
			info, err := zp.EnsureCustomDomain(ctx, customDomain)
			if err != nil {
				log.Printf("[Zerops] Notice: Custom domain L7 routing registration (%s): %v", customDomain, err)
			} else if info != nil {
				customDomInfo = info
				syncDomains(zp.GetServiceDomain(), info.Domain, info.ProjectIPv6)
			}
		}

		if customDomInfo == nil && (projectIPv6 != "" || zpDomain != "") {
			certState := "PENDING_TLS"
			isValid := probeCustomDomainTLS(ctx, customDomain, projectIPv6, zpDomain)
			if isValid {
				certState = "VALID"
			}
			customDomInfo = &ZeropsCustomDomainInfo{
				Domain:            customDomain,
				ProjectIPv6:       projectIPv6,
				CNAMETarget:       zpDomain,
				CertificateStatus: certState,
				SSLReady:          isValid,
				RouteReady:        isValid,
				Ready:             isValid,
			}
		}

		if customDomInfo != nil && cf != nil && cf.Token != "" {
			recID, dnsErr := cf.ProvisionZeropsDNS(ctx, customDomInfo)
			if dnsErr != nil {
				log.Printf("[Cloudflare] Warning: Automated Zerops DNS provisioning: %v", dnsErr)
			} else {
				dnsRecordID = recID
				cfDNSProvisioned = true
				_ = sleepContext(ctx, dnsPropagationSettleDelay)
			}
		}
	}

	if cf != nil && cf.Token != "" && ctx.Err() == nil {
		cf.Tune(ctx)
		syncDomains(cf.GetZeropsOrigin(), cf.CachedZoneDomain(), cf.GetZeropsProjectIPv6())
	}

	autoOrange := !strings.EqualFold(getEnv("BERMUDA_CF_AUTO_ORANGE", "true"), "false")
	if cf != nil && customDomInfo != nil && !customDomInfo.IsCertificateValid() && autoOrange && ctx.Err() == nil {
		if cfDNSProvisioned || customDomInfo.RecordsVerified {
			log.Printf("[Zerops] Waiting for L7 Balancer Let's Encrypt TLS verification on %s before enabling Cloudflare Orange Cloud...", customDomInfo.Domain)
			if zp != nil && zp.IsConfigured() {
				updatedInfo, valid := zp.WaitCustomDomainCertificate(ctx, customDomInfo.ID, customDomInfo.Domain, defaultZPCertPollWait)
				if valid && updatedInfo != nil {
					cf.PromoteCustomDomainToOrangeCloud(ctx, updatedInfo.Domain, updatedInfo.ProjectIPv6, updatedInfo.CNAMETarget, dnsRecordID)
				} else if ctx.Err() == nil {
					go watchAndPromoteCustomDomain(ctx, zp, cf, customDomInfo, dnsRecordID)
				}
			} else {
				go watchAndPromoteCustomDomain(ctx, nil, cf, customDomInfo, dnsRecordID)
			}
		} else if cf.GetZoneID() != "" {
			go watchAndPromoteCustomDomain(ctx, zp, cf, customDomInfo, dnsRecordID)
		}
	}

	if zp != nil && zp.IsConfigured() && ctx.Err() == nil {
		zp.TuneComputeAndNetwork(ctx)
	}

	if ctx.Err() == nil && !loggedAfterDiscovery && (topologyUpdated || zp != nil || cf != nil) {
		log.Printf("[Runtime] Synchronized Topology: ZeropsDomain=%q | CloudflareDomain=%q | ProjectIPv6=%q | Region=%q",
			zpDomain, customDomain, projectIPv6, region)
		sup.LogProvisioningLink("")
	}
}

func watchAndPromoteCustomDomain(
	parent context.Context,
	zp *ZeropsClient,
	cf *CloudflareClient,
	info *ZeropsCustomDomainInfo,
	dnsRecordID string,
) {
	ctx, cancel := context.WithTimeout(parent, 15*time.Minute)
	defer cancel()

	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if zp != nil && zp.IsConfigured() {
				latest, err := zp.FetchCustomDomainStatus(ctx, info.ID, info.Domain)
				if err == nil && latest != nil && latest.IsCertificateValid() {
					log.Printf("[Zerops] ✓ Deferred L7 Balancer TLS verified for %s (%s)",
						latest.Domain, latest.CertificateStatus)
					cf.PromoteCustomDomainToOrangeCloud(ctx, latest.Domain, latest.ProjectIPv6, latest.CNAMETarget, dnsRecordID)
					return
				}
			} else if probeCustomDomainTLS(ctx, info.Domain, info.ProjectIPv6, info.CNAMETarget) {
				log.Printf("[Zerops] ✓ Direct Origin TLS + Route Identity verified for %s", info.Domain)
				cf.PromoteCustomDomainToOrangeCloud(ctx, info.Domain, info.ProjectIPv6, info.CNAMETarget, dnsRecordID)
				return
			}
		}
	}
}

func teardown(
	srv *http.Server,
	gw *Gateway,
	sup *Supervisor,
	supCancel context.CancelFunc,
	cloudCancel context.CancelFunc,
	graceful bool,
) {
	hardDeadline := time.Now().Add(18 * time.Second)

	if cloudCancel != nil {
		cloudCancel()
	}

	gw.SetDraining()
	if graceful {
		log.Println("[Gateway] Stage 1/5: Health status set to 503 (traffic shedding)...")
		time.Sleep(drainPropagationWindow)
	}

	if graceful {
		log.Println("[Gateway] Stage 2/5: Draining HTTP listeners and active XHTTP streams...")
		httpDeadline := minTime(hardDeadline.Add(-6*time.Second), time.Now().Add(10*time.Second))
		httpCtx, cancelHTTP := context.WithDeadline(context.Background(), httpDeadline)
		if err := srv.Shutdown(httpCtx); err != nil {
			log.Printf("[Gateway] HTTP drain timeout (%v); closing listeners", err)
			_ = srv.Close()
		} else {
			log.Println("[Gateway] HTTP listeners drained cleanly")
		}
		cancelHTTP()

		log.Println("[Gateway] Stage 3/5: Waiting for active upgraded WebSocket tunnels...")
		tunnelDeadline := minTime(hardDeadline.Add(-5*time.Second), time.Now().Add(httpDrainTimeout))
		if tunnelDeadline.After(time.Now()) {
			tunnelCtx, cancelTunnel := context.WithDeadline(context.Background(), tunnelDeadline)
			gw.WaitTunnels(tunnelCtx)
			cancelTunnel()
		}
	} else {
		_ = srv.Close()
	}

	log.Println("[Gateway] Stage 4/5: Closing remaining sockets and idle pools...")
	gw.CloseTunnels()
	gw.CloseIdleBackendConns()

	log.Println("[Gateway] Stage 5/5: Stopping worker process group...")
	supCancel()
	remainingSupTime := time.Until(hardDeadline)
	if remainingSupTime <= 0 {
		remainingSupTime = 2 * time.Second
	}
	sup.Stop(remainingSupTime)
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.LUTC)
	log.Println("[Gateway] Initializing BERMUDA PORTAL Edge Router (Zerops Cloud + Cloudflare Dedicated IPv6 Edition)...")

	gwMB, workerMB, compact := deriveMemoryBudget()
	procs := applyGOMAXPROCS()

	_ = syscall.Setenv("BERMUDA_WORKER_MEM_MB", strconv.Itoa(workerMB))
	_ = syscall.Setenv("BERMUDA_XRAY_MEM_MB", strconv.Itoa(workerMB))
	_ = syscall.Setenv("BERMUDA_WORKER_GOMAXPROCS", strconv.Itoa(procs))
	_ = syscall.Setenv("BERMUDA_XRAY_GOMAXPROCS", strconv.Itoa(procs))

	tierLabel := "STANDARD-INCUS"
	if compact {
		tierLabel = "COMPACT-LOW-MEM"
	}
	log.Printf("[Runtime] Resource budget calibrated [%s]: Gateway=%dMiB, Worker=%dMiB | GOMAXPROCS=%d",
		tierLabel, gwMB, workerMB, procs)

	sigCtx, stopSig := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stopSig()

	portStr, _ := resolveContainerPort()
	zpDomain, customDomain, projectIPv6 := resolveInfrastructureDomains()

	rawRegion := getEnv("BERMUDA_REGION", getEnv("ZEROPS_REGION", getEnv("REGION", "")))
	if rawRegion == "" && strings.Contains(zpDomain, ".us-east") {
		rawRegion = "us-east4"
	}
	region := normalizeRegion(rawRegion)

	// NewSupervisor initializes credentials, in-memory config, and subreaper in <1ms without
	// blocking on network I/O, allowing :8080 to bind immediately for Zerops readinessCheck.
	sup := NewSupervisor()
	sup.SetProjectIPv6(projectIPv6)

	cfToken := sanitizeCloudflareToken(getEnv("CLOUDFLARE_API_TOKEN", getEnv("BERMUDA_CF_API_TOKEN", "")))
	cfZoneID := sanitizeExplicitCredential(getEnv("CLOUDFLARE_ZONE_ID", getEnv("BERMUDA_CF_ZONE_ID", "")))
	var cf *CloudflareClient
	if cfToken != "" {
		cf = NewCloudflareClient(cfToken, cfZoneID)
		if zpDomain != "" {
			cf.SetZeropsOrigin(zpDomain)
		}
		if projectIPv6 != "" {
			cf.SetZeropsProjectIPv6(projectIPv6)
		}
		if customDomain != "" {
			cf.SetPreferredDomain(customDomain)
		}
	} else {
		log.Println("[Cloudflare] Notice: CLOUDFLARE_API_TOKEN unset. Edge auto-tuning bypassed.")
	}

	zpToken := sanitizeZeropsToken(getEnv("ZEROPS_API_TOKEN", getEnv("ZEROPS_TOKEN", getEnv("BERMUDA_ZEROPS_TOKEN", ""))))
	var zp *ZeropsClient
	if zpToken != "" {
		zp = NewZeropsClient(zpToken)
		if zpDomain != "" {
			zp.SetServiceDomain(zpDomain)
		}
		if customDomain != "" {
			zp.SetCustomDomain(customDomain)
		}
		if projectIPv6 != "" {
			zp.SetProjectIPv6(projectIPv6)
		}
	} else {
		log.Println("[Zerops] Notice: ZEROPS_API_TOKEN unset. Zerops REST API self-provisioning bypassed (local zsc active).")
	}

	sup.SetInfrastructureDomains(zpDomain, customDomain, region)
	primaryLogDomain := customDomain
	if primaryLogDomain == "" {
		primaryLogDomain = zpDomain
	}
	if primaryLogDomain != "" {
		sup.SetPublicDomain(primaryLogDomain)
	}

	log.Printf("[Runtime] Initial Topology: ZeropsDomain=%q | CloudflareDomain=%q | ProjectIPv6=%q | Region=%q",
		zpDomain, customDomain, projectIPv6, region)

	gw := NewGateway(sup, cf, zpDomain, customDomain, region)
	gw.SetZeropsClient(zp)
	gw.SetProjectIPv6(projectIPv6)

	topologyUpdater := func(zpDom, cfDom string) {
		sup.SetInfrastructureDomains(zpDom, cfDom, region)
		gw.SetInfrastructureDomains(zpDom, cfDom, region)
	}
	if cf != nil {
		cf.SetTopologyCallback(topologyUpdater)
	}
	if zp != nil {
		zp.SetTopologyCallback(topologyUpdater)
	}

	maxHdrBytes := 32 << 10
	if compact {
		maxHdrBytes = 16 << 10
	}

	srv := &http.Server{
		Addr:              "0.0.0.0:" + portStr,
		Handler:           gw.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       0,
		WriteTimeout:      0,
		IdleTimeout:       16 * time.Minute,
		MaxHeaderBytes:    maxHdrBytes,
		ConnState:         gw.TrackConnState,
	}

	listenCfg := net.ListenConfig{
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   true,
			Idle:     edgeKeepAlivePeriod,
			Interval: edgeKeepAlivePeriod,
			Count:    4,
		},
		Control: func(network, address string, c syscall.RawConn) error {
			_ = c.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpUserTimeoutOpt, 90000)
			})
			return nil
		},
	}

	// Bind HTTP listeners FIRST before starting worker bootstrap so Zerops readinessCheck passes immediately
	listeners, boundAddrs, err := bindDualListeners(&listenCfg, portStr)
	if err != nil {
		log.Fatalf("[Gateway] Fatal: Cannot bind HTTP listener on :%s: %v", portStr, err)
	}

	serverErrCh := make(chan error, len(listeners))
	log.Printf("[Gateway] Edge listeners active on %s (PID %d, GOMAXPROCS=%d)",
		strings.Join(boundAddrs, " & "), os.Getpid(), procs)

	for _, ln := range listeners {
		activeLn := ln
		go func() {
			if err := srv.Serve(activeLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				select {
				case serverErrCh <- err:
				default:
				}
			}
		}()
	}

	supCtx, supCancel := context.WithCancel(context.Background())
	supErrCh := make(chan error, 1)
	go func() {
		supErrCh <- sup.Run(supCtx)
	}()

	go func() {
		select {
		case <-sup.BootstrapDone():
		case <-sigCtx.Done():
			return
		}
		runtime.GC()
		debug.FreeOSMemory()
		applyMemoryCeiling(gwMB, compact)
	}()

	cloudCtx, cloudCancel := context.WithCancel(sigCtx)
	defer cloudCancel()
	if zp != nil || cf != nil || sup.IsMasterKeyAutoGenerated() {
		go orchestrateCloudInfrastructure(cloudCtx, sup, gw, zp, cf, zpDomain, customDomain, projectIPv6, region)
	}

	select {
	case err := <-serverErrCh:
		log.Printf("[Gateway] Fatal: HTTP server error: %v", err)
		teardown(srv, gw, sup, supCancel, cloudCancel, false)
		os.Exit(1)
	case err := <-supErrCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("[Gateway] Fatal: Worker supervisor halted: %v", err)
		}
		teardown(srv, gw, sup, supCancel, cloudCancel, false)
		os.Exit(1)
	case <-sigCtx.Done():
		log.Println("[Gateway] Termination signal received. Initiating graceful teardown...")
	}

	teardown(srv, gw, sup, supCancel, cloudCancel, true)
	log.Println("[Gateway] BERMUDA PORTAL Edge Router shutdown complete. Exit 0.")
}
