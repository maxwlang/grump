package main

import (
    "context"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net"
    "os"
    "os/signal"
    "strconv"
    "strings"
    "syscall"
    "time"

    "github.com/redis/go-redis/v9"
)

type PortRange struct {
    Start int `json:"start"`
    End   int `json:"end"`
}

type Config struct {
    TargetCIDR           string            `json:"target_cidr"`
    RedisHost            string            `json:"redis_host"`
    RedisPort            int               `json:"redis_port"`
    RedisTTL             int               `json:"redis_ttl"`
    RedisPrefix          string            `json:"redis_prefix"`
    ListenAddr           string            `json:"listen_address"`
    MaxScansPerIP        int               `json:"max_scans_per_ip"`
    MaxScansPerIPTimeout int               `json:"max_scans_per_ip_timeout"`
    DisallowedHosts      []string          `json:"disallowed_hosts"`
    PortRanges           []PortRange       `json:"port_ranges"`
    Timeouts             map[string]int    `json:"timeouts"`
}

var (
    redisClient *redis.Client
    ctx         = context.Background()
    targetIPs   []net.IP
    config      Config
)

func redisKey(parts ...string) string {
    return fmt.Sprintf("%s%s", config.RedisPrefix, strings.Join(parts, ":"))
}

func logEvent(proto, result, srcIP string, srcPort int, dstIP string, dstPort int, extra map[string]interface{}) {
    if net.ParseIP(srcIP) == nil || net.ParseIP(dstIP) == nil {
        log.Printf(`{"level":"warn","message":"Malformed IP","src_ip":"%s","dst_ip":"%s"}`, srcIP, dstIP)
        return
    }

    event := map[string]interface{}{
        "timestamp": time.Now().Format(time.RFC3339),
        "proto":     proto,
        "result":    result,
        "src_ip":    srcIP,
        "src_port":  srcPort,
        "dst_ip":    dstIP,
        "dst_port":  dstPort,
    }

    for k, v := range extra {
        event[k] = v
    }

    jsonEvent, _ := json.Marshal(event)
    fmt.Println(string(jsonEvent))
}

func flattenPortRanges() []int {
    var ports []int
    for _, r := range config.PortRanges {
        for p := r.Start; p <= r.End; p++ {
            ports = append(ports, p)
        }
    }
    return ports
}

func formatPortList(portList []int) string {
    if len(portList) == 0 {
        return ""
    }
    result := ""
    start := portList[0]
    prev := portList[0]
    for i := 1; i <= len(portList); i++ {
        var curr int
        if i < len(portList) {
            curr = portList[i]
        } else {
            curr = portList[i-1] + 2
        }
        if curr != prev+1 {
            if start == prev {
                result += fmt.Sprintf("%d,", start)
            } else {
                result += fmt.Sprintf("%d-%d,", start, prev)
            }
            start = curr
        }
        prev = curr
    }
    return strings.TrimRight(result, ",")
}

func checkPortWithTimeout(ip net.IP, port int, timeout time.Duration) bool {
    if ip.To4() == nil {
        return false
    }
    addr := fmt.Sprintf("%s:%d", ip.String(), port)
    conn, err := net.DialTimeout("tcp", addr, timeout)
    if err != nil {
        return false
    }
    conn.Close()
    return true
}

func resolveTargetIPWithCacheFlag(port int, clientIP string) (string, bool) {
    timeout := time.Second
    if ms, ok := config.Timeouts[fmt.Sprintf("%d", port)]; ok {
        timeout = time.Duration(ms) * time.Millisecond
    }

    cacheKey := redisKey("map", fmt.Sprintf("%d", port))
    cachedIP, err := redisClient.Get(ctx, cacheKey).Result()
    if err == nil && cachedIP != "" {
        ip := net.ParseIP(cachedIP)
        _, cidr, _ := net.ParseCIDR(config.TargetCIDR)
        if ip != nil && ip.To4() != nil && cidr.Contains(ip) && checkPortWithTimeout(ip, port, timeout) {
            return cachedIP, true
        }
    }

    redisScanKey := redisKey("scan", clientIP)
    scanned, _ := redisClient.Incr(ctx, redisScanKey).Result()
    if scanned == 1 {
        redisClient.Expire(ctx, redisScanKey, time.Duration(config.MaxScansPerIPTimeout)*time.Second)
    }
    if scanned > int64(config.MaxScansPerIP) {
        logEvent("TCP", "RATE_LIMIT", clientIP, 0, "-", port, nil)
        return "", false
    }

    for _, ip := range targetIPs {
        if ip.To4() == nil {
            continue
        }
        skip := false
        for _, disallowed := range config.DisallowedHosts {
            if ip.String() == disallowed {
                skip = true
                break
            }
        }
        if skip {
            continue
        }

        if checkPortWithTimeout(ip, port, timeout) {
            redisClient.Set(ctx, cacheKey, ip.String(), time.Duration(config.RedisTTL)*time.Second)
            return ip.String(), false
        }
    }

    return "", false
}

func generateTargetIPs(cidr string) ([]net.IP, error) {
    ip, ipnet, err := net.ParseCIDR(cidr)
    if err != nil {
        return nil, err
    }
    var ips []net.IP
    for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
        dup := make(net.IP, len(ip))
        copy(dup, ip)
        if dup.To4() != nil {
            ips = append(ips, dup)
        }
    }
    if len(ips) > 2 {
        return ips[1 : len(ips)-1], nil
    }
    return []net.IP{}, nil
}

func inc(ip net.IP) {
    for j := len(ip) - 1; j >= 0; j-- {
        ip[j]++
        if ip[j] > 0 {
            break
        }
    }
}

func handleTCP(port int) {
    ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", config.ListenAddr, port))
    if err != nil {
        log.Fatalf("TCP listen error on port %d: %v", port, err)
    }

    for {
        conn, err := ln.Accept()
        if err != nil {
            continue
        }
        go func(c net.Conn) {
            startTime := time.Now()
            defer c.Close()
            srcAddr := c.RemoteAddr().String()
            srcIP, srcPortStr, err := net.SplitHostPort(srcAddr)
            if err != nil {
                return
            }
            srcPort, err := strconv.Atoi(srcPortStr)
            if err != nil {
                return
            }

            targetIP, fromCache := resolveTargetIPWithCacheFlag(port, srcIP)
            if targetIP == "" {
                logEvent("TCP", "CANCELED", srcIP, srcPort, "-", port, nil)
                return
            }

            dstConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", targetIP, port), time.Second)
            if err != nil {
                logEvent("TCP", "TIMEOUT", srcIP, srcPort, targetIP, port, nil)
                return
            }
            defer dstConn.Close()

            cacheStatus := "UNCACHED"
            if fromCache {
                cacheStatus = "CACHED"
            }

            logEvent("TCP", "ACCEPT", srcIP, srcPort, targetIP, port, map[string]interface{}{
                "duration_ms":  time.Since(startTime).Milliseconds(),
                "cache_status": cacheStatus,
            })

            go io.Copy(dstConn, c)
            io.Copy(c, dstConn)
        }(conn)
    }
}

func handleUDP(port int) {
    addr := net.UDPAddr{Port: port, IP: net.ParseIP(config.ListenAddr)}
    sock, err := net.ListenUDP("udp", &addr)
    if err != nil {
        log.Fatalf("UDP listen error on port %d: %v", port, err)
    }
    defer sock.Close()

    buf := make([]byte, 4096)
    for {
        n, clientAddr, err := sock.ReadFromUDP(buf)
        if err != nil {
            continue
        }

        targetIP, _ := resolveTargetIPWithCacheFlag(port, clientAddr.IP.String())
        if targetIP == "" {
            logEvent("UDP", "CANCELED", clientAddr.IP.String(), clientAddr.Port, "-", port, nil)
            continue
        }

        _, err = sock.WriteToUDP(buf[:n], &net.UDPAddr{IP: net.ParseIP(targetIP), Port: port})
        result := "RELAY"
        if err != nil {
            result = "ERROR"
        }
        logEvent("UDP", result, clientAddr.IP.String(), clientAddr.Port, targetIP, port, nil)
    }
}

func main() {
    if os.Geteuid() == 0 {
        log.Fatal("[GRUMP][SECURITY] This program should not be run as root.")
    }
    fmt.Println("GRUMP — Game Routing Unified Mapping Proxy")

    f, err := os.Open("config.json")
    if err != nil {
        log.Fatalf("Failed to open config.json: %v", err)
    }
    decoder := json.NewDecoder(f)
    if err := decoder.Decode(&config); err != nil {
        log.Fatalf("Failed to parse config.json: %v", err)
    }

    redisClient = redis.NewClient(&redis.Options{
        Addr: fmt.Sprintf("%s:%d", config.RedisHost, config.RedisPort),
    })

    _, err = redisClient.Ping(ctx).Result()
    if err != nil {
        log.Fatalf("Failed to connect to Redis: %v", err)
    }

    targetIPs, err = generateTargetIPs(config.TargetCIDR)
    if err != nil || len(targetIPs) == 0 {
        log.Fatalf("Invalid CIDR or no usable IPs: %v", err)
    }

    ports := flattenPortRanges()
    fmt.Printf("[GRUMP][TCP][LISTENING] %s:%s\n", config.ListenAddr, formatPortList(ports))
    fmt.Printf("[GRUMP][UDP][LISTENING] %s:%s\n", config.ListenAddr, formatPortList(ports))
    for _, port := range ports {
        go handleTCP(port)
        go handleUDP(port)
    }

    sigs := make(chan os.Signal, 1)
    signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
    <-sigs
    fmt.Println("\n[GRUMP] Shutting down gracefully...")
}
