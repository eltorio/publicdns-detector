/*
 * Copyright (C) 2022 Ronan Le Meillat
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// Package main is the main package of the Public DNS Detector application.
// It provides functionality to detect the public IP address of a client using a DNS server.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/time/rate"
)

// Constants for default values
const (
	_serverAddr           = "192.0.2.1"          // DNS server default address
	_serverAddrIPv6       = "2001:db8::1"        // DNS server default address (IPv6)
	_ttl                  = 60                   // TTL default for the DNS records
	_httpAddr             = ""                   // Default address for the HTTP server
	_httpPort             = 80                   // Default port for the HTTP server
	_dnsAddr              = ""                   // Default address for the DNS server
	_dnsPort              = 53                   // Default port for the DNS server
	_zone                 = "zonetest.zone.tld." // Default zone for the DNS server
	_templateLocation     = "./templates"        // Default location for the templates
	_maxRequestsPerSecond = 10                   // Maximum requests per second
	_burstSize            = 5                    // Burst size
)

// Clients is a map that stores the IP addresses of the clients
type Clients map[string]string

// ResponseJson is a struct representing the JSON response
type ResponseJson struct {
	Server string `json:"server"`
}

var (
	dnsClients           = make(Clients) // DNS clients map for storing the IP addresses of the clients
	mu                   sync.Mutex
	serverAddr           string
	serverAddrIPv6       string
	ttl                  int
	httpAddr             string
	httpPort             int
	dnsAddr              string
	dnsPort              int
	zone                 string
	templateLocation     string
	maxRequestsPerSecond int
	burstSize            int
	rateLimiter          *rate.Limiter
	uniqueIPs            = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "publicdns_detector_unique_ips_total",
		Help: "Total number of unique IPs",
	})
	totalRequests = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "publicdns_detector_requests_total",
		Help: "Total number of requests",
	})
)

// init initializes the default flag values from environment variables or hardcoded values
func init() {

	flag.StringVar(&serverAddr, "serverAddr", getEnv("SERVER_ADDR", _serverAddr), "DNS server default address")
	flag.StringVar(&serverAddrIPv6, "serverAddrIPv6", getEnv("SERVER_ADDR_IPV6", _serverAddrIPv6), "DNS server default address (IPv6)")
	flag.IntVar(&ttl, "ttl", getEnvAsInt("TTL", _ttl), "TTL default for the DNS records")
	flag.StringVar(&httpAddr, "httpAddr", getEnv("HTTP_ADDR", _httpAddr), "Default address for the HTTP server")
	flag.IntVar(&httpPort, "httpPort", getEnvAsInt("HTTP_PORT", _httpPort), "Default port for the HTTP server")
	flag.StringVar(&dnsAddr, "dnsAddr", getEnv("DNS_ADDR", _dnsAddr), "Default address for the DNS server")
	flag.IntVar(&dnsPort, "dnsPort", getEnvAsInt("DNS_PORT", _dnsPort), "Default port for the DNS server")
	flag.StringVar(&zone, "zone", getEnv("ZONE", _zone), "Default zone for the DNS server")
	flag.StringVar(&templateLocation, "templateLocation", getEnv("TEMPLATE_LOCATION", _templateLocation), "Default location for the templates")
	flag.IntVar(&maxRequestsPerSecond, "maxRequestsPerSecond", getEnvAsInt("MAX_REQUESTS_PER_SECOND", _maxRequestsPerSecond), "Maximum requests per second")
	flag.IntVar(&burstSize, "burstSize", getEnvAsInt("BURST_SIZE", _burstSize), "Burst size")

	// Create a rate limiter
	rateLimiter = rate.NewLimiter(rate.Limit(maxRequestsPerSecond), burstSize)
	if rateLimiter == nil {
		log.Fatalf("Failed to create rate limiter")
	}
	// Register the Prometheus metrics
	prometheus.MustRegister(uniqueIPs)
	prometheus.MustRegister(totalRequests)
}

// getEnv returns the value of the environment variable with the given key,
// or the fallback value if the environment variable is not set.
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// getEnvAsInt returns the value of the environment variable with the given name as an integer,
// or the default value if the environment variable is not set or cannot be parsed as an integer.
func getEnvAsInt(name string, defaultVal int) int {
	valueStr := getEnv(name, "")
	if value, err := strconv.Atoi(valueStr); err == nil {
		return value
	}
	return defaultVal
}

// check if the Client map contains the IP address
func isNewIP(ip string) bool {
	mu.Lock()
	defer mu.Unlock()
	for _, v := range dnsClients {
		if v == ip {
			return false
		}
	}
	return true
}

// cheks request for preventing DNS injection
func checkRequest(r *dns.Msg) bool {
	if len(r.Question) != 1 {
		return false
	}
	if r.Question[0].Qclass != dns.ClassINET {
		return false
	}
	if r.Question[0].Qtype != dns.TypeA && r.Question[0].Qtype != dns.TypeAAAA {
		return false
	}
	if r.Question[0].Name[len(r.Question[0].Name)-1] != '.' {
		return false
	}
	if strings.Contains(r.Question[0].Name, "..") {
		return false
	}
	//check if the request is a valid FQDN
	if !dns.IsFqdn(r.Question[0].Name) {
		return false
	}
	// check if Name is in our zone
	if !dns.IsSubDomain(zone, r.Question[0].Name) {
		return false
	}
	return true
}

// handleDNS handles DNS requests and sets the DNS response
func handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	// Check if the request rate limit has been exceeded
	if !rateLimiter.Allow() {
		log.Printf("too many DNS requests\n")
		dns.HandleFailed(w, r)
		return
	}
	if !checkRequest(r) {
		log.Printf("malformed DNS requests\n")
		dns.HandleFailed(w, r)
		return
	}
	totalRequests.Inc()
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	var (
		rr  dns.RR
		err error
	)

	switch r.Question[0].Qtype {
	case dns.TypeA:
		log.Printf("serve record: %s %d IN A %s", r.Question[0].Name, ttl, serverAddr)
		record := fmt.Sprintf("%s %d IN A %s", r.Question[0].Name, ttl, serverAddr)
		rr, err = dns.NewRR(record)
	case dns.TypeAAAA:
		log.Printf("serve record: %s %d IN AAAA %s", r.Question[0].Name, ttl, serverAddrIPv6)
		record := fmt.Sprintf("%s %d IN AAAA %s", r.Question[0].Name, ttl, serverAddrIPv6)
		rr, err = dns.NewRR(record)
	}
	if rr != nil && err == nil {
		m.Answer = append(m.Answer, rr)
		hostFQDNWithoutDot := r.Question[0].Name[:len(r.Question[0].Name)-1]
		remoteIPAddr := strings.Split(w.RemoteAddr().String(), ":")[0]
		if isNewIP(remoteIPAddr) {
			uniqueIPs.Inc()
		}
		mu.Lock()
		defer mu.Unlock()
		dnsClients[hostFQDNWithoutDot] = remoteIPAddr

	}
	w.WriteMsg(m)
}

// setHeaders sets the headers for the HTTP response
func setHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Max-Age", "3600")
}

// handleHTTPDns handles HTTP requests for the /dns-detector endpoint
func handleHTTPDns(w http.ResponseWriter, r *http.Request) {
	if !rateLimiter.Allow() {
		http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
		return
	}
	mu.Lock()
	defer mu.Unlock()
	ip, ok := dnsClients[r.Host]
	if ok {
		// Answer with the IP address of the client in a JSON format
		setHeaders(w)
		w.Header().Set("Content-Type", "application/json")
		responseJson := ResponseJson{Server: ip}
		err := json.NewEncoder(w).Encode(responseJson)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	} else {
		http.NotFound(w, r)
	}
}

func handleHTTP(w http.ResponseWriter, r *http.Request, templatePath string, data interface{}) {
	if !rateLimiter.Allow() {
		http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
		return
	}

	setHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	tmpl, err := template.ParseFiles(fmt.Sprintf("templates/%s", templatePath))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// handleHTTPRoot handles HTTP requests for the root endpoint
func handleHTTPRoot(w http.ResponseWriter, r *http.Request) {

	// Create a data structure to pass to the template
	data := struct {
		Title     string
		Copyright string
	}{
		Title:     "Public DNS Detector",
		Copyright: "© 2024 Ronan LE MEILLAT. All rights reserved.",
	}
	handleHTTP(w, r, "root.html", data)
}

// handleHTTPLicense handles HTTP requests for the /license endpoint
func handleHTTPLicense(w http.ResponseWriter, r *http.Request) {

	// Create a data structure to pass to the template
	data := struct {
		Title       string
		License     string
		Year        string
		Author      string
		Email       string
		Website     string
		Company     string
		CompanyID   string
		Description string
	}{
		Title:       "License",
		License:     "AGPLv3 License",
		Year:        fmt.Sprintf("2023-%d", time.Now().Year()),
		Author:      "Ronan LE MEILLAT",
		Email:       "",
		Website:     "https://www.sctg.eu.org",
		Company:     "SCTG Development",
		CompanyID:   "",
		Description: "Public DNS Detector is a free software that allows you to detect the public IP address of a client using a DNS server.",
	}
	handleHTTP(w, r, "license.html", data)
}

// main is the entry point of the application
func main() {
	err := run()
	if err != nil {
		log.Fatalf("Failed to run the application: %v", err)
	}
}

func run() error {
	flag.Parse()

	if flag.NArg() > 0 && flag.Arg(0) == "help" {
		fmt.Println("Usage of my program:")
		flag.PrintDefaults()
		return nil
	}

	log.Println("Public DNS Detector is starting…")
	dns.HandleFunc(zone, handleDNS)
	go func() {
		_dnsAddr := fmt.Sprintf("%s:%d", dnsAddr, dnsPort)
		server := &dns.Server{Addr: _dnsAddr, Net: "udp"}
		err := server.ListenAndServe()
		if err != nil {
			log.Fatalf("Failed to start DNS server: %v", err)
		}
	}()
	_httpAddr := fmt.Sprintf("%s:%d", httpAddr, httpPort)
	http.HandleFunc("/", (handleHTTPRoot))
	http.HandleFunc("/license", handleHTTPLicense)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.HandleFunc("/dns-detector", handleHTTPDns)
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("OK")) })
	err := http.ListenAndServe(_httpAddr, nil)
	if err != nil {
		log.Fatalf("Failed to start HTTP server: %v", err)
	}
	return nil
}
