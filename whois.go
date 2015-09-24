package whois

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"strings"
	"time"
)

// WhoisResponse is passed to the DoesExist closure. It includes the query response and the domain queried
type WhoisResponse struct {
	Response string
	Domain   string
}

// DoesExist should return true if the whois record says the domain is available
type DoesExist func(WhoisResponse) bool

// ScanFrom is Scan's helper function to recursively query the whois server
func ScanFrom(start string, tld string, charset string, length int, cmp DoesExist, delay time.Duration, results map[string]bool) {

	for _, rune := range charset {

		if length == 0 {
			break
		}

		domain := fmt.Sprint(start, string(rune))
		ScanFrom(domain, tld, charset, length-1, cmp, delay, results)

		lookup, _ := Lookup(fmt.Sprint(domain, ".", tld))
		results[domain] = cmp(WhoisResponse{lookup, domain})
		time.Sleep(delay)
	}
}

// Scan searches for available domain names
func Scan(tld string, charset string, length int, cmp DoesExist, delay time.Duration) map[string]bool {

	results := make(map[string]bool)

	for _, rune := range charset {
		ScanFrom(string(rune), tld, charset, length-1, cmp, delay, results)
	}

	return results
}

// Lookup queries the whois server TLD.whois-servers.net
func Lookup(domain string) (string, error) {
	parts := strings.Split(domain, ".")
	tld := parts[len(parts)-1]
	server := fmt.Sprint(tld, ".whois-servers.net")

	if tld == "com" || tld == "net" || tld == "org" {
		domain = fmt.Sprint("=", domain)
	}

	return ServerLookup(server, domain)
}

// ServerLookup queries a specific whois server
func ServerLookup(server string, query string) (string, error) {
	conn, err := net.Dial("tcp", fmt.Sprint(server, ":43"))

	if err != nil {
		return "", err
	}

	fmt.Fprintf(conn, fmt.Sprint(query, "\r\n"))

	scanner := bufio.NewScanner(conn)

	var buffer bytes.Buffer

	for scanner.Scan() {
		buffer.WriteString(fmt.Sprint(scanner.Text(), "\n"))
	}

	return buffer.String(), nil
}
