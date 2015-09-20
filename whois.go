package whois

import (
	"fmt"
	"net"
	"bufio"
	"bytes"
	"strings"
)

func Lookup(domain string) (string, error) {
	parts := strings.Split(domain, ".")
	tld := parts[len(parts) - 1]
	server := fmt.Sprint(tld, ".whois-servers.net")

	return ServerLookup(server, domain)
}

func ServerLookup(server string, query string) (string, error) {	
	conn, err := net.Dial("tcp", fmt.Sprint(server, ":43"))
	
	if err != nil {
		return "", err
	}

	fmt.Fprintf(conn, fmt.Sprint(query, "\r\n"));
	
	scanner := bufio.NewScanner(conn)

	var buffer bytes.Buffer

	for scanner.Scan() {
		buffer.WriteString(fmt.Sprint(scanner.Text(), "\n"))	
	}

	return buffer.String(), nil
}
