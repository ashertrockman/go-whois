Go-Whois
========

Library for whois lookups, as specified by [RFC 3912](https://tools.ietf.org/html/rfc3912).

Basic usage:
```go
resp, err := whois.Lookup("google.com")
fmt.Println(resp)
```

Scanning:
```go
// Returns a map[string]bool of (domain:available)
// TLD, charset, length, condition of availability, delay
results := whois.Scan("sh", "abcdef", 3, func(wr whois.WhoisResponse) bool {
	return strings.Contains(wr.Response, "available")
}, time.Millisecond * 100)

```

Scanning with asynchronous messages:
```go
msg := make(chan string)

go func(c chan string) {
	whois.Scan("sh", "abcdef", 3, func(wr whois.WhoisResponse) bool {
		available := strings.Contains(wr.Response, "available")
		msg <- fmt.Sprintf("%s %t", wr.Domain, available)
		return available
	}, time.Millisecond * 100)
}(msg)

for {
	fmt.Println(<-msg)
}

```

