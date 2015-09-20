Go-Whois
========

Library for whois lookups, as specified by [RFC 3912](https://tools.ietf.org/html/rfc3912).

```go
// For TLDs using the Verisign server (whois.verisign-grs.com), add equals for exact match
resp, err := whois.Lookup("=google.com")
fmt.Println(resp)
```


