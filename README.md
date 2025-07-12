# acme - Go ACME Client

A simplified and decoupled Let's Encrypt client for Go, based on [ACME V2](https://tools.ietf.org/html/rfc8555). This client aims to be framework-agnostic and returns certificate data directly without writing to filesystem or coupling to specific web servers.

## Features

- 🔒 **DNS-01 validation only** - Perfect for wildcard certificates
- 🚀 **Zero dependencies** except `hashicorp/go-retryablehttp` for reliability
- 🌍 **Production ready** - Built for high-scale, multi-tenant environments
- 📦 **Decoupled design** - Returns certificate data, doesn't manage files
- 🔄 **Automatic retries** - Robust HTTP client with exponential backoff
- ⚡ **High performance** - Optimized for concurrent certificate generation

## Why This Package?

This package is extremely useful when you need to dynamically fetch and install certificates in:

- **Multi-tenant SaaS platforms** - Generate certificates for customer domains
- **CDN/Edge deployments** - Secure video delivery and API endpoints
- **Containerized environments** - Certificate management without filesystem coupling
- **Wildcard certificates** - `*.yourdomain.com` support via DNS validation
- **API integrations** - Programmatic certificate lifecycle management

Almost all existing ACME clients are coupled to specific web servers or fixed domain sets. This client provides complete flexibility for dynamic certificate management.

## Installation

```bash
go get github.com/mdsohelmia/acme
```

## Requirements

- Go 1.21+
- DNS provider with API access (for TXT record creation)
- Valid email address for Let's Encrypt account

## Quick Start

### Basic Usage

```go
package main

import (
    "fmt"
    "log"

    "github.com/mdsohelmia/acme"
)

func main() {
    // Configure the client
    config := &acme.ClientConfig{
        Username:  "admin@yourdomain.com",
        Mode:      acme.ModeStaging,  // Use ModeStaging for testing
        KeyLength: 4096,
        BasePath:  "data/le",
    }

    // Create client
    client, err := acme.NewClient(config)
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // Create order for domains
    domains := []string{"*.yourdomain.com", "yourdomain.com"}
    order, err := client.CreateOrder(domains)
    if err != nil {
        log.Fatal(err)
    }

    // Get authorizations
    auths, err := client.Authorize(order)
    if err != nil {
        log.Fatal(err)
    }

    // Process DNS challenges
    for _, auth := range auths {
        txtRecord := auth.GetTxtRecord()
        if txtRecord == nil {
            continue
        }

        fmt.Printf("Create DNS TXT record:\n")
        fmt.Printf("Name: %s\n", txtRecord.GetName())
        fmt.Printf("Value: %s\n", txtRecord.GetValue())

        // Create the DNS record in your DNS provider
        // Wait for user confirmation or automate via DNS API

        // Validate the challenge
        if client.SelfTest(auth) {
            dnsChallenge := auth.GetDNSChallenge()
            client.Validate(dnsChallenge, 15)
        }
    }

    // Get certificate when ready
    if client.IsReady(order) {
        cert, err := client.GetCertificate(order)
        if err != nil {
            log.Fatal(err)
        }

        // Use the certificate data
        certPEM := cert.GetCertificate()        // Full chain
        keyPEM := cert.GetPrivateKey()          // Private key
        intermediatePEM := cert.GetIntermediate() // Intermediate only
    }
}
```

## API Reference

### Client Configuration

```go
type ClientConfig struct {
    Username  string  // Email for Let's Encrypt account (required)
    Mode      string  // acme.ModeLive or acme.ModeStaging
    KeyLength int     // RSA key length (default: 4096)
    BasePath  string  // Directory for account storage (default: "le")
    SourceIP  string  // Optional: bind to specific IP
}
```

**Modes:**
- `acme.ModeStaging` - Let's Encrypt staging environment (for testing)
- `acme.ModeLive` - Let's Encrypt production environment

### Client Methods

#### NewClient(config *ClientConfig) (*Client, error)
Creates a new ACME client and initializes the Let's Encrypt account.

#### CreateOrder(domains []string) (*Order, error)
Creates a new certificate order for the specified domains. Supports wildcards with DNS validation.

```go
// Single domain
order, err := client.CreateOrder([]string{"example.com"})

// Multiple domains
order, err := client.CreateOrder([]string{"example.com", "www.example.com"})

// Wildcard (DNS validation required)
order, err := client.CreateOrder([]string{"*.example.com", "example.com"})
```

#### Authorize(order *Order) ([]*Authorization, error)
Retrieves authorizations for the order. Each domain gets one authorization with DNS challenges.

#### SelfTest(auth *Authorization) bool
Tests if the DNS TXT record is properly configured and propagated.

#### Validate(challenge *Challenge, maxAttempts int) bool
Submits the challenge to Let's Encrypt for validation.

#### IsReady(order *Order) bool
Checks if the order is ready for certificate generation.

#### GetCertificate(order *Order) (*Certificate, error)
Generates and retrieves the final certificate.

### Data Types

#### Order
Represents a certificate order.

```go
order.GetID() string              // Order ID
order.GetStatus() string          // Order status
order.GetDomains() []string       // Domains in order
order.GetExpiresAt() time.Time    // Order expiration
```

#### Authorization
Represents domain authorization.

```go
auth.GetDomain() string                    // Domain being authorized
auth.GetTxtRecord() *Record               // DNS TXT record details
auth.GetDNSChallenge() *Challenge         // DNS challenge
auth.GetExpires() time.Time               // Authorization expiration
```

#### Record
DNS TXT record information.

```go
record.GetName() string    // Record name (e.g., "_acme-challenge.example.com")
record.GetValue() string   // Record value (challenge token)
```

#### Certificate
Final certificate with all components.

```go
cert.GetCertificate() string         // Full certificate chain
cert.GetCertificate(false) string    // Domain certificate only
cert.GetPrivateKey() string          // Private key
cert.GetIntermediate() string        // Intermediate certificate
cert.GetExpiryDate() time.Time       // Certificate expiration
cert.GetCSR() string                 // Certificate signing request
```

## Advanced Usage

### Production Configuration

```go
config := &acme.ClientConfig{
    Username:  "ssl@yourcompany.com",
    Mode:      acme.ModeLive,        // Production
    KeyLength: 4096,
    BasePath:  "/etc/ssl/acme",      // Secure storage
}
```

### Automated DNS Integration

```go
func automatedCertificateGeneration(domains []string) (*acme.Certificate, error) {
    client, err := acme.NewClient(config)
    if err != nil {
        return nil, err
    }
    defer client.Close()

    order, err := client.CreateOrder(domains)
    if err != nil {
        return nil, err
    }

    auths, err := client.Authorize(order)
    if err != nil {
        return nil, err
    }

    // Automated DNS record creation
    for _, auth := range auths {
        txtRecord := auth.GetTxtRecord()

        // Create DNS record via your provider's API
        err := createDNSRecord(txtRecord.GetName(), txtRecord.GetValue())
        if err != nil {
            return nil, err
        }

        // Wait for DNS propagation
        if !waitForDNSPropagation(txtRecord, 300) {
            return nil, fmt.Errorf("DNS propagation timeout")
        }

        // Validate
        dnsChallenge := auth.GetDNSChallenge()
        if !client.Validate(dnsChallenge, 15) {
            return nil, fmt.Errorf("validation failed for %s", auth.GetDomain())
        }
    }

    // Get certificate
    return client.GetCertificate(order)
}
```

### Concurrent Certificate Generation

```go
func generateMultipleCertificates(domainSets [][]string) error {
    var wg sync.WaitGroup
    results := make(chan result, len(domainSets))

    for _, domains := range domainSets {
        wg.Add(1)
        go func(domains []string) {
            defer wg.Done()
            cert, err := automatedCertificateGeneration(domains)
            results <- result{domains: domains, cert: cert, err: err}
        }(domains)
    }

    wg.Wait()
    close(results)

    // Process results
    for result := range results {
        if result.err != nil {
            log.Printf("Failed to generate cert for %v: %v", result.domains, result.err)
        } else {
            deployCertificate(result.domains, result.cert)
        }
    }

    return nil
}
```

### Certificate Deployment Examples

#### Nginx Deployment
```go
func deployToNginx(cert *acme.Certificate, domains []string) error {
    // Save certificate files
    err := os.WriteFile("/etc/nginx/ssl/fullchain.crt",
        []byte(cert.GetCertificate()), 0644)
    if err != nil {
        return err
    }

    err = os.WriteFile("/etc/nginx/ssl/private.key",
        []byte(cert.GetPrivateKey()), 0600)
    if err != nil {
        return err
    }

    // Reload Nginx
    return exec.Command("nginx", "-s", "reload").Run()
}
```

#### CDN Deployment
```go
func deployCDN(cert *acme.Certificate, domains []string) error {
    // Most CDNs want separate certificate and key
    domainCert := cert.GetCertificate(false)  // Domain cert only
    privateKey := cert.GetPrivateKey()
    intermediate := cert.GetIntermediate()

    return cdnAPI.UploadCertificate(domains[0], domainCert, privateKey, intermediate)
}
```

#### Load Balancer Deployment
```go
func deployLoadBalancer(cert *acme.Certificate, domains []string) error {
    // Load balancers typically want the full chain
    fullChain := cert.GetCertificate(true)
    privateKey := cert.GetPrivateKey()

    return loadBalancerAPI.UpdateSSL(domains, fullChain, privateKey)
}
```

## Error Handling

The client provides detailed error information:

```go
cert, err := client.GetCertificate(order)
if err != nil {
    switch {
    case strings.Contains(err.Error(), "DNS"):
        log.Printf("DNS validation failed: %v", err)
        // Handle DNS issues
    case strings.Contains(err.Error(), "timeout"):
        log.Printf("Request timeout: %v", err)
        // Handle timeout issues
    default:
        log.Printf("Certificate generation failed: %v", err)
        // Handle other errors
    }
}
```

## Best Practices

### Security
- **Protect private keys**: Store with 0600 permissions
- **Secure account storage**: Use appropriate file permissions for BasePath
- **Certificate rotation**: Renew certificates 30 days before expiration
- **Validate inputs**: Always validate domain names before processing

### Performance
- **Concurrent processing**: Generate multiple certificates in parallel
- **DNS optimization**: Cache DNS provider connections
- **Retry logic**: The client includes automatic retries for reliability
- **Resource cleanup**: Always call `client.Close()` when done

### Monitoring
- **Certificate expiry**: Monitor expiration dates
- **Validation failures**: Log and alert on DNS validation issues
- **Rate limiting**: Be aware of Let's Encrypt rate limits
- **Health checks**: Verify certificate validity regularly

## Rate Limits

Let's Encrypt has the following rate limits:
- **Certificates per Registered Domain**: 50 per week
- **Duplicate Certificate**: 5 per week
- **Failed Validations**: 5 failures per account, per hostname, per hour
- **New Orders**: 300 per account per 3 hours

Plan your certificate generation accordingly.

## Examples

### Multi-tenant SaaS Platform
```go
func generateCustomerCertificate(customerDomain string) error {
    domains := []string{customerDomain, fmt.Sprintf("www.%s", customerDomain)}

    cert, err := automatedCertificateGeneration(domains)
    if err != nil {
        return err
    }

    // Deploy to customer's CDN edge
    return deployToCustomerCDN(customerDomain, cert)
}
```

### Wildcard Certificate for Microservices
```go
func generateWildcardCert(baseDomain string) error {
    domains := []string{
        fmt.Sprintf("*.%s", baseDomain),
        baseDomain,
    }

    cert, err := automatedCertificateGeneration(domains)
    if err != nil {
        return err
    }

    // Deploy to all microservices
    services := []string{"api", "auth", "cdn", "admin"}
    for _, service := range services {
        subdomain := fmt.Sprintf("%s.%s", service, baseDomain)
        deployToService(subdomain, cert)
    }

    return nil
}
```
## Contributing

Contributions are welcome! Please ensure:
- Tests pass for all changes
- Documentation is updated
- Code follows Go conventions
- DNS validation works across providers

## License

Apache 2.0 License - same as the original PHP yaac project.

## Support

- 🐛 **Issues**: [GitHub Issues](https://github.com/mdsohelmia/acme/issues)
- 📧 **Email**: Contact package maintainer
- 💬 **Discussions**: [GitHub Discussions](https://github.com/mdsohelmia/acme/discussions)

---

**Built for high-performance, production-grade certificate management in Go.**
