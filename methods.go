package acme

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/hashicorp/go-retryablehttp"
)

// AccountResponse represents the ACME account response
type AccountResponse struct {
	Contact   []string `json:"contact"`
	CreatedAt string   `json:"createdAt"`
	Status    string   `json:"status"`
}

// OrderResponse represents the ACME order response
type OrderResponse struct {
	Status         string              `json:"status"`
	Expires        string              `json:"expires"`
	Identifiers    []map[string]string `json:"identifiers"`
	Authorizations []string            `json:"authorizations"`
	Finalize       string              `json:"finalize"`
	Certificate    string              `json:"certificate,omitempty"`
}

// AuthorizationResponse represents the ACME authorization response
type AuthorizationResponse struct {
	Identifier map[string]string   `json:"identifier"`
	Status     string              `json:"status"`
	Expires    string              `json:"expires"`
	Challenges []ChallengeResponse `json:"challenges"`
}

// ChallengeResponse represents the ACME challenge response
type ChallengeResponse struct {
	Type   string `json:"type"`
	Status string `json:"status"`
	URL    string `json:"url"`
	Token  string `json:"token"`
}

// GetAccount retrieves account information (public method)
func (c *Client) GetAccount() (*Account, error) {
	return c.getAccount()
}

// getOrder retrieves an existing order by ID (internal helper)
func (c *Client) getOrder(id string) (*Order, error) {
	url := strings.Replace(c.directories[DirectoryNewOrder], "new-order", "order", 1)
	url = fmt.Sprintf("%s/%s/%s", url, c.account.GetID(), id)

	jws, err := c.signPayloadKID(nil, url)
	if err != nil {
		return nil, err
	}

	resp, err := c.request("POST", url, jws)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var orderResp OrderResponse
	if err := json.Unmarshal(body, &orderResp); err != nil {
		return nil, err
	}

	domains := make([]string, len(orderResp.Identifiers))
	for i, identifier := range orderResp.Identifiers {
		domains[i] = identifier["value"]
	}

	return NewOrder(
		domains,
		url,
		orderResp.Status,
		orderResp.Expires,
		orderResp.Identifiers,
		orderResp.Authorizations,
		orderResp.Finalize,
	)
}

// GetOrder retrieves an existing order by ID (public method)
func (c *Client) GetOrder(id string) (*Order, error) {
	return c.getOrder(id)
}

// IsReady checks if an order is ready for finalization
func (c *Client) IsReady(order *Order) bool {
	updatedOrder, err := c.getOrder(order.GetID())
	if err != nil {
		fmt.Printf("Error checking order status: %v\n", err)
		return false
	}

	fmt.Printf("Order status: %s\n", updatedOrder.GetStatus())
	return updatedOrder.GetStatus() == "ready"
}

// CreateOrder creates a new ACME order
func (c *Client) CreateOrder(domains []string) (*Order, error) {
	identifiers := make([]map[string]string, len(domains))
	for i, domain := range domains {
		identifiers[i] = map[string]string{
			"type":  "dns",
			"value": domain,
		}
	}

	payload := map[string]interface{}{
		"identifiers": identifiers,
	}

	url := c.directories[DirectoryNewOrder]
	jws, err := c.signPayloadKID(payload, url)
	if err != nil {
		return nil, err
	}

	resp, err := c.request("POST", url, jws)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var orderResp OrderResponse
	if err := json.Unmarshal(body, &orderResp); err != nil {
		return nil, err
	}

	orderURL := resp.Header.Get("Location")
	return NewOrder(
		domains,
		orderURL,
		orderResp.Status,
		orderResp.Expires,
		orderResp.Identifiers,
		orderResp.Authorizations,
		orderResp.Finalize,
	)
}

// Authorize obtains authorizations for an order
func (c *Client) Authorize(order *Order) ([]*Authorization, error) {
	digest, err := c.getDigest()
	if err != nil {
		return nil, err
	}

	var authorizations []*Authorization
	for _, authURL := range order.GetAuthorizationURLs() {
		jws, err := c.signPayloadKID(nil, authURL)
		if err != nil {
			return nil, err
		}

		resp, err := c.request("POST", authURL, jws)
		if err != nil {
			return nil, err
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}

		var authResp AuthorizationResponse
		if err := json.Unmarshal(body, &authResp); err != nil {
			return nil, err
		}

		authorization, err := NewAuthorization(
			authResp.Identifier["value"],
			authResp.Expires,
			digest,
		)
		if err != nil {
			return nil, err
		}

		for _, challengeData := range authResp.Challenges {
			challenge := NewChallenge(
				authURL,
				challengeData.Type,
				challengeData.Status,
				challengeData.URL,
				challengeData.Token,
			)
			authorization.AddChallenge(challenge)
		}

		authorizations = append(authorizations, authorization)
	}

	return authorizations, nil
}

// SelfTest performs a DNS self-test for the authorization
func (c *Client) SelfTest(authorization *Authorization) bool {
	maxAttempts := 15
	return c.selfDNSTest(authorization, maxAttempts)
}

// selfDNSTest performs DNS validation self-test using Cloudflare DNS
func (c *Client) selfDNSTest(authorization *Authorization, maxAttempts int) bool {
	txtRecord := authorization.GetTxtRecord()
	if txtRecord == nil {
		return false
	}

	fmt.Printf("🔍 Testing DNS record: %s = %s\n", txtRecord.GetName(), txtRecord.GetValue())

	for maxAttempts > 0 {
		url := fmt.Sprintf("https://cloudflare-dns.com/dns-query?name=%s&type=TXT",
			txtRecord.GetName())

		req, err := retryablehttp.NewRequest("GET", url, nil)
		if err != nil {
			maxAttempts--
			continue
		}

		req.Header.Set("Accept", "application/dns-json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			maxAttempts--
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			maxAttempts--
			continue
		}

		var dnsResp struct {
			Answer []struct {
				Data string `json:"data"`
			} `json:"Answer"`
		}

		if err := json.Unmarshal(body, &dnsResp); err != nil {
			maxAttempts--
			continue
		}

		for _, answer := range dnsResp.Answer {
			data := strings.Trim(answer.Data, "\"")
			if data == txtRecord.GetValue() {
				fmt.Printf("✅ DNS record found and verified!\n")
				return true
			}
		}

		if maxAttempts > 1 {
			fmt.Printf("🔄 DNS record not found yet, retrying... (%d attempts left)\n", maxAttempts-1)
			time.Sleep(time.Duration(45/maxAttempts) * time.Second)
		}
		maxAttempts--
	}

	fmt.Printf("❌ DNS record not found after all attempts\n")
	return false
}

// Validate validates a DNS challenge
func (c *Client) Validate(challenge *Challenge, maxAttempts int) bool {
	digest, err := c.getDigest()
	if err != nil {
		return false
	}

	payload := map[string]interface{}{
		"keyAuthorization": challenge.GetToken() + "." + digest,
	}

	jws, err := c.signPayloadKID(payload, challenge.GetURL())
	if err != nil {
		return false
	}

	// Submit challenge
	resp, err := c.request("POST", challenge.GetURL(), jws)
	if err != nil {
		return false
	}
	resp.Body.Close()

	fmt.Printf("🔐 Challenge submitted to Let's Encrypt, waiting for validation...\n")

	// Poll for validation
	for maxAttempts > 0 {
		jws, err := c.signPayloadKID(nil, challenge.GetAuthorizationURL())
		if err != nil {
			return false
		}

		resp, err := c.request("POST", challenge.GetAuthorizationURL(), jws)
		if err != nil {
			return false
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return false
		}

		var authResp AuthorizationResponse
		if err := json.Unmarshal(body, &authResp); err != nil {
			return false
		}

		fmt.Printf("📋 Authorization status: %s\n", authResp.Status)

		if authResp.Status == "valid" {
			fmt.Printf("✅ Domain validation successful!\n")
			return true
		}

		if authResp.Status == "invalid" {
			fmt.Printf("❌ Domain validation failed\n")
			return false
		}

		if maxAttempts > 1 && authResp.Status != "valid" {
			fmt.Printf("⏳ Waiting for validation... (%d attempts remaining)\n", maxAttempts-1)
			time.Sleep(time.Duration(15/maxAttempts) * time.Second)
		}
		maxAttempts--
	}

	return false
}

// GetCertificate retrieves the certificate for an order
func (c *Client) GetCertificate(order *Order) (*Certificate, error) {
	// Generate new private key for certificate
	privateKey, privateKeyPEM, err := generateNewKey(c.config.KeyLength)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate CSR
	csr, err := generateCSR(order.GetDomains(), privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CSR: %w", err)
	}

	// Convert CSR to DER format
	csrDER, err := toDER(csr)
	if err != nil {
		return nil, fmt.Errorf("failed to convert CSR to DER: %w", err)
	}

	// Submit CSR for finalization
	payload := map[string]interface{}{
		"csr": base64.RawURLEncoding.EncodeToString(csrDER),
	}

	jws, err := c.signPayloadKID(payload, order.GetFinalizeURL())
	if err != nil {
		return nil, err
	}

	resp, err := c.request("POST", order.GetFinalizeURL(), jws)
	if err != nil {
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	var orderResp OrderResponse
	if err := json.Unmarshal(body, &orderResp); err != nil {
		return nil, err
	}

	// Poll for order completion and certificate URL
	maxAttempts := 30 // Wait up to 30 attempts (30 seconds)
	orderURL := order.GetURL()

	fmt.Println("📜 Waiting for certificate to be issued...")

	for maxAttempts > 0 {
		// Get updated order status
		jws, err := c.signPayloadKID(nil, orderURL)
		if err != nil {
			return nil, err
		}

		resp, err := c.request("POST", orderURL, jws)
		if err != nil {
			return nil, err
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}

		if err := json.Unmarshal(body, &orderResp); err != nil {
			return nil, err
		}

		fmt.Printf("📋 Order status: %s\n", orderResp.Status)

		if orderResp.Status == "valid" && orderResp.Certificate != "" {
			fmt.Println("🎉 Certificate is ready!")
			break
		}

		if orderResp.Status == "invalid" {
			return nil, fmt.Errorf("order became invalid")
		}

		if maxAttempts > 1 {
			fmt.Printf("⏳ Waiting for certificate... (%d attempts remaining)\n", maxAttempts-1)
			time.Sleep(1 * time.Second)
		}
		maxAttempts--
	}

	if orderResp.Certificate == "" {
		return nil, fmt.Errorf("certificate URL not available after polling")
	}

	fmt.Printf("📥 Downloading certificate from: %s\n", orderResp.Certificate)

	// Download certificate
	jws, err = c.signPayloadKID(nil, orderResp.Certificate)
	if err != nil {
		return nil, err
	}

	certResp, err := c.request("POST", orderResp.Certificate, jws)
	if err != nil {
		return nil, err
	}

	certChain, err := io.ReadAll(certResp.Body)
	certResp.Body.Close()
	if err != nil {
		return nil, err
	}

	// Clean up the certificate chain
	chainStr := strings.TrimSpace(string(certChain))

	return NewCertificate(privateKeyPEM, csr, chainStr)
}
