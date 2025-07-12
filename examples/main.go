package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/mdsohelmia/acme"
)

func main() {
	fmt.Println("🔒 CertForge - DNS SSL Certificate Generator")
	fmt.Println("===========================================")

	// Configuration
	config := &acme.ClientConfig{
		Username:  "sohelcse1999@gmail.com", // Change to your email
		Mode:      acme.ModeLive,            // Use ModeStaging for testing, ModeLive for production
		KeyLength: 4096,
		BasePath:  "data/le",
	}

	// Initialize client
	fmt.Println("🚀 Initializing ACME client...")
	client, err := acme.NewClient(config)
	if err != nil {
		log.Fatalf("❌ Failed to create ACME client: %v", err)
	}
	defer client.Close()

	// Domains to get certificate for (supports wildcards with DNS validation)
	domains := []string{"myssl.sohel.pro"}
	fmt.Printf("📋 Creating order for domains: %v\n", domains)

	order, err := client.CreateOrder(domains)
	if err != nil {
		log.Fatalf("❌ Failed to create order: %v", err)
	}

	fmt.Printf("✅ Order created successfully!\n")
	fmt.Printf("   📝 Order ID: %s\n", order.GetID())
	fmt.Printf("   📊 Status: %s\n", order.GetStatus())
	fmt.Printf("   ⏰ Expires: %s\n", order.GetExpiresAt())

	// Get authorizations
	fmt.Println("\n🔍 Getting authorizations...")
	authorizations, err := client.Authorize(order)
	if err != nil {
		log.Fatalf("❌ Failed to get authorizations: %v", err)
	}

	fmt.Printf("✅ Got %d authorizations\n", len(authorizations))

	// Process DNS challenges for each domain
	allValidated := true
	for i, auth := range authorizations {
		fmt.Printf("\n--- 🌐 Processing Domain %d/%d: %s ---\n", i+1, len(authorizations), auth.GetDomain())

		// Get DNS TXT record details
		txtRecord := auth.GetTxtRecord()
		if txtRecord == nil {
			log.Printf("❌ No DNS challenge available for %s", auth.GetDomain())
			allValidated = false
			continue
		}

		fmt.Printf("📋 DNS Challenge Details:\n")
		fmt.Printf("   🏷️  Record Name: %s\n", txtRecord.GetName())
		fmt.Printf("   🔑 Record Value: %s\n", txtRecord.GetValue())
		fmt.Printf("\n📝 Please create the following DNS TXT record:\n")
		fmt.Printf("   Name:  %s\n", txtRecord.GetName())
		fmt.Printf("   Type:  TXT\n")
		fmt.Printf("   Value: %s\n", txtRecord.GetValue())
		fmt.Printf("   TTL:   300 (or your DNS provider's minimum)\n")

		fmt.Println("\n⏳ Waiting for you to create the DNS record...")
		fmt.Println("   1. Log into your DNS provider")
		fmt.Println("   2. Create the TXT record shown above")
		fmt.Println("   3. Wait for DNS propagation (usually 1-5 minutes)")
		fmt.Print("   4. Press Enter when ready: ")

		var input string
		fmt.Scanln(&input)

		// Self test DNS
		fmt.Println("🔍 Running DNS self-test...")
		if !client.SelfTest(auth) {
			log.Printf("❌ DNS self test failed for %s", auth.GetDomain())
			fmt.Println("   Please verify the DNS record is correct and has propagated")
			allValidated = false
			continue
		}

		// Wait a bit more for DNS propagation to all Let's Encrypt servers
		fmt.Println("⏳ Waiting additional 30 seconds for DNS propagation...")
		time.Sleep(30 * time.Second)

		// Request validation from Let's Encrypt
		fmt.Println("🔐 Requesting validation from Let's Encrypt...")
		dnsChallenge := auth.GetDNSChallenge()
		if dnsChallenge == nil {
			log.Printf("❌ No DNS challenge found for %s", auth.GetDomain())
			allValidated = false
			continue
		}

		if !client.Validate(dnsChallenge, 15) {
			log.Printf("❌ DNS validation failed for %s", auth.GetDomain())
			allValidated = false
			continue
		}

		fmt.Printf("🎉 Successfully validated %s\n", auth.GetDomain())
	}

	if !allValidated {
		log.Fatal("❌ Not all domains were validated. Please fix the issues above and try again.")
	}

	// Wait for all validations to complete
	fmt.Println("\n⏳ Waiting for all validations to complete...")
	time.Sleep(5 * time.Second)

	// Check if order is ready
	fmt.Println("🔍 Checking if order is ready for certificate generation...")
	attempts := 0
	maxAttempts := 10

	for attempts < maxAttempts {
		if client.IsReady(order) {
			break
		}

		attempts++
		if attempts < maxAttempts {
			fmt.Printf("   ⏳ Order not ready yet, waiting... (attempt %d/%d)\n", attempts, maxAttempts)
			time.Sleep(3 * time.Second)
		}
	}

	if !client.IsReady(order) {
		log.Fatal("❌ Order did not become ready within the timeout period")
	}

	fmt.Println("✅ Order is ready! Generating certificate...")

	// Get the certificate
	certificate, err := client.GetCertificate(order)
	if err != nil {
		log.Fatalf("❌ Failed to get certificate: %v", err)
	}

	// Save certificate files
	fmt.Println("\n💾 Saving certificate files...")

	files := map[string][]byte{
		"cert/certificate.crt":  []byte(certificate.GetCertificate(false)), // Domain cert only
		"cert/private.key":      []byte(certificate.GetPrivateKey()),
		"cert/intermediate.crt": []byte(certificate.GetIntermediate()),
		"cert/fullchain.crt":    []byte(certificate.GetCertificate(true)), // Full chain
	}

	for filename, content := range files {
		var perm os.FileMode = 0644
		if filename == "private.key" {
			perm = 0600 // Private key should be more restricted
		}

		err = os.WriteFile(filename, content, perm)
		if err != nil {
			log.Printf("❌ Failed to save %s: %v", filename, err)
		} else {
			fmt.Printf("✅ Saved: %s\n", filename)
		}
	}

	fmt.Println("\n🎉 Certificate generated successfully!")
	fmt.Printf("📅 Certificate expires: %s\n", certificate.GetExpiryDate().Format("2006-01-02 15:04:05"))
	fmt.Printf("🔗 Domains covered: %v\n", domains)

	fmt.Println("\n📋 Files created:")
	fmt.Println("   📄 cert/certificate.crt    - Domain certificate")
	fmt.Println("   🔐 cert/private.key        - Private key (keep secure!)")
	fmt.Println("   📄 cert/intermediate.crt   - Intermediate certificate")
	fmt.Println("   📄 cert/fullchain.crt      - Full certificate chain")

	fmt.Println("\n🚀 Ready to deploy to your Vidinfra platform!")
	fmt.Println("\n🧹 Cleanup: You can now remove the DNS TXT records.")
}
