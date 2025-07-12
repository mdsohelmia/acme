# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-12-21

### Added
- Initial release of Go ACME client
- DNS-01 validation support for wildcard certificates
- Retryable HTTP client for improved reliability
- Complete ACME v2 protocol implementation
- Account management with automatic key generation
- Certificate chain handling (domain, intermediate, fullchain)
- Self-test functionality for DNS propagation
- Comprehensive error handling and logging
- Production-ready configuration options

### Features
- Support for Let's Encrypt staging and production environments
- Automatic retry logic with exponential backoff
- Concurrent certificate generation capabilities
- Decoupled design for flexible deployment scenarios
- Zero filesystem dependencies for certificate storage
- Multi-tenant SaaS platform ready

### Documentation
- Complete API reference
- Usage examples for common scenarios
- Deployment guides for Nginx, CDN, and Load Balancers
- Best practices for security and performance
- Migration guide from PHP yaac client

### Dependencies
- `github.com/hashicorp/go-retryablehttp v0.7.4` - For reliable HTTP requests
- Go 1.21+ - Minimum Go version requirement
