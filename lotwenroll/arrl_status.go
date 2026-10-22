package lotwenroll

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const arrlStatusURL = "https://lotw.arrl.org/lotw/crl"

// ARRLCertificateStatusClient queries the public certificate-status endpoint
// used by TQSL. It never falls back to TQSL's locally cached status file.
type ARRLCertificateStatusClient struct {
	HTTPClient *http.Client
	Now        func() time.Time
}

type arrlCertificateStatusResponse struct {
	XMLName xml.Name `xml:"LoTW_CRL"`
	Serial  []string `xml:"Serial"`
	Status  []string `xml:"Status"`
}

// Check performs a TLS-verified, cache-revalidating status query. The
// observation timestamp is derived from the HTTP Date and Age headers, so a
// cached response does not become fresh merely because it was just fetched.
func (c ARRLCertificateStatusClient) Check(ctx context.Context, cert *x509.Certificate) (StatusEvidence, error) {
	evidence := StatusEvidence{Status: StatusUnknown, Source: arrlStatusURL}
	if cert == nil || cert.SerialNumber == nil || cert.SerialNumber.Sign() <= 0 || !cert.SerialNumber.IsInt64() {
		return evidence, errors.New("certificate has no positive LoTW-compatible serial number")
	}
	var cacheNonce [16]byte
	if _, err := rand.Read(cacheNonce[:]); err != nil {
		return evidence, fmt.Errorf("create LoTW status cache key: %w", err)
	}
	endpoint, err := url.Parse(arrlStatusURL)
	if err != nil {
		return evidence, err
	}
	query := endpoint.Query()
	serial := cert.SerialNumber.String()
	query.Set("serial", serial)
	// TQSL's endpoint is cacheable for two weeks. A unique ignored parameter
	// plus revalidation directives prevents a shared HTTP cache from reusing a
	// prior answer for this request.
	query.Set("arap_nonce", hex.EncodeToString(cacheNonce[:]))
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return evidence, err
	}
	request.Header.Set("Accept", "application/xml, text/plain;q=0.9")
	request.Header.Set("Cache-Control", "no-cache, no-store, max-age=0")
	request.Header.Set("Pragma", "no-cache")
	request.Header.Set("User-Agent", "ARAP enrollment status checker")

	client := c.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	response, err := client.Do(request)
	if err != nil {
		return evidence, fmt.Errorf("query LoTW certificate status: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return evidence, fmt.Errorf("LoTW certificate-status endpoint returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 8193))
	if err != nil {
		return evidence, fmt.Errorf("read LoTW certificate status: %w", err)
	}
	if len(body) == 0 || len(body) > 8192 {
		return evidence, errors.New("LoTW certificate-status response has invalid size")
	}
	var parsed arrlCertificateStatusResponse
	if err := xml.Unmarshal(body, &parsed); err != nil || parsed.XMLName.Local != "LoTW_CRL" {
		return evidence, errors.New("LoTW certificate-status response is malformed")
	}
	if len(parsed.Serial) != 1 || len(parsed.Status) != 1 {
		return evidence, errors.New("LoTW certificate-status response must contain one serial and one status")
	}
	if strings.TrimSpace(parsed.Serial[0]) != serial {
		return evidence, errors.New("LoTW certificate-status response serial does not match the request")
	}
	serverDate, err := http.ParseTime(response.Header.Get("Date"))
	if err != nil {
		return evidence, errors.New("LoTW certificate-status response has no valid Date header")
	}
	age := int64(0)
	if value := response.Header.Get("Age"); value != "" {
		age, err = strconv.ParseInt(value, 10, 64)
		if err != nil || age < 0 || age > int64((365*24*time.Hour)/time.Second) {
			return evidence, errors.New("LoTW certificate-status response has an invalid Age header")
		}
	}
	observed := serverDate.UTC().Add(-time.Duration(age) * time.Second)
	now := time.Now().UTC()
	if c.Now != nil {
		now = c.Now().UTC()
	}
	if observed.After(now.Add(5 * time.Minute)) {
		return evidence, errors.New("LoTW certificate-status response is future-dated")
	}
	// The HTTP Date header has one-second precision, and the status host's clock
	// may be slightly ahead. Clamping to local observation time is conservative:
	// it can only make the evidence age sooner.
	if observed.After(now) {
		observed = now
	}
	evidence.ObservedAt = observed
	switch strings.TrimSpace(parsed.Status[0]) {
	case "Unrevoked":
		evidence.Status = StatusGood
	case "Revoked":
		evidence.Status = StatusRevoked
	case "Superceded", "Expired", "Bad serial":
		evidence.Status = StatusInvalid
	default:
		evidence.Status = StatusUnknown
	}
	return evidence, nil
}
