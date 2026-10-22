package lotwenroll

import (
	"context"
	"crypto/x509"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestARRLCertificateStatusUsesSerialAndFreshResponseTime(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	var gotRequest *http.Request
	client := ARRLCertificateStatusClient{
		Now: func() time.Time { return now },
		HTTPClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			gotRequest = request
			return &http.Response{
				StatusCode: http.StatusOK,
				Header: http.Header{
					"Date":          []string{now.Format(http.TimeFormat)},
					"Age":           []string{"60"},
					"Cache-Control": []string{"max-age=1209600"},
				},
				Body: io.NopCloser(strings.NewReader("<LoTW_CRL><Serial>12345</Serial><Status>Unrevoked</Status></LoTW_CRL>")),
			}, nil
		})},
	}
	evidence, err := client.Check(context.Background(), &x509.Certificate{SerialNumber: big.NewInt(12345)})
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Status != StatusGood || !evidence.ObservedAt.Equal(now.Add(-time.Minute)) {
		t.Fatalf("status evidence=%+v, want fresh Unrevoked observation", evidence)
	}
	if gotRequest == nil || gotRequest.URL.Query().Get("serial") != "12345" || gotRequest.URL.Query().Get("arap_nonce") == "" {
		t.Fatalf("status request query=%v, want serial and cache-busting nonce", gotRequest)
	}
	if gotRequest.Header.Get("Cache-Control") != "no-cache, no-store, max-age=0" {
		t.Fatalf("Cache-Control=%q", gotRequest.Header.Get("Cache-Control"))
	}
}

func TestARRLCertificateStatusFailsClosedForInvalidOrUnknownSerialStatuses(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name, status string
		want         Status
	}{
		{name: "revoked", status: "Revoked", want: StatusRevoked},
		{name: "superseded", status: "Superceded", want: StatusInvalid},
		{name: "expired", status: "Expired", want: StatusInvalid},
		{name: "bad serial", status: "Bad serial", want: StatusInvalid},
		{name: "unknown", status: "Pending", want: StatusUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := ARRLCertificateStatusClient{
				Now: func() time.Time { return now },
				HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					body := "<LoTW_CRL><Serial>7</Serial><Status>" + test.status + "</Status></LoTW_CRL>"
					return &http.Response{StatusCode: http.StatusOK,
						Header: http.Header{"Date": []string{now.Format(http.TimeFormat)}},
						Body:   io.NopCloser(strings.NewReader(body))}, nil
				})},
			}
			evidence, err := client.Check(context.Background(), &x509.Certificate{SerialNumber: big.NewInt(7)})
			if err != nil {
				t.Fatal(err)
			}
			if evidence.Status != test.want {
				t.Fatalf("status=%q want=%q", evidence.Status, test.want)
			}
		})
	}
}

func TestARRLCertificateStatusRejectsFutureDatedResponse(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	client := ARRLCertificateStatusClient{
		Now: func() time.Time { return now },
		HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			future := now.Add(10 * time.Minute)
			return &http.Response{StatusCode: http.StatusOK,
				Header: http.Header{"Date": []string{future.Format(http.TimeFormat)}},
				Body:   io.NopCloser(strings.NewReader("<LoTW_CRL><Serial>7</Serial><Status>Unrevoked</Status></LoTW_CRL>"))}, nil
		})},
	}
	if _, err := client.Check(context.Background(), &x509.Certificate{SerialNumber: big.NewInt(7)}); err == nil {
		t.Fatal("accepted future-dated status response")
	}
}
