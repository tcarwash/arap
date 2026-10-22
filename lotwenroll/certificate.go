package lotwenroll

import (
	"encoding/asn1"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/tcarwash/arap/protocol"
)

var tqslCallsignOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12348, 1, 1}

// CallsignFromCertificate reads the ARRL/TQSL AROcallsign subject attribute
// (OID 1.3.6.1.4.1.12348.1.1). It deliberately does not infer callsigns from
// CommonName or emailAddress.
func CallsignFromCertificate(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", errors.New("certificate is required")
	}
	var found string
	count := 0
	for _, attribute := range cert.Subject.Names {
		if !attribute.Type.Equal(tqslCallsignOID) {
			continue
		}
		value, ok := attribute.Value.(string)
		if !ok || value == "" {
			return "", errors.New("TQSL callsign attribute is not nonempty text")
		}
		found = value
		count++
	}
	if count != 1 {
		return "", fmt.Errorf("certificate must contain exactly one TQSL callsign attribute; found %d", count)
	}
	call, err := protocol.NormalizeCallsign(found)
	if err != nil || call != found {
		return "", errors.New("TQSL callsign attribute is not a normalized callsign")
	}
	return call, nil
}
