package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"github.com/openshift/installer/pkg/asset/tls"
	"time"
)

const (
	keySize = 2048

	// ValidityOneDay sets the validity of a cert to 24 hours.
	ValidityOneDay = time.Hour * 24

	// ValidityOneYear sets the validity of a cert to 1 year.
	ValidityOneYear = ValidityOneDay * 365

	// ValidityTenYears sets the validity of a cert to 10 years.
	ValidityTenYears = ValidityOneYear * 10
)

func main() {
	for _, cfg := range []tls.CertCfg{
		{
			Subject:   pkix.Name{CommonName: "kube-apiserver-lb-signer", OrganizationalUnit: []string{"openshift"}},
			KeyUsages: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			Validity:  ValidityTenYears,
			IsCA:      true,
		},
		{
			Subject:   pkix.Name{CommonName: "kube-apiserver-localhost-signer", OrganizationalUnit: []string{"openshift"}},
			KeyUsages: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			Validity:  ValidityTenYears,
			IsCA:      true,
		},
		{
			Subject:   pkix.Name{CommonName: "kube-apiserver-service-network-signer", OrganizationalUnit: []string{"openshift"}},
			KeyUsages: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			Validity:  ValidityTenYears,
			IsCA:      true,
		},
	} {
		key, cert, err := tls.GenerateSelfSignedCertificate(&cfg)
		if err != nil {
			panic(err)
		}

		keyRaw := tls.PrivateKeyToPem(key)
		certRaw := tls.CertToPem(cert)

		fmt.Println(string(keyRaw))

		fmt.Println(string(certRaw))
	}

}
