package cert_test

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/lightningnetwork/lnd/cert"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnencrypt"
	"github.com/lightningnetwork/lnd/lntest/mock"

	"github.com/stretchr/testify/require"
)

var (
	extraIPs     = []string{"1.1.1.1", "123.123.123.1", "199.189.12.12"}
	extraDomains = []string{"home", "and", "away"}
	privKeyBytes = [32]byte{
		0xb7, 0x94, 0x38, 0x5f, 0x2d, 0x1e, 0xf7, 0xab,
		0x4d, 0x92, 0x73, 0xd1, 0x90, 0x63, 0x81, 0xb4,
		0x4f, 0x2f, 0x6f, 0x25, 0x88, 0xa3, 0xef, 0xb9,
		0x6a, 0x49, 0x18, 0x83, 0x31, 0x98, 0x47, 0x53,
	}

	privKey, _ = btcec.PrivKeyFromBytes(btcec.S256(),
		privKeyBytes[:])
)

type mockKeyRing struct {
	fail bool
}

func (m *mockKeyRing) DeriveNextKey(keyFam keychain.KeyFamily) (keychain.KeyDescriptor, error) {
	return keychain.KeyDescriptor{}, nil
}
func (m *mockKeyRing) DeriveKey(keyLoc keychain.KeyLocator) (keychain.KeyDescriptor, error) {
	if m.fail {
		return keychain.KeyDescriptor{}, fmt.Errorf("fail")
	}

	_, pub := btcec.PrivKeyFromBytes(btcec.S256(), testWalletPrivKey)
	return keychain.KeyDescriptor{
		PubKey: pub,
	}, nil
}

// TestIsOutdatedCert checks that we'll consider the TLS certificate outdated
// if the ip addresses or dns names don't match.
func TestIsOutdatedCert(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "certtest")
	if err != nil {
		t.Fatal(err)
	}

	keyRing := &mock.SecretKeyRing{}
	certPath := tempDir + "/tls.cert"
	keyPath := tempDir + "/tls.key"
	keyRing := &mockKeyRing{}

	// Generate TLS files with two extra IPs and domains.
	_, _, err = cert.GenCertPair(
		"lnd autogenerated cert", certPath, keyPath, extraIPs[:2],
		extraDomains[:2], cert.DefaultAutogenValidity, false,
		false, keyRing, "ec",
	)
	if err != nil {
		t.Fatal(err)
	}

	// We'll attempt to check up-to-date status for all variants of 1-3
	// number of IPs and domains.
	for numIPs := 1; numIPs <= len(extraIPs); numIPs++ {
		for numDomains := 1; numDomains <= len(extraDomains); numDomains++ {
			certBytes, err := ioutil.ReadFile(certPath)
			if err != nil {
				t.Fatal(err)
			}
			keyBytes, err := ioutil.ReadFile(keyPath)
			if err != nil {
				t.Fatal(err)
			}
			_, parsedCert, err := cert.LoadCert(
				certBytes, keyBytes,
			)
			if err != nil {
				t.Fatal(err)
			}

			// Using the test case's number of IPs and domains, get
			// the outdated status of the certificate we created
			// above.
			outdated, err := cert.IsOutdated(
				parsedCert, extraIPs[:numIPs],
				extraDomains[:numDomains], false,
			)
			if err != nil {
				t.Fatal(err)
			}

			// We expect it to be considered outdated if the IPs or
			// domains don't match exactly what we created.
			expected := numIPs != 2 || numDomains != 2
			if outdated != expected {
				t.Fatalf("expected certificate to be "+
					"outdated=%v, got=%v", expected,
					outdated)
			}
		}
	}
}

// TestIsOutdatedPermutation tests that the order of listed IPs or DNS names,
// nor dulicates in the lists, matter for whether we consider the certificate
// outdated.
func TestIsOutdatedPermutation(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "certtest")
	if err != nil {
		t.Fatal(err)
	}

	keyRing := &mock.SecretKeyRing{}
	certPath := tempDir + "/tls.cert"
	keyPath := tempDir + "/tls.key"
	keyRing := &mockKeyRing{}

	// Generate TLS files from the IPs and domains.
	_, _, err = cert.GenCertPair(
		"lnd autogenerated cert", certPath, keyPath, extraIPs[:],
		extraDomains[:], cert.DefaultAutogenValidity, false,
		false, keyRing, "ec",
	)
	if err != nil {
		t.Fatal(err)
	}

	certBytes, err := ioutil.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	_, parsedCert, err := cert.LoadCert(certBytes, keyBytes)
	if err != nil {
		t.Fatal(err)
	}

	// If we have duplicate IPs or DNS names listed, that shouldn't matter.
	dupIPs := make([]string, len(extraIPs)*2)
	for i := range dupIPs {
		dupIPs[i] = extraIPs[i/2]
	}

	dupDNS := make([]string, len(extraDomains)*2)
	for i := range dupDNS {
		dupDNS[i] = extraDomains[i/2]
	}

	outdated, err := cert.IsOutdated(parsedCert, dupIPs, dupDNS, false)
	if err != nil {
		t.Fatal(err)
	}

	if outdated {
		t.Fatalf("did not expect duplicate IPs or DNS names be " +
			"considered outdated")
	}

	// Similarly, the order of the lists shouldn't matter.
	revIPs := make([]string, len(extraIPs))
	for i := range revIPs {
		revIPs[i] = extraIPs[len(extraIPs)-1-i]
	}

	revDNS := make([]string, len(extraDomains))
	for i := range revDNS {
		revDNS[i] = extraDomains[len(extraDomains)-1-i]
	}

	outdated, err = cert.IsOutdated(parsedCert, revIPs, revDNS, false)
	if err != nil {
		t.Fatal(err)
	}

	if outdated {
		t.Fatalf("did not expect reversed IPs or DNS names be " +
			"considered outdated")
	}
}

// TestTLSDisableAutofill checks that setting the --tlsdisableautofill flag
// does not add interface ip addresses or hostnames to the cert.
func TestTLSDisableAutofill(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "certtest")
	if err != nil {
		t.Fatal(err)
	}

	keyRing := &mock.SecretKeyRing{}
	certPath := tempDir + "/tls.cert"
	keyPath := tempDir + "/tls.key"

	// Generate TLS files with two extra IPs and domains and no interface IPs.
	_, _, err = cert.GenCertPair(
		"lnd autogenerated cert", certPath, keyPath, extraIPs[:2],
		extraDomains[:2], true, cert.DefaultAutogenValidity,
		false, keyRing, "ec",
	)
	require.NoError(
		t, err,
		"unable to generate tls certificate pair",
	)

	// Read certs from disk
	certBytes, err := ioutil.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	// Load the certificate
	_, parsedCert, err := cert.LoadCert(
		certBytes, keyBytes,
	)
	require.NoError(
		t, err,
		"unable to load tls certificate pair",
	)

	// Check if the TLS cert is outdated while still preventing
	// interface IPs from being used. Should not be outdated
	shouldNotBeOutdated, err := cert.IsOutdated(
		parsedCert, extraIPs[:2],
		extraDomains[:2], true,
	)
	require.NoError(t, err)

	require.Equal(
		t, false, shouldNotBeOutdated,
		"TLS Certificate was marked as outdated when it should not be",
	)

	// Check if the TLS cert is outdated while allowing for
	// interface IPs to be used. Should report as outdated.
	shouldBeOutdated, err := cert.IsOutdated(
		parsedCert, extraIPs[:2],
		extraDomains[:2], false,
	)
	require.NoError(t, err)

	require.Equal(
		t, true, shouldBeOutdated,
		"TLS Certificate was not marked as outdated when it should be",
	)
}

// TestTlsConfig tests to ensure we can generate a TLS Config from
// a tls cert and tls key.
func TestTlsConfig(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "certtest")
	if err != nil {
		t.Fatal(err)
	}

	certPath := tempDir + "/tls.cert"
	keyPath := tempDir + "/tls.key"
	keyRing := &mock.SecretKeyRing{}

	// Generate TLS files with an extra IP and domain.
	_, _, err = cert.GenCertPair(
		"lnd autogenerated cert", certPath, keyPath, []string{extraIPs[0]},
		[]string{extraDomains[0]}, false, cert.DefaultAutogenValidity,
		false, keyRing, "ec",
	)
	if err != nil {
		t.Fatal(err)
	}

	// Read certs from disk
	certBytes, err := ioutil.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	// Load the certificate
	certData, parsedCert, err := cert.LoadCert(
		certBytes, keyBytes,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Check to make sure the IP and domain are in the cert
	var foundDomain bool
	var foundIp bool
	for _, domain := range parsedCert.DNSNames {
		if domain == extraDomains[0] {
			foundDomain = true
			break
		}
	}
	for _, ip := range parsedCert.IPAddresses {
		if ip.String() == extraIPs[0] {
			foundIp = true
			break
		}
	}
	if !foundDomain || !foundIp {
		t.Fatal(fmt.Errorf("Did not find required information inside "+
			"of TLS Certificate. foundDomain: %v, foundIp: %v",
			foundDomain, foundIp))
	}

	// Create TLS Config
	tlsCfg := cert.TLSConfFromCert(certData)

	if len(tlsCfg.Certificates) != 1 {
		t.Fatal(fmt.Errorf("Found incorrect number of TLS certificates "+
			"in TLS Config: %v", len(tlsCfg.Certificates)))
	}
}

// TestEncryptedTlsConfig tests to ensure we can generate a TLS Config from
// a tls cert and tls key with key encryption is enabled.
func TestEncryptedTlsConfig(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "certtest")
	if err != nil {
		t.Fatal(err)
	}

	certPath := tempDir + "/tls.cert"
	keyPath := tempDir + "/tls.key"
	keyRing := &mock.SecretKeyRing{
		RootKey: privKey,
	}

	// Generate TLS files with an extra IP and domain.
	_, _, err = cert.GenCertPair(
		"lnd autogenerated cert", certPath, keyPath, []string{extraIPs[0]},
		[]string{extraDomains[0]}, false, cert.DefaultAutogenValidity,
		true, keyRing, "ec",
	)
	if err != nil {
		t.Fatal(err)
	}

	// Read certs from disk
	certBytes, err := ioutil.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	// Check to make sure the file was written encrypted
	privateKeyPrefix := []byte("-----BEGIN EC PRIVATE KEY-----")
	if bytes.HasPrefix(keyBytes, privateKeyPrefix) {
		t.Fatal(fmt.Errorf("TLS Certificate is written in plaintext when it " +
			"should be written encrypted."))
	}

	// Try to decrypt the key
	reader := bytes.NewReader(keyBytes)
	keyBytes, err = lnencrypt.DecryptPayloadFromReader(reader, keyRing)
	if err != nil {
		t.Fatal(err)
	}

	// Load the certificate
	certData, parsedCert, err := cert.LoadCert(
		certBytes, keyBytes,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Check to make sure the IP and domain are in the cert
	var foundDomain bool
	var foundIp bool
	for _, domain := range parsedCert.DNSNames {
		if domain == extraDomains[0] {
			foundDomain = true
			break
		}
	}
	for _, ip := range parsedCert.IPAddresses {
		if ip.String() == extraIPs[0] {
			foundIp = true
			break
		}
	}
	if !foundDomain || !foundIp {
		t.Fatal(fmt.Errorf("Did not find required information inside "+
			"of TLS Certificate. foundDomain: %v, foundIp: %v",
			foundDomain, foundIp))
	}

	// Create TLS Config
	tlsCfg := cert.TLSConfFromCert(certData)

	if len(tlsCfg.Certificates) != 1 {
		t.Fatal(fmt.Errorf("Found incorrect number of TLS certificates "+
			"in TLS Config: %v", len(tlsCfg.Certificates)))
	}
}
