package certprovider

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

const (
	cloudflareBaseUrl            string = "https://api.cloudflare.com/client/v4"
	cloudflareCreateCertEndpoint        = cloudflareBaseUrl + "/certificates"
)

const (
	// cloudflare cert validity lengths
	certValidityYear int = 365
	// cloudflare cert request types
	originRsa = "origin-rsa"
)

var (
	cloudflareOriginCaBundle = `-----BEGIN CERTIFICATE-----
MIIEADCCAuigAwIBAgIID+rOSdTGfGcwDQYJKoZIhvcNAQELBQAwgYsxCzAJBgNV
BAYTAlVTMRkwFwYDVQQKExBDbG91ZEZsYXJlLCBJbmMuMTQwMgYDVQQLEytDbG91
ZEZsYXJlIE9yaWdpbiBTU0wgQ2VydGlmaWNhdGUgQXV0aG9yaXR5MRYwFAYDVQQH
Ew1TYW4gRnJhbmNpc2NvMRMwEQYDVQQIEwpDYWxpZm9ybmlhMB4XDTE5MDgyMzIx
MDgwMFoXDTI5MDgxNTE3MDAwMFowgYsxCzAJBgNVBAYTAlVTMRkwFwYDVQQKExBD
bG91ZEZsYXJlLCBJbmMuMTQwMgYDVQQLEytDbG91ZEZsYXJlIE9yaWdpbiBTU0wg
Q2VydGlmaWNhdGUgQXV0aG9yaXR5MRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMRMw
EQYDVQQIEwpDYWxpZm9ybmlhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEAwEiVZ/UoQpHmFsHvk5isBxRehukP8DG9JhFev3WZtG76WoTthvLJFRKFCHXm
V6Z5/66Z4S09mgsUuFwvJzMnE6Ej6yIsYNCb9r9QORa8BdhrkNn6kdTly3mdnykb
OomnwbUfLlExVgNdlP0XoRoeMwbQ4598foiHblO2B/LKuNfJzAMfS7oZe34b+vLB
yrP/1bgCSLdc1AxQc1AC0EsQQhgcyTJNgnG4va1c7ogPlwKyhbDyZ4e59N5lbYPJ
SmXI/cAe3jXj1FBLJZkwnoDKe0v13xeF+nF32smSH0qB7aJX2tBMW4TWtFPmzs5I
lwrFSySWAdwYdgxw180yKU0dvwIDAQABo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYD
VR0TAQH/BAgwBgEB/wIBAjAdBgNVHQ4EFgQUJOhTV118NECHqeuU27rhFnj8KaQw
HwYDVR0jBBgwFoAUJOhTV118NECHqeuU27rhFnj8KaQwDQYJKoZIhvcNAQELBQAD
ggEBAHwOf9Ur1l0Ar5vFE6PNrZWrDfQIMyEfdgSKofCdTckbqXNTiXdgbHs+TWoQ
wAB0pfJDAHJDXOTCWRyTeXOseeOi5Btj5CnEuw3P0oXqdqevM1/+uWp0CM35zgZ8
VD4aITxity0djzE6Qnx3Syzz+ZkoBgTnNum7d9A66/V636x4vTeqbZFBr9erJzgz
hhurjcoacvRNhnjtDRM0dPeiCJ50CP3wEYuvUzDHUaowOsnLCjQIkWbR7Ni6KEIk
MOz2U0OBSif3FTkhCgZWQKOOLo1P42jHC3ssUZAtVNXrCk3fw9/E15k8NPkBazZ6
0iykLhH1trywrKRMVw67F44IE8Y=
-----END CERTIFICATE-----`
)

type CloudflareAuth struct {
	OriginCaKey string
}

type CloudflareError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type CloudflareExternalCert struct {
	CertId         string   `json:"id"`
	Certificate    string   `json:"certificate"`
	Hostnames      []string `json:"hostnames"`
	Expires        string   `json:"expires_on"`
	OriginCaBundle string   `json:"-"`
}

type CloudflareCertCreateResponse struct {
	Sucess bool                   `json:"success"`
	Errors []CloudflareError      `json:"errors"`
	Result CloudflareExternalCert `json:"result"`
}

type CloudflareCertCreateRequest struct {
	Hostnames         []string `json:"hostnames"`
	RequestedValidity int      `json:"requested_validity"`
	RequestType       string   `json:"request_type"`
	Csr               string   `json:"csr"`
}

func getCloudflareAuth() (*CloudflareAuth, error) {
	var authInfo *CloudflareAuth

	authKey, keyFound := os.LookupEnv("CLOUDFLARE_ORIGIN_CA_KEY")
	if !keyFound {
		return nil, fmt.Errorf("CLOUDFLARE_ORIGIN_CA_KEY environment variable not set")
	}

	if keyFound && authKey == "" {
		return nil, fmt.Errorf("CLOUDFLARE_ORIGIN_CA_KEY environment variable set to empty string")
	}

	authInfo = &CloudflareAuth{
		OriginCaKey: authKey,
	}

	return authInfo, nil
}

func CloudflareGenerateCsr(keyBytes []byte, domain string) (csrBuffer bytes.Buffer, err error) {
	block, _ := pem.Decode(keyBytes)
	x509Encoded := block.Bytes
	privKey, err := x509.ParsePKCS1PrivateKey(x509Encoded)
	if err != nil {
		return csrBuffer, err
	}
	subj := pkix.Name{
		CommonName: domain,
	}
	rawSubj := subj.ToRDNSequence()
	asn1Subj, _ := asn1.Marshal(rawSubj)
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privKey)
	if err != nil {
		return csrBuffer, err
	}
	pem.Encode(&csrBuffer, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	return csrBuffer, nil
}

func CloudflareRequestCert(csr bytes.Buffer, domain string) (certificate CloudflareExternalCert, err error) {
	authInfo, getAuthErr := getCloudflareAuth()

	if getAuthErr != nil {
		return certificate, getAuthErr
	}

	requestBody := CloudflareCertCreateRequest{
		Hostnames:         []string{domain},
		RequestedValidity: certValidityYear,
		RequestType:       originRsa,
		Csr:               csr.String(),
	}

	marshaledBody, err := json.Marshal(requestBody)
	if err != nil {
		return certificate, fmt.Errorf("error marshalling cert request body: %[1]v", err)
	}

	client := &http.Client{}
	req, err := http.NewRequest("POST", cloudflareCreateCertEndpoint, bytes.NewBuffer(marshaledBody))

	if err != nil {
		return certificate, err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-Auth-User-Service-Key", authInfo.OriginCaKey)

	resp, err := client.Do(req)
	if err != nil {
		return certificate, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		return certificate, fmt.Errorf("received bad response from Cloudflare: %v - %v", resp.StatusCode, string(body))
	}

	var certResponse CloudflareCertCreateResponse

	body, _ := ioutil.ReadAll(resp.Body)
	err = json.Unmarshal(body, &certResponse)

	if err != nil {
		return certificate, fmt.Errorf("Unknown error occured: %v", string(body))
	}

	certificate = certResponse.Result

	certificate.OriginCaBundle = cloudflareOriginCaBundle

	return certificate, nil
}
