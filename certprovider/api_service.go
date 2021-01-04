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

type ApiServiceNewCertRequest struct {
	Csr      string `json:"csr"`      // stringified CSR data
	Hostname string `json:"hostname"` // hostname
	Validity int    `json:"validity"` // validity in days
}

type ApiServiceExistingCertRequest struct {
	Hostname string `json:"hostname"`
}

type ApiServiceCertResponse struct {
	Success     bool   `json:"success"`
	Error       string `json:"error"`
	Certificate string `json:"certificate"`
	OriginCa    string `json:"origin_ca"`
}

type ApiServiceCertificate struct {
	Certificate string `json:"certificate"`
	OriginCa    string `json:"origin_ca"`
}

const (
	createCertEndpoint   = "/certs/create"
	existingCertEndpoint = "/certs"
)

func GenerateCsr(keyBytes []byte, domain string) (csrBuffer bytes.Buffer, err error) {
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

func ApiServiceRequestCertificate(csr bytes.Buffer, domain string) (returnCert ApiServiceCertificate, err error) {
	externalApiUri, exists := os.LookupEnv("EXTERNAL_API_URI")
	if !exists {
		return returnCert, fmt.Errorf("env key EXTERNAL_API_URI not set, cannot request a certificate")
	}

	reqBody := ApiServiceNewCertRequest{
		Csr:      csr.String(),
		Hostname: domain,
		Validity: certValidityYear,
	}

	reqBodyBytes, _ := json.Marshal(reqBody)
	reqBodyBuffer := bytes.NewBuffer(reqBodyBytes)

	endpointUri := externalApiUri + createCertEndpoint

	req, err := http.NewRequest("POST", endpointUri, reqBodyBuffer)
	if err != nil {
		return returnCert, fmt.Errorf("unable to create http post request for external certificate uri: %[1]v", err)
	}

	httpClient := &http.Client{}

	resp, err := httpClient.Do(req)
	if err != nil {
		return returnCert, fmt.Errorf("error doing http POST request for external certificate: %[1]v", err)
	}

	defer resp.Body.Close()

	respBodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return returnCert, fmt.Errorf("error reading response body: %[1]v", err)
	}

	var apiResponse ApiServiceCertResponse

	if err := json.Unmarshal(respBodyBytes, &apiResponse); err != nil {
		return returnCert, fmt.Errorf("error unmarshalling response body: %[1]v", err)
	}

	if apiResponse.Success {
		cert := ApiServiceCertificate{
			Certificate: apiResponse.Certificate,
			OriginCa:    apiResponse.OriginCa,
		}
		return cert, nil
	}

	return returnCert, fmt.Errorf("error getting new certificate from external api: %[1]s", apiResponse.Error)
}

func ApiServiceGetCertificate(domain string) (returnCert ApiServiceCertificate, err error) {
	externalApiUri, exists := os.LookupEnv("EXTERNAL_API_URI")
	if !exists {
		return returnCert, fmt.Errorf("env key EXTERNAL_API_URI not set, cannot request a certificate")
	}

	reqBody := ApiServiceExistingCertRequest{
		Hostname: domain,
	}

	reqBodyBytes, _ := json.Marshal(reqBody)
	reqBodyBuffer := bytes.NewBuffer(reqBodyBytes)

	endpointUri := externalApiUri + existingCertEndpoint

	req, err := http.NewRequest("POST", endpointUri, reqBodyBuffer)
	if err != nil {
		return returnCert, fmt.Errorf("unable to create http post request for external certificate uri: %[1]v", err)
	}

	httpClient := &http.Client{}

	resp, err := httpClient.Do(req)
	if err != nil {
		return returnCert, fmt.Errorf("error doing http POST request for external certificate: %[1]v", err)
	}

	defer resp.Body.Close()

	respBodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return returnCert, fmt.Errorf("error reading response body: %[1]v", err)
	}

	var apiResponse ApiServiceCertResponse

	if err := json.Unmarshal(respBodyBytes, &apiResponse); err != nil {
		return returnCert, fmt.Errorf("error unmarshalling response body: %[1]v", err)
	}

	if apiResponse.Success {
		cert := ApiServiceCertificate{
			Certificate: apiResponse.Certificate,
			OriginCa:    apiResponse.OriginCa,
		}
		return cert, nil
	}

	return returnCert, fmt.Errorf("error getting certificate from external api: %[1]s", apiResponse.Error)
}
