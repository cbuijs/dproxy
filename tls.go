/*
File: tls.go
Description: Helper functions for loading TLS certificates or generating self-signed certificates.
*/

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

func getTLSConfig(certPath, keyPath, listenIP string) (*tls.Config, error) {
	var cert tls.Certificate
	var err error

	if certPath != "" && keyPath != "" {
		cert, err = tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load certificates: %w", err)
		}
	} else {
		log.Println("Generating self-signed certificate...")
		cert, err = generateSelfSignedCert(listenIP)
		if err != nil {
			return nil, fmt.Errorf("failed to generate certificate: %w", err)
		}
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3", "doq", "h2", "http/1.1"},
		ClientAuth:   tls.NoClientCert,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func generateSelfSignedCert(listenIP string) (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	if ip := net.ParseIP(listenIP); ip != nil {
		ips = append(ips, ip)
	}

	hostnames := []string{"localhost"}
	if h, err := os.Hostname(); err == nil {
		hostnames = append(hostnames, h)
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"DNS Proxy"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              hostnames,
		IPAddresses:           ips,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return tls.X509KeyPair(certPEM, keyPEM)
}

