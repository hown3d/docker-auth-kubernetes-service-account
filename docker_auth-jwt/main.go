package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"

	"github.com/coreos/go-oidc/v3/oidc"
)

var (
	cacertFile          = flag.String("ca-file", "", "A file containing PEM eoncoded certificates added to the rootCAS for requests to the openid issuer.")
	issuer              = flag.String("issuer", "", "OpenID issuer")
	issuerAuthTokenFile = flag.String("issuer-auth-token-file", "", "File containing a bearer token to authenticate against the issuer")
)

func main() {
	flag.Parse()
	log.SetOutput(os.Stderr)
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	args := flag.Args()
	if len(args) != 2 {
		return errors.New("args are not length 2")
	}
	token := args[1]
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	client, err := buildHTTPClient()
	if err != nil {
		return err
	}
	ctx = oidc.ClientContext(ctx, client)
	idtoken, err := validateToken(ctx, *issuer, token)
	if err != nil {
		return fmt.Errorf("validating token: %w", err)
	}

	l, err := buildLabels(idtoken)
	if err != nil {
		return fmt.Errorf("building labels: %w", err)
	}
	return json.NewEncoder(os.Stdout).Encode(l)
}

func buildLabels(tok *oidc.IDToken) (labels, error) {
	var kubeClaims kubernetesClaims
	if err := tok.Claims(&kubeClaims); err != nil {
		return labels{}, fmt.Errorf("getting kubernetes claims: %w", err)
	}
	return labels{
		Labels: map[string]any{
			"kubernetes": kubeClaims.Kubernetes,
			"sub":        tok.Subject,
			"aud":        tok.Audience,
		},
	}, nil
}

type labels struct {
	Labels map[string]any `json:"labels"`
}

// copied from https://github.com/kubernetes/kubernetes/blob/d4ac5efd9ddba7b93f6c304c0278723bcc9cd80e/pkg/serviceaccount/claims.go#L56C1-L63C2
type kubernetesClaims struct {
	Kubernetes kubernetes `json:"kubernetes.io"`
}

type kubernetes struct {
	Namespace string `json:"namespace,omitempty"`
	Svcacct   ref    `json:"serviceaccount,omitempty"`
	Pod       *ref   `json:"pod,omitempty"`
	Secret    *ref   `json:"secret,omitempty"`
	Node      *ref   `json:"node,omitempty"`
}

type ref struct {
	Name string `json:"name,omitempty"`
	UID  string `json:"uid,omitempty"`
}

func validateToken(ctx context.Context, issuer, token string) (*oidc.IDToken, error) {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	config := &oidc.Config{
		SkipClientIDCheck: true,
	}

	verifier := provider.VerifierContext(ctx, config)
	return verifier.Verify(ctx, token)
}

func buildHTTPClient() (*http.Client, error) {
	// Load client cert
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	if *cacertFile != "" {
		pemCerts, err := os.ReadFile(*cacertFile)
		if err != nil {
			return nil, err
		}
		pool.AppendCertsFromPEM(pemCerts)
	}
	// Setup HTTPS client
	tlsConfig := &tls.Config{
		RootCAs: pool,
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}
	if *issuerAuthTokenFile != "" {
		tokenRT, err := newBearerTokenRoundTripperFromFile(*issuerAuthTokenFile, transport)
		if err != nil {
			return nil, err
		}
		client.Transport = tokenRT
	}
	return client, nil
}

type bearerTokenRoundTripper struct {
	next  http.RoundTripper
	token []byte
}

func newBearerTokenRoundTripperFromFile(file string, next http.RoundTripper) (http.RoundTripper, error) {
	tok, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return &bearerTokenRoundTripper{
		next:  next,
		token: tok,
	}, nil
}

func (b *bearerTokenRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("Authorization", "Bearer "+string(b.token))
	return b.next.RoundTrip(req)
}
