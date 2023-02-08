package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	jwk "github.com/lestrrat-go/jwx/jwk"
	"golang.org/x/net/http2"
)

type OIDCConfigurationResponse struct {
	Issuer                           string   `json:"issuer"`
	JWKsURI                          string   `json:"jwks_uri"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
}

type key struct {
	SigningMethod jwt.SigningMethod
	PrivateKey    interface{}
	PublicKey     interface{}
	HMACKey       []byte
}

var (
	jwkBytes []byte
	keys     = make(map[string]*key)
)

const (
	hmacKeyID = "hmacKeyID_1"
	hmacKey   = "e2c6c78e079ca23ac0d37fbbc0ae36a2d5c0f0c7186e70fbd6a964e60444a0de"

	rsaKeyID  = "rsaKeyID_1"
	rsaPubKey = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqqrpBHkLN4vT6g279KYT
nnbKWHIEa+fK04wlamlrALQpV6QGfIrPwSgU/ElRFpsPJYWxCvEtYS01lBC70IeA
hObR5DY9Z+jTvhk1tA+VrxyEhAHLuCuCsAPLow4ZSJ+aB0vZuUtaV9+qO+0gyJEG
9y/5FKT51Tbr0INtjDASH43seoQtsPDG2tnKEj9r7jOLUNehj5j4Dgv+sJMGe3Ey
Klw7p6vsIhsU23v0VrTxdHGuelzplxCUQJoPRSxgepYyVmfrB12XJ5uJtLhYwuTb
Fb3BIUyswBtxtGcigvk/ftkuSQjubiXe8UtltBI7INfs7vmAVuQr7YN8Alni4Z3B
eQIDAQAB
-----END PUBLIC KEY-----`

	rsaPrivKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAqqrpBHkLN4vT6g279KYTnnbKWHIEa+fK04wlamlrALQpV6QG
fIrPwSgU/ElRFpsPJYWxCvEtYS01lBC70IeAhObR5DY9Z+jTvhk1tA+VrxyEhAHL
uCuCsAPLow4ZSJ+aB0vZuUtaV9+qO+0gyJEG9y/5FKT51Tbr0INtjDASH43seoQt
sPDG2tnKEj9r7jOLUNehj5j4Dgv+sJMGe3EyKlw7p6vsIhsU23v0VrTxdHGuelzp
lxCUQJoPRSxgepYyVmfrB12XJ5uJtLhYwuTbFb3BIUyswBtxtGcigvk/ftkuSQju
biXe8UtltBI7INfs7vmAVuQr7YN8Alni4Z3BeQIDAQABAoIBAG2SZSA2BnmXEGsI
fk/IAHiQk8DNEwGkQ5gmNi9nlwdQo+pcqL108YV1kmOXPrRgwQy6FLyNszDcsbVq
OOrc1Cp/duop2KrJ1IgL72q3RsaybHHEJWMMrE8NYMRC3QC/V0iv7g0Ez+/y7Xyj
9ZRPaEVzS1txv+Sf6i5o8wA6LKiMjMDYLFKxfzhjdakghshSNobuP3Vrw+KthHtr
96bTESBD/nvBJolZs8wiFa/DcXGrgoh2htZhuxlZCTsEMWT8TCETsZohR5NUZ0wL
yD2+KXwIydp2NIkunfKT7EISaZ1fNpPPjCMskpEL675yQklluo+D6qj9W1HDRkYk
zo7PEMECgYEA4cQddq3H6CftnLrg2QcDT3jOhxOnHCT31oQBHZbUNLpQ38fHp6BX
YnQ0bH32eFHYLw9TEdYhwebp2rLruPjy25r8buRK+YXkhNL404ooo9dC1XhX7oVz
6aMVq6yHSlNsNrbTXH1CChP/9hgPR5osfeUP8u2Utp7exQg9qE/zmr0CgYEAwYXe
J0LWmXknnqZ/8Ld7ZKZiL7U9E5QV8Epz9OYCHDQevRoh03iWhUWJeP1ps0sp1rb8
zW3kUs5iCzj54UylcwcPYLK9hgVsYtgLFbNas9XwdNPQH0OdlUBAtAIvyZudIVCb
vJyCcuw/KlUIbDDI23n3/sqiM60H0H9u+FOFy20CgYAV7vap1AJK5K4p/uHfU9YX
f3YZG2itzE2jspllJYUiRkObKg6Uk3hJ4V5CeA5c7B6jm8qHPhVzgBqSG7XY956o
hSsnHtjF2yMzYEe6TX7bRAuDL7jjPGXhee2eCxntt6MYwbRRFP44em7wmq/JVgoi
hQGCqWA8Sbz8yWssEfBpxQKBgGgc1wmUQdPLhG8r8ETW0YGyqbw06yjvUGY4B+5H
F/eIaskdl/knNQN6B52Z6BXXaCjlxVfXuTB7a+/RtU1qaNBbigBh6OiDXm5HAJ+q
IDAD9xtDIQLQ46R6LtUpIAB8wao8raxpHx0o0Eq7+I4MKOM62RqwdVcLzdpz1IWw
mZh5AoGAeVkFstY9lmcdEi2rHUAsR2WMOnzYP4WS+/dYIMsXVryNVa/obbjwz94N
rWWOI9aKV6wvK+CIzHsI7hsFw7aF0S2x1gg4RvtxDgHCMbgI3t8tdCtph7cmDKNp
W1NUvPpHH7t1YenNODRZSEo/ETn69WX6i0kV4BNI64+cU60pUwQ=
-----END RSA PRIVATE KEY-----`

	// EC
	// openssl ecparam -name prime256v1 -genkey -noout -out ec_private-key.pem
	// openssl ec -in ec_private-key.pem -pubout -out ec_public-key.pem
	ecKeyID  = "ecKeyID_1"
	ecPubKey = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQjKEvzgFPN7bIq6FpBKPcaBS1dCY
aPwTO9YR4vZwCTrJqK2xDRJkWzWS9BuMbHJeE8Nva1bZK7/pkkIj5IKSKg==
-----END PUBLIC KEY-----`
	ecPrivKey = `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIF343AResU+p7wF/p7kPBgWBgb00a70B86Mm5fboWxvMoAoGCCqGSM49
AwEHoUQDQgAEQjKEvzgFPN7bIq6FpBKPcaBS1dCYaPwTO9YR4vZwCTrJqK2xDRJk
WzWS9BuMbHJeE8Nva1bZK7/pkkIj5IKSKg==
-----END EC PRIVATE KEY-----`
)

func createJWK(keyID string, k *key) (jwkBytes []byte, err error) {
	var jkey jwk.Key
	if k.SigningMethod == jwt.SigningMethodHS256 {
		jkey, err = jwk.New(k.HMACKey)

	} else {
		jkey, err = jwk.New(k.PublicKey)
	}
	if err != nil {
		return nil, err
	}
	jkey.Set(jwk.KeyIDKey, keyID)
	jkey.Set(jwk.KeyUsageKey, "sig")
	jkey.Set(jwk.AlgorithmKey, k.SigningMethod)

	buf, err := json.MarshalIndent(jkey, "", "  ")
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func frontHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("/ called")
	fmt.Fprint(w, "ok")
}

func certsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-Type", "application/json")
	fmt.Fprint(w, string(jwkBytes))
}

func tokenHandler(w http.ResponseWriter, r *http.Request) {

	keyID := r.URL.Query().Get("kid")

	// find out if this is a valid key
	for k := range keys {
		if k == keyID {
			break
		}
	}
	if keyID == "" {
		log.Printf("Keyid nil, using default RS256 key %s", rsaKeyID)
		keyID = rsaKeyID
	}

	var claims jwt.MapClaims

	b, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error parsing request body %v", err)
		http.Error(w, fmt.Sprintf("Error parsing request body %v", err), http.StatusInternalServerError)
		return
	}

	if err := json.Unmarshal(b, &claims); err != nil {
		http.Error(w, fmt.Sprintf("couldn't parse claims JSON: %v", err), http.StatusInternalServerError)
		return
	}

	token := jwt.NewWithClaims(keys[keyID].SigningMethod, claims)
	token.Header["kid"] = keyID
	var out string
	if keys[keyID].SigningMethod == jwt.SigningMethodHS256 {
		out, err = token.SignedString(keys[keyID].HMACKey)
	} else {
		out, err = token.SignedString(keys[keyID].PrivateKey)
	}
	if err != nil {
		log.Printf("Error creating JWT %v", err)
		http.Error(w, fmt.Sprintf("Error creating JWT %v", err), http.StatusInternalServerError)
		return
	}

	// v, err := jwt.Parse(string(out), func(token *jwt.Token) (interface{}, error) {
	// 	return pubKey, nil
	// })
	// if v.Valid {
	// 	log.Printf("Error verifying issued JWT %v", err)
	// 	http.Error(w, fmt.Sprintf("Error verifying issued JWT %v", err), http.StatusInternalServerError)
	// }

	w.Header().Set("content-Type", "text/plain")
	fmt.Fprint(w, out)
}

// ref from firebase: https://securetoken.google.com/mineral-minutia-820/.well-known/openid-configuration
// https://openid.net/specs/openid-connect-discovery-1_0.html

func wellKnownHandler(w http.ResponseWriter, r *http.Request) {
	issuer := fmt.Sprintf("https://%s", r.Host)
	jwkSetURL := fmt.Sprintf("https://%s/certs", r.Host)
	resp := &OIDCConfigurationResponse{
		Issuer:                           issuer,
		JWKsURI:                          jwkSetURL,
		IDTokenSigningAlgValuesSupported: []string{jwt.SigningMethodRS256.Alg(), jwt.SigningMethodES256.Alg(), jwt.SigningMethodHS256.Alg()},
		SubjectTypesSupported:            []string{"public"},
		ResponseTypesSupported:           []string{"id_token"},
	}
	w.Header().Set("content-type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func main() {

	// read in all the keys

	// add rsa
	block, _ := pem.Decode([]byte(rsaPrivKey))
	if block == nil {
		log.Fatalf("no PEM block found in " + rsaPrivKey)
	}
	privKeyRSA, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("Unable to parse private key %v", err)
	}
	keys[rsaKeyID] = &key{
		SigningMethod: jwt.SigningMethodRS256,
		PrivateKey:    privKeyRSA,
		PublicKey:     privKeyRSA.PublicKey,
	}

	// add ec
	block, _ = pem.Decode([]byte(ecPrivKey))
	if block == nil {
		log.Fatalf("no PEM block found in " + rsaPrivKey)
	}
	privKeyEC, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("Unable to parse private key %v", err)
	}
	keys[ecKeyID] = &key{
		SigningMethod: jwt.SigningMethodES256,
		PrivateKey:    privKeyEC,
		PublicKey:     privKeyEC.PublicKey,
	}

	// add hmac
	keys[hmacKeyID] = &key{
		SigningMethod: jwt.SigningMethodHS256,
		HMACKey:       []byte(hmacKey),
	}

	// populate the registry

	rsjwkBytes, err := createJWK(rsaKeyID, keys[rsaKeyID])
	if err != nil {
		log.Fatalf("Unable to create RS JWK %v", err)
	}
	log.Printf("Loaded JWK RS256 \n%s\n", string(rsjwkBytes))

	ecjwkBytes, err := createJWK(ecKeyID, keys[ecKeyID])
	if err != nil {
		log.Fatalf("Unable to create EC JWK %v", err)
	}
	log.Printf("Loaded  JWK ES256 \n%s\n", string(ecjwkBytes))

	hsjwkBytes, err := createJWK(hmacKeyID, keys[hmacKeyID])
	if err != nil {
		log.Fatalf("Unable to create HS JWK %v", err)
	}
	log.Printf("Loaded JWK HS256 \n%s\n", string(hsjwkBytes))

	jwkBytes = []byte(fmt.Sprintf(`{"keys": [ %s, %s, %s ] }`, string(rsjwkBytes), string(ecjwkBytes), string(hsjwkBytes)))

	r := mux.NewRouter()
	r.StrictSlash(true)
	r.Handle("/", http.HandlerFunc(frontHandler)).Methods(http.MethodGet)
	r.Handle("/certs", http.HandlerFunc(certsHandler)).Methods(http.MethodGet)
	r.Handle("/.well-known/openid-configuration", http.HandlerFunc(wellKnownHandler)).Methods(http.MethodGet)
	r.Handle("/token", http.HandlerFunc(tokenHandler)).Methods(http.MethodPost)
	http.Handle("/", r)

	server := &http.Server{
		Addr: ":8080",
	}
	http2.ConfigureServer(server, &http2.Server{})
	log.Println("Starting Server..")
	err = server.ListenAndServe()
	log.Fatalf("Unable to start Server %v", err)
}
