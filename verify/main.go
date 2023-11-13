package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat/go-jwx/jwk"
)

const (
	hmacKeyID = "hmacKeyID_1"
	hmacKey   = "e2c6c78e079ca23ac0d37fbbc0ae36a2d5c0f0c7186e70fbd6a964e60444a0de"
)

var (
	jwtSet   *jwk.Set
	jwksURL  = flag.String("jwkUrl", "https://idp-on-cloud-run-3kdezruzua-uc.a.run.app/certs", "JWK Endpoint")
	jwtToken = flag.String("jwtToken", "", "JWT Token")
)

func main() {

	flag.Parse()

	if *jwtToken == "" {
		fmt.Println("Must specify --jwtToken")
		os.Exit(1)
	}

	ctx := context.Background()

	var err error
	jwtSet, err = jwk.FetchHTTP(*jwksURL)
	if err != nil {
		log.Fatal("Unable to load JWK Set: ", err)
	}
	log.Printf("Keys in JWT Set : [%d]\n", len(jwtSet.Keys))
	doc, err := verifyIDToken(ctx, *jwtToken)
	if err != nil {
		log.Fatalf("Unable to verify IDTOKEN: %v", err)
	}
	log.Printf("     OIDC doc has Audience [%s]   Issuer [%s] and SubjectEmail [%s]", doc.Audience, doc.RegisteredClaims.Issuer, doc.Email)
	// End verification

}

type customJWT struct {
	jwt.RegisteredClaims
	MyGroups      []string `json:"mygroups,omitempty"`
	Email         string   `json:"email,omitempty"`
	EmailVerified bool     `json:"email_verified,omitempty"`
	IsAdmin       string   `json:"is_admin,omitempty"`
}

func getKey(token *jwt.Token) (interface{}, error) {
	keyID, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("expecting JWT header to have string kid")
	}
	if token.Method == jwt.SigningMethodHS256 {
		if keyID == "hmacKeyID_1" {
			return []byte(hmacKey), nil
		} else {
			return nil, errors.New("unable to find HMAC key")
		}
	}
	if key := jwtSet.LookupKeyID(keyID); len(key) == 1 {
		log.Printf("     Found OIDC KeyID  " + keyID)
		return key[0].Materialize()
	}
	return nil, errors.New("unable to find key")
}

func verifyIDToken(ctx context.Context, rawToken string) (customJWT, error) {
	token, err := jwt.ParseWithClaims(rawToken, &customJWT{}, getKey)
	if err != nil {
		log.Printf("     Error parsing JWT %v", err)
		return customJWT{}, err
	}
	if claims, ok := token.Claims.(*customJWT); ok && token.Valid {
		return *claims, nil
	}
	return customJWT{}, errors.New("Error parsing JWT Claims")
}
