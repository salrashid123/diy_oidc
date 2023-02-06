package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	jwt "github.com/golang-jwt/jwt"
	"github.com/lestrrat/go-jwx/jwk"
)

const ()

var (
	jwtSet   *jwk.Set
	jwksURL  = flag.String("jwkUrl", "https://idp-on-cloud-run-6w42z6vi3q-uc.a.run.app/certs", "JWK Endpoint")
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
	log.Printf("     OIDC doc has Audience [%s]   Issuer [%s] and SubjectEmail [%s]", doc.Audience, doc.StandardClaims.Issuer, doc.Email)
	// End verification

}

type customJWT struct {
	MyGroups      []string `json:"mygroups,omitempty"`
	Email         string   `json:"email,omitempty"`
	EmailVerified bool     `json:"email_verified,omitempty"`
	IsAdmin       string   `json:"is_admin,omitempty"`
	jwt.StandardClaims
}

func getKey(token *jwt.Token) (interface{}, error) {
	keyID, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("expecting JWT header to have string kid")
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
