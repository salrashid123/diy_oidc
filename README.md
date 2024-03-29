
## DIY OIDC Server 

Simple `OIDC` server which will can issue arbitrary `oidc` tokens which an app can verify using the server's associated `JWK` endpoint/certificates

The intent of this application is to provide a test harness against which you can configure a system which authenticates the bearer of an OIDC token using a JWK endpoint.

This OIDC server does not require authentication to get a token; all you have to do is post the JWT claims it needs to sign.  The response will be an OIDC token which you can submit to any other server for authentication.

Basically, its a test app and needless to say **do not** use this in production...

>> this repo is not supported by google

### QuickStart

```bash
git clone https://github.com/salrashid123/diy_oidc.git
cd diy_oidc/

# i'm currently running it on cloud run here but you are free to deploy it on your own (see steps later on in the article)
# export URL=`gcloud run services describe idp-on-cloud-run --region=us-central1 --format="value(status.url)"`
export URL="https://idp-on-cloud-run-3kdezruzua-uc.a.run.app"

export IAT=`date -u +%s`
export EXP=`date -u +%s -d "+3600 seconds"`
export EMAIL="alice@domain.com"
export SUB="alice@domain.com"
export ISS=$URL
export NAME="alice"
export AUD="https://some_audience"
envsubst < "templates/jwt.tmpl" > "/tmp/jwt.json"

# simply post the JSON Claims...
export JWT_TOKEN=`curl -s -X POST -d @/tmp/jwt.json  $URL/token?kid=rsaKeyID_1`
echo $JWT_TOKEN
```

The response will be an OIDC token reflecting the claims you posted:

You can view the contents of the JWT by decoding `$JWT_TOKEN` using [jwt.io](jwt.io) debugger

A sample `JWT` may look like

```json
{
  "alg": "RS256",
  "kid": "rsaKeyID_1",
  "typ": "JWT"
}
{
  "aud": "https://some_audience",
  "email": "alice@domain.com",
  "email_verified": true,
  "exp": 1675880504,
  "iat": 1675876904,
  "isadmin": "true",
  "iss": "https://idp-on-cloud-run-3kdezruzua-uc.a.run.app",
  "mygroups": [
    "group1",
    "group2"
  ],
  "name": "alice",
  "nbf": 1675876904,
  "sub": "alice@domain.com"
}
```

### .well-known and JWK Metadata Endpoints

As with any self-respecting OIDC server, it necessarily surfaces the [.well-known](https://www.rfc-editor.org/rfc/rfc8414.html) endpoints

- `.well-known/openid-configuration` endpoint will print out the standard oidc configuration 

- `/certs` will return the `JWK` formatted public key used for `JWT` verification

- `/token?kid=rsaKeyID_1` endpoint will sign whatever `well-formed` JSON file is sent via POST
   where the `kid` field denotes the algorithm the JWT should use for signing: 
   - `RS256`: `kid=rsaKeyID_1` (default)
   - `ES256`: `kid=ecKeyID_1`
   - `HS256`: `kid=hmacKeyID_1`

```
curl -s https://idp-on-cloud-run-3kdezruzua-uc.a.run.app/.well-known/openid-configuration |jq '.'

{
  "issuer": "https://idp-on-cloud-run-3kdezruzua-uc.a.run.app",
  "jwks_uri": "https://idp-on-cloud-run-3kdezruzua-uc.a.run.app/certs",
  "id_token_signing_alg_values_supported": [
    "RS256",
    "ES256",
    "HS256"
  ],
  "response_types_supported": [
    "id_token"
  ],
  "subject_types_supported": [
    "public"
  ]
}
```

While the certificates in `JWK` format is available at

```
$ curl -s https://idp-on-cloud-run-3kdezruzua-uc.a.run.app/certs | jq '.'
{
  "keys": [
    {
      "e": "AQAB",
      "kid": "rsaKeyID_1",
      "kty": "RSA",
      "n": "qqrpBHkLN4vT6g279KYTnnbKWHIEa-fK04wlamlrALQpV6QGfIrPwSgU_ElRFpsPJYWxCvEtYS01lBC70IeAhObR5DY9Z-jTvhk1tA-VrxyEhAHLuCuCsAPLow4ZSJ-aB0vZuUtaV9-qO-0gyJEG9y_5FKT51Tbr0INtjDASH43seoQtsPDG2tnKEj9r7jOLUNehj5j4Dgv-sJMGe3EyKlw7p6vsIhsU23v0VrTxdHGuelzplxCUQJoPRSxgepYyVmfrB12XJ5uJtLhYwuTbFb3BIUyswBtxtGcigvk_ftkuSQjubiXe8UtltBI7INfs7vmAVuQr7YN8Alni4Z3BeQ",
      "use": "sig"
    },
    {
      "crv": "P-256",
      "kid": "ecKeyID_1",
      "kty": "EC",
      "use": "sig",
      "x": "QjKEvzgFPN7bIq6FpBKPcaBS1dCYaPwTO9YR4vZwCTo",
      "y": "yaitsQ0SZFs1kvQbjGxyXhPDb2tW2Su_6ZJCI-SCkio"
    }
  ]
}

```

You can ofcourse deploy your own server with your own certs...just change the certs in `server.go` and deploy wherever.

### Deploy your own IDP

If you want to deploy your own server on `cloud run`, simply run:

```bash
cd idp_server/

gcloud run deploy   --platform=managed  \
 --region=us-central1   --allow-unauthenticated  \
 --source .   idp-on-cloud-run
 ```

Or you can just run the docker file or app on any internal server thats accessible (the issue with running it standalone is that the `https://` cert should be trusted; cloud run makes it easy but is now internet-accessible)


### Verify

Included in this repo is a simple go app that will verify the default JWT format above.

To run

```bash
export URL="https://idp-on-cloud-run-3kdezruzua-uc.a.run.app"

curl -s $URL/certs | jq '.'
curl -s $URL/.well-known/openid-configuration |jq '.'

# rsa
export JWT_TOKEN_RS=`curl -s -X POST -d @/tmp/jwt.json  $URL/token?kid=rsaKeyID_1`
echo $JWT_TOKEN_RS

go run main.go --jwtToken=$JWT_TOKEN_RS --jwkUrl=$URL/certs

# ec
export JWT_TOKEN_EC=`curl -s -X POST -d @/tmp/jwt.json  $URL/token?kid=ecKeyID_1`
echo $JWT_TOKEN_EC

go run main.go --jwtToken=$JWT_TOKEN_EC --jwkUrl=$URL/certs

# hmac
export JWT_TOKEN_HS=`curl -s -X POST -d @/tmp/jwt.json  $URL/token?kid=hmacKeyID_1`
echo $JWT_TOKEN_HS

go run main.go --jwtToken=$JWT_TOKEN_HS --jwkUrl=$URL/certs
```

![images/verify.png](images/verify.png)

---

#### References

I initially wrote this app as a side show to demo workload federation here:

* [Authenticating using Workload Identity Federation to Cloud Run, Cloud Functions](https://github.com/salrashid123/workload_federation_cloudrun_gcf#1--fake-oidc-server)
* [Hashicorp Consul JWT Auth](https://github.com/salrashid123/consul_jwt_auth#quickstart)
