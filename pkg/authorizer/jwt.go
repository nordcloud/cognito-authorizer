package authorizer

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"

	ncerrors "bitbucket.org/nordcloud/rnd-toolkit-go/errors"

	jwt "github.com/dgrijalva/jwt-go"
)

// IDTokenClaims represents claims stored in jw token
type IDTokenClaims struct {
	EmailVerified   bool   `json:"email_verified"`
	TokenUse        string `json:"token_use"`
	AuthTime        int64  `json:"auth_time"`
	CognitoUsername string `json:"cognito:username"`
	GivenName       string `json:"given_name"`
	Email           string `json:"email"`
	jwt.StandardClaims
}

type AccessTokenClaims struct {
	AuthTime int64  `json:"auth_time"`
	Exp      int64  `json:"exp"`
	Iat      int64  `json:"iat"`
	Iss      string `json:"iss"`
	Scope    string `json:"scope"`
	Sub      string `json:"sub"`
	TokenUse string `json:"token_use"`
	Username string `json:"username"`
	jwt.StandardClaims
}

// JWKey struct holds information about json web key
type JWKey struct {
	Algorithm string `json:"alg"`
	Exponent  string `json:"e"`
	KeyID     string `json:"kid"`
	KeyType   string `json:"kty"`
	N         string `json:"n"`
	Use       string `json:"use"`
}

const cognitoKeyRetrieveURL = "https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json"

type jwkResponse struct {
	Keys []JWKey `json:"keys"`
}

// GetCognitoKeysURL build URL to retrieve Cognito keys.
func GetCognitoKeysURL(region, userPoolID string) string {
	return fmt.Sprintf(cognitoKeyRetrieveURL, region, userPoolID)
}

func GetDecryptionKeys(url string) ([]JWKey, error) {
	response, err := http.Get(url)

	if err != nil {
		return nil, err
	}

	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var tokenResponse jwkResponse
	err = json.Unmarshal(body, &tokenResponse)
	if err != nil {
		return nil, err
	}

	return tokenResponse.Keys, nil
}

func getDecryptionKey(keys []JWKey, keyID string) (*JWKey, error) {
	for _, jwt := range keys {
		if jwt.KeyID == keyID {
			return &jwt, nil
		}
	}

	return nil, ncerrors.New("key not found", ncerrors.Fields{})
}

func getKeyForToken(keys []JWKey) func(token *jwt.Token) (interface{}, error) {
	f := func(token *jwt.Token) (interface{}, error) {
		keyID, ok := token.Header["kid"].(string)
		if !ok {
			return nil, ncerrors.New("kid is not a string", ncerrors.Fields{})
		}

		jwk, err := getDecryptionKey(keys, keyID)

		if err != nil {
			return nil, ncerrors.WithContext(err, "fetching decryption key error", ncerrors.Fields{})
		}

		pemString, err := convertJWKtoPEMString(*jwk)

		if err != nil {
			return nil, ncerrors.WithContext(err, "converting decryption key to PEM error", ncerrors.Fields{})
		}

		return jwt.ParseRSAPublicKeyFromPEM([]byte(*pemString))
	}
	return f
}

func GetIDClaims(encodedToken string, keys []JWKey, claims *IDTokenClaims) error {
	_, err := jwt.ParseWithClaims(encodedToken, claims, getKeyForToken(keys))
	if err != nil {
		return err
	}

	return nil
}

func GetAccessClaims(encodedToken string, keys []JWKey, claims *AccessTokenClaims) error {
	_, err := jwt.ParseWithClaims(encodedToken, claims, getKeyForToken(keys))

	if err != nil {
		return err
	}

	return nil
}

func GetStandardClaims(encodedToken string, keys []JWKey, claims *jwt.StandardClaims) error {
	_, err := jwt.ParseWithClaims(encodedToken, claims, getKeyForToken(keys))

	if err != nil {
		return err
	}

	return nil
}

func convertJWKtoPEMString(jwk JWKey) (*string, error) {
	nb, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}

	eb, err := base64.RawURLEncoding.DecodeString(jwk.Exponent)
	if err != nil {
		return nil, err
	}

	if len(eb) > 4 {
		return nil, ncerrors.New("e is not a uint32", ncerrors.Fields{"e": eb})
	}

	// if byte array has less than four items we need to add leading zeros to match uint32 byte lengths
	if len(eb) < 4 {
		ndata := make([]byte, 4)
		copy(ndata[4-len(eb):], eb)
		eb = ndata
	}

	e := binary.BigEndian.Uint32(eb)

	pk := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nb),
		E: int(e),
	}

	der, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: der,
	}

	var out bytes.Buffer
	pem.Encode(&out, block)

	output := out.String()

	return &output, nil
}
