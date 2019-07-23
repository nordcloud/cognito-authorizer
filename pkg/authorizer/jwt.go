package authorizer

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
)

// BaseTokenClaims is a common structure for token data.
type BaseTokenClaims struct {
	TokenUse string `json:"token_use"`
	jwt.StandardClaims
}

// IDTokenClaims represents claims stored in ID type JW token
type IDTokenClaims struct {
	EmailVerified   bool   `json:"email_verified"`
	AuthTime        int64  `json:"auth_time"`
	CognitoUsername string `json:"cognito:username"`
	GivenName       string `json:"given_name"`
	Email           string `json:"email"`
	BaseTokenClaims
}

// AccessTokenClaims represents claims stored in Access type JW token.
type AccessTokenClaims struct {
	AuthTime int64  `json:"auth_time"`
	Scope    string `json:"scope"`
	Username string `json:"username"`
	BaseTokenClaims
}

// JWKey struct holds information about JSON web key.
type JWKey struct {
	Algorithm string `json:"alg"`
	Exponent  string `json:"e"`
	KeyID     string `json:"kid"`
	KeyType   string `json:"kty"`
	N         string `json:"n"`
	Use       string `json:"use"`
}

const cognitoKeyRetrieveURLTemplate = "https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json"

type jwkResponse struct {
	Keys []JWKey `json:"keys"`
}

// GetDecryptionKeys gets JW token description keys from AWS Cognito service.
func GetDecryptionKeys(region, userPoolID string) ([]JWKey, error) {
	url := fmt.Sprintf(cognitoKeyRetrieveURLTemplate, region, userPoolID)
	return RequestKeys(url)
}

// RequestKeys retrieves decryption keys from external service.
func RequestKeys(url string) ([]JWKey, error) {
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

	for _, key := range tokenResponse.Keys {
		if key.KeyType != "RSA" {
			return nil, errors.New("key type is not an RSA")
		}
	}

	return tokenResponse.Keys, nil
}

// getDecryptionKey searches for key by ID in list of keys.
func getDecryptionKey(keys []JWKey, keyID string) (*JWKey, error) {
	for _, jwt := range keys {
		if jwt.KeyID == keyID {
			return &jwt, nil
		}
	}

	return nil, fmt.Errorf("%s key not found", keyID)
}

func getKeyForToken(keys []JWKey) func(token *jwt.Token) (interface{}, error) {
	f := func(token *jwt.Token) (interface{}, error) {
		keyID, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("key id is not a string")
		}

		jwk, err := getDecryptionKey(keys, keyID)

		if err != nil {
			return nil, err
		}

		pemString, err := convertJWKtoPEMString(*jwk)

		if err != nil {
			return nil, err
		}

		return jwt.ParseRSAPublicKeyFromPEM([]byte(*pemString))
	}
	return f
}

// GetIDClaims fills claims with ID type token data.
func GetIDClaims(encodedToken string, keys []JWKey, claims *IDTokenClaims) error {
	_, err := jwt.ParseWithClaims(encodedToken, claims, getKeyForToken(keys))
	if err != nil {
		return err
	}

	return nil
}

// GetAccessClaims fills claims with Access type token data.
func GetAccessClaims(encodedToken string, keys []JWKey, claims *AccessTokenClaims) error {
	_, err := jwt.ParseWithClaims(encodedToken, claims, getKeyForToken(keys))

	if err != nil {
		return err
	}

	return nil
}

// GetStandardClaims fills claims with standard token type data.
func GetBaseClaims(encodedToken string, keys []JWKey, claims *BaseTokenClaims) error {
	_, err := jwt.ParseWithClaims(encodedToken, claims, getKeyForToken(keys))

	if err != nil {
		return err
	}

	return nil
}

// converts JWK key type to PEM key type.
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
		return nil, errors.New("e is not a uint32")
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
