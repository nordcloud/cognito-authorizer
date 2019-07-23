package authorizer

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var testKeyServerResponseBody = `
{
	"keys": [
		{
			"alg": "RS256",
			"e": "AQAB",
			"kid": "abcdefghijklmnopqrsexample=",
			"kty": "RSA",
			"n": "lsjhglskjhgslkjgh43lj5h34lkjh34lkjht3example",
			"use": "sig"
		}, {
			"alg": "RS256",
			"e": "AQAB",
			"kid": "123456789",
			"kty": "RSA",
			"n": "3Nzq67VGAE3RNBN9DWuK-eIQ8LscppizsW9G1U7pUmqOM3-FgYYlWS-cMyIDROzyGNM6R6n0hwTehxyMiX9Ucwf6Q2Z9z0OMb8I0m918CBAYC3NJKWlpxt7O3keZam_U7wY4woYGBt01epJGi5-dIq8N5X2yQ2kx654YfTzrBR-23u8TC_05E1sYyqKPZtO2aasHGC9lFQD9-B2LeBEBChnDpc9pb8JriDibA5NNh-4ZC8RjqBkKTLGphkTDJ28HXYjtwV0yZJ05zwKlW_YWSCdiIh_nzaVKVziboCBaJVVknCEy5brjvLy_5v0HGxRzyeA0xkCauinS2L57JfO_SQ",
			"use": "sig"
		}
	]
}`

func createTestKeyServer(body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(body))
	}))
}

func TestGetDecryptionKey(t *testing.T) {
	testServer := createTestKeyServer(testKeyServerResponseBody)
	defer testServer.Close()

	keys, err := RequestKeys(testServer.URL)

	assert.Nil(t, err)
	assert.Equal(t, createTestKeys(), keys)
}

func TestGetDecryptionKeyNonRSAKeyError(t *testing.T) {
	body := `
	{
		"keys": [
			{
				"alg": "RS256",
				"e": "AQAB",
				"kid": "abcdefghijklmnopqrsexample=",
				"kty": "RSA",
				"n": "abcd",
				"use": "sig"
			}, {
				"alg": "RS256",
				"e": "AQAB",
				"kid": "123456789",
				"kty": "non-rsa-key",
				"n": "accd",
				"use": "sig"
			}
		]
	}`
	testServer := createTestKeyServer(body)
	defer testServer.Close()

	keys, err := RequestKeys(testServer.URL)

	assert.NotNil(t, err)
	assert.Nil(t, keys)
}

func TestGetIDClaims(t *testing.T) {
	testEmail := "test@example.com"
	testSubject := "test-subject"
	testKeys := createTestKeys()
	idClaims := &IDTokenClaims{}
	token := createTestIDToken(testEmail, testSubject, "", nil)

	err := GetIDClaims(token, testKeys, idClaims)

	assert.Nil(t, err)
	assert.Equal(t, testEmail, idClaims.Email)
	assert.Equal(t, testSubject, idClaims.StandardClaims.Subject)
}

func TestGetIDClaimsExpired(t *testing.T) {
	testEmail := "test@example.com"
	testSubject := "test-subject"
	expiresAt := time.Now().Add(-time.Hour)
	testKeys := createTestKeys()
	idClaims := &IDTokenClaims{}
	token := createTestIDToken(testEmail, testSubject, "", &expiresAt)

	err := GetIDClaims(token, testKeys, idClaims)

	assert.NotNil(t, err)
}

func TestGetAccessClaims(t *testing.T) {
	testScope := "test-scope"
	testSubject := "test-subject"
	testKeys := createTestKeys()
	accessClaims := &AccessTokenClaims{}
	token := createTestAccessToken(testScope, testSubject, nil)

	err := GetAccessClaims(token, testKeys, accessClaims)

	assert.Nil(t, err)
	assert.Equal(t, testScope, accessClaims.Scope)
	assert.Equal(t, testSubject, accessClaims.StandardClaims.Subject)
}

func TestGetBaseClaims(t *testing.T) {
	testUse := "test-use"
	testSubject := "test-subject"
	testAudience := "test-audience"
	testKeys := createTestKeys()
	baseClaims := &BaseTokenClaims{}
	token := createTestBaseToken(testUse, testSubject, testAudience, nil)

	err := GetBaseClaims(token, testKeys, baseClaims)

	assert.Nil(t, err)
	assert.Equal(t, testUse, baseClaims.TokenUse)
	assert.Equal(t, testAudience, baseClaims.Audience)
	assert.Equal(t, testSubject, baseClaims.Subject)
}
