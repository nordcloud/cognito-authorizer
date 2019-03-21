package authorizer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetClaimsFromToken(t *testing.T) {
	testServer := createTestKeyServer()
	defer testServer.Close()

	username := "andrzej"
	subject := "test-principal-id"

	tokenString := createTestToken(username, subject, nil)

	keys := []JWKey{
		JWKey{KeyID: "1234"},
		JWKey{
			Algorithm: "RS256",
			Exponent:  "AQAB",
			KeyID:     "123456789",
			KeyType:   "RSA",
			N:         "3Nzq67VGAE3RNBN9DWuK-eIQ8LscppizsW9G1U7pUmqOM3-FgYYlWS-cMyIDROzyGNM6R6n0hwTehxyMiX9Ucwf6Q2Z9z0OMb8I0m918CBAYC3NJKWlpxt7O3keZam_U7wY4woYGBt01epJGi5-dIq8N5X2yQ2kx654YfTzrBR-23u8TC_05E1sYyqKPZtO2aasHGC9lFQD9-B2LeBEBChnDpc9pb8JriDibA5NNh-4ZC8RjqBkKTLGphkTDJ28HXYjtwV0yZJ05zwKlW_YWSCdiIh_nzaVKVziboCBaJVVknCEy5brjvLy_5v0HGxRzyeA0xkCauinS2L57JfO_SQ",
			Use:       "sig",
		},
	}
	tokenClaims, err := getClaimsFromToken(tokenString, keys)

	assert.Nil(t, err)
	assert.Equal(t, username, tokenClaims.Email)
}

func TestGetDecryptionKey(t *testing.T) {
	testServer := createTestKeyServer()
	defer testServer.Close()

	keys, err := GetDecryptionKeys(testServer.URL)

	assert.Nil(t, err)
	assert.Equal(t, createTestKeys(), keys)
}
