package authorizer

import (
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

const rawKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA3Nzq67VGAE3RNBN9DWuK+eIQ8LscppizsW9G1U7pUmqOM3+F
gYYlWS+cMyIDROzyGNM6R6n0hwTehxyMiX9Ucwf6Q2Z9z0OMb8I0m918CBAYC3NJ
KWlpxt7O3keZam/U7wY4woYGBt01epJGi5+dIq8N5X2yQ2kx654YfTzrBR+23u8T
C/05E1sYyqKPZtO2aasHGC9lFQD9+B2LeBEBChnDpc9pb8JriDibA5NNh+4ZC8Rj
qBkKTLGphkTDJ28HXYjtwV0yZJ05zwKlW/YWSCdiIh/nzaVKVziboCBaJVVknCEy
5brjvLy/5v0HGxRzyeA0xkCauinS2L57JfO/SQIDAQABAoIBAFrykb5MIC5B3RLv
r4AWN91cTROESXEE0oIPS4DNBOFORY5JRcWnYrvOEikwKV55n9u/J3GZN7tdsvC6
Pdjk2PahY1nb25S8wRjIRPemBcwgLHaSm5707HzbBR6dJzygHnPrAPaBT/wFnV8C
2w/lw0QkB7nnv79okwjuSjFQI4sw1xhtf/u809EUm1sDwPupKo0n096AiOMJfixi
HnL27rJr9K31D1qTrjVJ0PTBVrOa+88kVX10y12iX+UkJMwJZ9i5misznPEeCSx+
BCkBwMGGK9a+6QGxkQuM6HXIkfidf+ITxRaYkRWvcx+qsqApWGEyARchlahYdf49
a7icNe0CgYEA9wKA7dj0RsNSRR6nJ2ebunAcfIBmWttmTEMLqwS7NHDywfgdSkdB
GR6Ef2ZjFYamjjipOlBR5ZtwsRcVLmn/BRGpgnl6B8ZTSTycNR/RhvPXPv+xvPPP
Vk32GHvMstTxg0OUPqSkFLYHxPnAuszvsdlq68/b75C7Qnm3XO8Xp3sCgYEA5ObK
+M1ppsuJ7/QL6XfVFxenBk6Ml1WEoxmXOUbv09BTlwvxMQYeL228IXiRxNq4vq8F
Em00RcQkmiXITpbFPgKDSqQkKdyrVvgA3+UeXiQ9CdOVrdtlQIL3XRsT3LprtgSE
WUSJKoHb+DtHabadHIajO5ONO6KRTuHiSLiSlwsCgYEA1YiNipAmRFIv+d7Q48i2
oEqw5ZReZ6cJXV4MZTB24ZPO2I40S/UjOqLeKgCKIZ7At2wWJ3ouAk8I8Z6hyfkJ
5AjrwAZhzvzNHR/PbkFucbq0VhrXPSCMGfDVkT7cq7BYhIBUVH8h9WGTf93kldf6
UoZA31BWslgs+f+c2zM6AKcCgYEA48CfhB8eWE9817vDfnE1HNzz21qcmJcGeiIk
TWE/j0lhYpEHUvf7YMWWwtbscyoNV+1c5pCxyhj3MkkVnNx3NNPbPpFDSkO+V7I7
bIrURGdaNETKUUpS3HVzGriucpkqQtkLtqZytFCxRbP1wkFo4dE06TpO9F80pYAr
XqAHezECgYEA8nbfXFP1NjftiHS/6R6edwTcdK+AFruP1t4M/0njh/5aaWzJ8aBh
KGnN0M08uvAI8cj3D86h+45gvkVV+ghB+MNh7uStVW5UNyiqPPqtCecm2YTenpnP
bsPcF5WhzjCGzwujQaYtl5tySIWj1+wfiCzBq55jk5Tr74bWu8j1isg=
-----END RSA PRIVATE KEY-----`

// CreateTestKeys helper function for testing purposes.
func CreateTestKeys() []JWKey {
	return []JWKey{
		JWKey{
			Algorithm: "RS256",
			Exponent:  "AQAB",
			KeyID:     "abcdefghijklmnopqrsexample=",
			KeyType:   "RSA",
			N:         "lsjhglskjhgslkjgh43lj5h34lkjh34lkjht3example",
			Use:       "sig",
		},
		JWKey{
			Algorithm: "RS256",
			Exponent:  "AQAB",
			KeyID:     "123456789",
			KeyType:   "RSA",
			N:         "3Nzq67VGAE3RNBN9DWuK-eIQ8LscppizsW9G1U7pUmqOM3-FgYYlWS-cMyIDROzyGNM6R6n0hwTehxyMiX9Ucwf6Q2Z9z0OMb8I0m918CBAYC3NJKWlpxt7O3keZam_U7wY4woYGBt01epJGi5-dIq8N5X2yQ2kx654YfTzrBR-23u8TC_05E1sYyqKPZtO2aasHGC9lFQD9-B2LeBEBChnDpc9pb8JriDibA5NNh-4ZC8RjqBkKTLGphkTDJ28HXYjtwV0yZJ05zwKlW_YWSCdiIh_nzaVKVziboCBaJVVknCEy5brjvLy_5v0HGxRzyeA0xkCauinS2L57JfO_SQ",
			Use:       "sig",
		},
	}
}

// CreateTestBaseToken is a helper function for testing.
func CreateTestBaseToken(tokenUse, subject, audience string, expiresAt *time.Time) string {
	claims := BaseTokenClaims{
		TokenUse: tokenUse,
	}
	claims.Subject = subject
	claims.Audience = audience

	if expiresAt != nil {
		claims.ExpiresAt = expiresAt.Unix()
	}

	rsaKey, _ := jwt.ParseRSAPrivateKeyFromPEM([]byte(rawKey))

	token := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), claims)
	token.Header["kid"] = "123456789"
	tokenString, _ := token.SignedString(rsaKey)

	return tokenString
}

// CreateTestIDToken is a helper function for testing purposes.
func CreateTestIDToken(username, subject, audience string, expiresAt *time.Time) string {
	claims := IDTokenClaims{
		Email: username,
	}
	claims.Subject = subject
	claims.Audience = audience
	claims.TokenUse = "id"

	if expiresAt != nil {
		claims.ExpiresAt = expiresAt.Unix()
	}

	rsaKey, _ := jwt.ParseRSAPrivateKeyFromPEM([]byte(rawKey))

	token := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), claims)
	token.Header["kid"] = "123456789"
	tokenString, _ := token.SignedString(rsaKey)

	return tokenString
}

// CreateTestAccessToken is a helper function for testing purposes.
func CreateTestAccessToken(scope, subject string, expiresAt *time.Time) string {
	claims := AccessTokenClaims{
		Scope: scope,
	}
	claims.Subject = subject
	claims.TokenUse = "access"

	if expiresAt != nil {
		claims.ExpiresAt = expiresAt.Unix()
	}

	rsaKey, _ := jwt.ParseRSAPrivateKeyFromPEM([]byte(rawKey))

	token := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), claims)
	token.Header["kid"] = "123456789"
	tokenString, _ := token.SignedString(rsaKey)

	return tokenString

}
