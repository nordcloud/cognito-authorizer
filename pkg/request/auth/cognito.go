package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/aws-sdk-go/service/ssm/ssmiface"
	"github.com/pkg/errors"

	log "github.com/sirupsen/logrus"
)

const GrantClientCredentials = "client_credentials"

var cache *tokenCache

type token struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

type tokenCache struct {
	token     *token
	timestamp time.Time
}

// CognitoM2MAuthorizer implements the Signer interface
// It reads the Cognito App secret key from the SSM parameter store and uses it to create the Authorization token.
// cognitoAPIURL is the URL configured in the Cognito Resource servers
// clientID is the cognito app client ID
// scope is the OAuth scope name withour the Api Url - it will be concatenated automatically
type CognitoM2MAuthorizer struct {
	CognitoAPIURL string
	ClientID      string
	Scope         string

	SsmClient     ssmiface.SSMAPI
	SsmSecretName string
}

// Sign method signs request using cognito M2M authentication token
func (s *CognitoM2MAuthorizer) AuthorizeRequest(request *http.Request) (*http.Request, error) {
	err := s.AddAuthorizationHeader(request.Header)
	return request, err
}

// AddAuthorizationHeader adds Authorization HTTP header.
func (s *CognitoM2MAuthorizer) AddAuthorizationHeader(headerAdder HeaderAdder) error {
	secret, err := s.getSecretKey()
	if err != nil {
		return errors.Wrap(err, "Failed to sign http Request")
	}
	token, err := s.getCognitoToken(secret)
	if err != nil {
		return errors.Wrap(err, "Failed to sign http Request")
	}
	headerAdder.Add("Authorization", *token)
	return nil
}

// GetSecretKey retrieves an secret API key from SSM parameter store using provided parameter name.
// It returns the API key value, SSM parameter version and an error if any occurred.
func (s *CognitoM2MAuthorizer) getSecretKey() (*string, error) {
	input := ssm.GetParameterInput{
		Name:           &s.SsmSecretName,
		WithDecryption: aws.Bool(true),
	}
	param, err := s.SsmClient.GetParameter(&input)
	if err != nil {
		log.WithError(err).WithField("ssmSecretName", s.SsmSecretName).Error("Failed to get secret API key from SSM")
		return nil, errors.Wrap(err, "Failed to get secret API key from SSM")
	}

	return param.Parameter.Value, nil
}

func (s *CognitoM2MAuthorizer) getCognitoToken(secret *string) (*string, error) {
	if token := getTokenFromCache(); token != nil {
		return token, nil
	}

	req, err := s.buildTokenRequest(secret)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to build token request")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to send token request")
	}
	if resp != nil && resp.StatusCode > 299 {
		resBytes, _ := ioutil.ReadAll(resp.Body)
		log.WithFields(log.Fields{
			"code":   resp.StatusCode,
			"method": req.Method,
			"body":   string(resBytes),
			"url":    req.URL.String()}).Error("Cognito API token call returned error")
		return nil, fmt.Errorf("cognito API token call returned error code: %d", resp.StatusCode)
	}

	var responseToken token
	err = json.NewDecoder(resp.Body).Decode(&responseToken)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to decode cognito token")
	}

	saveTokenInCache(&responseToken)
	return &responseToken.AccessToken, nil

}

func (s *CognitoM2MAuthorizer) buildTokenRequest(secret *string) (*http.Request, error) {
	payload := fmt.Sprintf("grant_type=%s&scope=%s", GrantClientCredentials, s.Scope)
	reader := bytes.NewReader([]byte(payload))

	req, err := http.NewRequest(http.MethodPost, s.CognitoAPIURL, reader)
	if err != nil {
		return nil, err
	}
	req.Header["Content-Type"] = []string{"application/x-www-form-urlencoded"}
	req.Header["Authorization"] = []string{buildAuthHeader(s.ClientID, *secret)}

	return req, nil
}

func buildAuthHeader(clientID, secret string) string {
	auth := fmt.Sprintf("%s:%s", clientID, secret)
	return fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(auth)))
}

func getTokenFromCache() *string {
	if cache == nil || cache.token == nil {
		return nil
	}

	if cache.timestamp.Add(time.Duration(cache.token.ExpiresIn-5) * time.Second).Before(time.Now()) {
		return nil
	}
	return &cache.token.AccessToken
}

func saveTokenInCache(token *token) {
	cache = &tokenCache{
		token:     token,
		timestamp: time.Now(),
	}
}
