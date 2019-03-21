package auth

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/aws-sdk-go/service/ssm/ssmiface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const (
	appID          = "testAppID"
	expectedToken  = "Basic dGVzdEFwcElEOnRlc3RTZWNyZXQ="
	testScope      = "full"
	testCognitoURL = "testAPIURL"
	testSecretName = "secret"
)

var (
	tokenValue = "accessToken"
	secret     = "testSecret"
)

type MockedSSM struct {
	ssmiface.SSMAPI
	mock.Mock
}

// GetParameter mocks ssm.GetParameter.
func (m *MockedSSM) GetParameter(in *ssm.GetParameterInput) (*ssm.GetParameterOutput, error) {
	args := m.Called(in)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ssm.GetParameterOutput), args.Error(1)
}

func Test_saveTokenInCache(t *testing.T) {
	token := &token{
		AccessToken: "access",
		ExpiresIn:   3600,
		TokenType:   "B",
	}

	cache = nil
	saveTokenInCache(token)
	assert.NotNil(t, cache)
	assert.Equal(t, token, cache.token)
}

func Test_buildAuthHeader(t *testing.T) {
	token := buildAuthHeader(appID, secret)
	assert.Equal(t, expectedToken, token)
}

func Test_getTokenFromCache(t *testing.T) {
	tests := []struct {
		name      string
		want      *string
		testCache *tokenCache
	}{
		{name: "emptyCache", want: nil, testCache: nil},
		{name: "oldCache", want: nil, testCache: &tokenCache{
			token:     &token{AccessToken: tokenValue, ExpiresIn: 3000},
			timestamp: time.Now().Add(-3500 * time.Second),
		}},
		{name: "okCache", want: &tokenValue, testCache: &tokenCache{
			token:     &token{AccessToken: tokenValue, ExpiresIn: 3000},
			timestamp: time.Now(),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache = tt.testCache

			got := getTokenFromCache()
			if tt.want != nil {
				assert.Equal(t, *tt.want, *got)
			} else {
				assert.Nil(t, got)
			}
		})
	}
}

func TestCognitoM2MSigner_getCognitoToken(t *testing.T) {
	testSecret := "897wgagf97w9f"
	testToken := fmt.Sprintf("{\"access_token\": \"%s\"}, \"expires_in\": 3000}", tokenValue)
	cache = nil

	signer := &CognitoM2MAuthorizer{
		CognitoAPIURL: testCognitoURL,
		ClientID:      appID,
		Scope:         testScope,
	}

	tests := []struct {
		name     string
		want     *string
		wantErr  bool
		respCode int
		respBody string
	}{
		{name: "responseError", want: nil, wantErr: true, respCode: 400, respBody: ""},
		{name: "decodeError", want: nil, wantErr: true, respCode: 200, respBody: "invalid json"},
		{name: "getTokenOk", want: &tokenValue, wantErr: false, respCode: 200, respBody: testToken},
	}
	testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		res.Write([]byte("body"))
	}))
	defer func() { testServer.Close() }()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				res.WriteHeader(tt.respCode)
				res.Write([]byte(tt.respBody))
			}))

			signer.CognitoAPIURL = testServer.URL
			got, err := signer.getCognitoToken(&testSecret)
			if (err != nil) != tt.wantErr {
				t.Errorf("CognitoM2MSigner.getCognitoToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.want != nil {
				assert.Equal(t, *tt.want, *got)
			}
		})
	}
}

func Test_buildTokenRequest(t *testing.T) {
	signer := &CognitoM2MAuthorizer{
		CognitoAPIURL: "testAPIURL",
		ClientID:      appID,
		Scope:         "testAPIURL/" + testScope,
	}

	req, err := signer.buildTokenRequest(aws.String(secret))

	assert.Nil(t, err)
	assert.NotNil(t, req)
	assert.Equal(t, expectedToken, req.Header["Authorization"][0])
	assert.Equal(t, "application/x-www-form-urlencoded", req.Header["Content-Type"][0])

	buf := new(bytes.Buffer)
	buf.ReadFrom(req.Body)
	data := buf.String()

	assert.Equal(t, data, "grant_type=client_credentials&scope=testAPIURL/full")
}

func TestCognitoM2MSigner_getSecretKey(t *testing.T) {
	signer := &CognitoM2MAuthorizer{
		CognitoAPIURL: "testAPIURL",
		ClientID:      appID,
		Scope:         testScope,
		SsmSecretName: testSecretName,
	}

	tests := []struct {
		name    string
		want    *string
		wantErr bool
	}{
		{name: "GetSSMErr", want: nil, wantErr: true},
		{name: "GetSSMOk", want: &secret, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSSM := &MockedSSM{}
			if tt.wantErr {
				mockSSM.On("GetParameter", mock.Anything).Return(nil, errors.New("err"))
			} else {
				mockSSM.On("GetParameter", &ssm.GetParameterInput{
					Name:           &signer.SsmSecretName,
					WithDecryption: aws.Bool(true),
				}).Return(&ssm.GetParameterOutput{Parameter: &ssm.Parameter{Value: &secret}}, nil)
			}
			signer.SsmClient = mockSSM

			got, err := signer.getSecretKey()
			if (err != nil) != tt.wantErr {
				t.Errorf("CognitoM2MSigner.getSecretKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("CognitoM2MSigner.getSecretKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
