package authorizer

import (
	"errors"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/stretchr/testify/assert"
)

func TestBuildResponseOk(t *testing.T) {
	testEmail := "test@example.com"
	testSubject := "test-subject"
	testAudience := "test-audience"
	testKeys := CreateTestKeys()
	token := CreateTestIDToken(testEmail, testSubject, testAudience, nil)

	policyBuilderMock := new(PolicyBuilderMock)
	policyBuilderMock.On("BuildPolicy", token).Return(events.APIGatewayCustomAuthorizerPolicy{}, nil).Once()
	contextBuilderMock := new(ContextBuilderMock)
	contextBuilderMock.On("BuildContext", token).Return(map[string]interface{}{}, nil).Once()

	responseBuilder := ResponseBuilder{
		Context: &Context{
			DecryptionKeys: testKeys,
			CognitoClients: []string{testAudience},
		},
		PolicyBuilder:  policyBuilderMock,
		ContextBuilder: contextBuilderMock,
	}

	response, err := responseBuilder.BuildResponse(token)

	assert.Nil(t, err)
	assert.Equal(t, events.APIGatewayCustomAuthorizerResponse{
		PrincipalID:    testSubject,
		PolicyDocument: events.APIGatewayCustomAuthorizerPolicy{},
		Context:        map[string]interface{}{},
	}, response)
	policyBuilderMock.AssertExpectations(t)
	contextBuilderMock.AssertExpectations(t)
}

func TestBuildResponsePolicyBuilderError(t *testing.T) {
	testKeys := CreateTestKeys()
	testAudience := "test-audience"
	token := CreateTestIDToken("", "", testAudience, nil)

	policyBuilderMock := new(PolicyBuilderMock)
	policyBuilderMock.On("BuildPolicy", token).Return(events.APIGatewayCustomAuthorizerPolicy{}, errors.New("error")).Once()
	contextBuilderMock := new(ContextBuilderMock)

	responseBuilder := ResponseBuilder{
		Context: &Context{
			DecryptionKeys: testKeys,
			CognitoClients: []string{testAudience},
		},
		PolicyBuilder:  policyBuilderMock,
		ContextBuilder: contextBuilderMock,
	}

	response, err := responseBuilder.BuildResponse(token)

	assert.NotNil(t, err)
	assert.Equal(t, events.APIGatewayCustomAuthorizerResponse{}, response)
	policyBuilderMock.AssertExpectations(t)
	contextBuilderMock.AssertExpectations(t)
}

func TestBuildResponseContextBuilderError(t *testing.T) {
	testKeys := CreateTestKeys()
	testAudience := "test-audience"
	token := CreateTestIDToken("", "", testAudience, nil)

	policyBuilderMock := new(PolicyBuilderMock)
	policyBuilderMock.On("BuildPolicy", token).Return(events.APIGatewayCustomAuthorizerPolicy{}, nil).Once()
	contextBuilderMock := new(ContextBuilderMock)
	contextBuilderMock.On("BuildContext", token).Return(map[string]interface{}{}, errors.New("error")).Once()

	responseBuilder := ResponseBuilder{
		Context: &Context{
			DecryptionKeys: testKeys,
			CognitoClients: []string{testAudience},
		},
		PolicyBuilder:  policyBuilderMock,
		ContextBuilder: contextBuilderMock,
	}

	response, err := responseBuilder.BuildResponse(token)

	assert.NotNil(t, err)
	assert.Equal(t, events.APIGatewayCustomAuthorizerResponse{}, response)
	policyBuilderMock.AssertExpectations(t)
	contextBuilderMock.AssertExpectations(t)
}

func TestBuildResponseBadToken(t *testing.T) {
	testKeys := CreateTestKeys()
	token := "bad-token"
	policyBuilderMock := new(PolicyBuilderMock)
	contextBuilderMock := new(ContextBuilderMock)

	responseBuilder := ResponseBuilder{
		Context: &Context{
			DecryptionKeys: testKeys,
		},
		PolicyBuilder:  policyBuilderMock,
		ContextBuilder: contextBuilderMock,
	}

	response, err := responseBuilder.BuildResponse(token)

	assert.NotNil(t, err)
	assert.Equal(t, events.APIGatewayCustomAuthorizerResponse{}, response)
	policyBuilderMock.AssertExpectations(t)
	contextBuilderMock.AssertExpectations(t)
}

func TestBuildResponseDescryptionKeysNotFound(t *testing.T) {
	token := CreateTestIDToken("", "", "", nil)

	policyBuilderMock := new(PolicyBuilderMock)
	contextBuilderMock := new(ContextBuilderMock)

	responseBuilder := ResponseBuilder{
		Context: &Context{
			DecryptionKeys: []JWKey{},
		},
		PolicyBuilder:  policyBuilderMock,
		ContextBuilder: contextBuilderMock,
	}

	response, err := responseBuilder.BuildResponse(token)

	assert.NotNil(t, err)
	assert.Equal(t, events.APIGatewayCustomAuthorizerResponse{}, response)
	policyBuilderMock.AssertExpectations(t)
	contextBuilderMock.AssertExpectations(t)
}

func TestBuildResponseTokenAudienceError(t *testing.T) {
	testEmail := "test@example.com"
	testSubject := "test-subject"
	testAudience := "test-audience"
	testKeys := CreateTestKeys()
	token := CreateTestIDToken(testEmail, testSubject, testAudience, nil)

	policyBuilderMock := new(PolicyBuilderMock)
	contextBuilderMock := new(ContextBuilderMock)

	responseBuilder := ResponseBuilder{
		Context: &Context{
			DecryptionKeys: testKeys,
			CognitoClients: []string{"wrong-audience"},
		},
		PolicyBuilder:  policyBuilderMock,
		ContextBuilder: contextBuilderMock,
	}

	response, err := responseBuilder.BuildResponse(token)

	assert.NotNil(t, err)
	assert.Equal(t, events.APIGatewayCustomAuthorizerResponse{}, response)
	policyBuilderMock.AssertExpectations(t)
	contextBuilderMock.AssertExpectations(t)
}

func TestBuildResponseTokenMultipeAudience(t *testing.T) {
	testEmail := "test@example.com"
	testSubject := "test-subject"
	testAudience := "test-audience-1"
	testKeys := CreateTestKeys()
	token := CreateTestIDToken(testEmail, testSubject, testAudience, nil)

	policyBuilderMock := new(PolicyBuilderMock)
	policyBuilderMock.On("BuildPolicy", token).Return(events.APIGatewayCustomAuthorizerPolicy{}, nil).Once()
	contextBuilderMock := new(ContextBuilderMock)
	contextBuilderMock.On("BuildContext", token).Return(map[string]interface{}{}, nil).Once()

	responseBuilder := ResponseBuilder{
		Context: &Context{
			DecryptionKeys: testKeys,
			CognitoClients: []string{"test-audience-2", testAudience},
		},
		PolicyBuilder:  policyBuilderMock,
		ContextBuilder: contextBuilderMock,
	}

	response, err := responseBuilder.BuildResponse(token)

	assert.Nil(t, err)
	assert.Equal(t, events.APIGatewayCustomAuthorizerResponse{
		PrincipalID:    testSubject,
		PolicyDocument: events.APIGatewayCustomAuthorizerPolicy{},
		Context:        map[string]interface{}{},
	}, response)
	policyBuilderMock.AssertExpectations(t)
	contextBuilderMock.AssertExpectations(t)
}

func TestBuildResponseTokenMultipeAudienceError(t *testing.T) {
	testEmail := "test@example.com"
	testSubject := "test-subject"
	testAudience := "test-audience-bad"
	testKeys := CreateTestKeys()
	token := CreateTestIDToken(testEmail, testSubject, testAudience, nil)

	policyBuilderMock := new(PolicyBuilderMock)
	contextBuilderMock := new(ContextBuilderMock)

	responseBuilder := ResponseBuilder{
		Context: &Context{
			DecryptionKeys: testKeys,
			CognitoClients: []string{"test-audience-1", "test-audience-2"},
		},
		PolicyBuilder:  policyBuilderMock,
		ContextBuilder: contextBuilderMock,
	}

	response, err := responseBuilder.BuildResponse(token)

	assert.NotNil(t, err)
	assert.Equal(t, events.APIGatewayCustomAuthorizerResponse{}, response)
	policyBuilderMock.AssertExpectations(t)
	contextBuilderMock.AssertExpectations(t)
}
