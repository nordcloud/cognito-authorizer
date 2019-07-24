[![Build Status](https://travis-ci.org/nordcloud/cognito-authorizer.svg?branch=master)](https://travis-ci.org/nordcloud/cognito-authorizer)

# Cognito authorizer
A golang packages that abstract out work with JSON web access/identity tokens for AWS API Gateway custom authorizer.

These packages handle:

- access, id and standard tokens
- token verification
- token payload decrypting (claims)
- building proper responses from a custom authorizer
- a M2M token signer helper

You don't need to worry about JWT. The `GetIDClaims`, `GetAccessClaims` and `GetStandardClaims` will do the work for you, so you can focus only on building `APIGatewayCustomAuthorizerPolicy`.

### Docs

- [authorizer](https://godoc.org/github.com/nordcloud/cognito-authorizer/pkg/authorizer#pkg-index)
- [default builder](https://godoc.org/github.com/nordcloud/cognito-authorizer/pkg/authorizer/builder)
- [request signer](https://godoc.org/github.com/nordcloud/cognito-authorizer/pkg/request/auth)


### About resource server context
You can pass a context created by your custom authorizer to the resource server. This is done by satisfying ContextBuilder interface. The method should return a `map[string]interface{}` (this is how AWS golang SDK works) but keys and values in this map have to be *strings*. More info [here](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-lambda-authorizer-output.html).


## Example

Custom authorizer main package
```go
package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	log "github.com/sirupsen/logrus"

	cognitoAuthorizer "github.com/nordcloud/cognito-authorizer/pkg/authorizer"
)

type PolicyEffect string

const (
	allow PolicyEffect = "allow"
	deny  PolicyEffect = "deny"
)

type Policy struct {
	Context *cognitoAuthorizer.Context
}

func (b Policy) BuildPolicy(encodedToken string) (events.APIGatewayCustomAuthorizerPolicy, error) {
	accessClaims := &cognitoAuthorizer.AccessTokenClaims{}
	err := cognitoAuthorizer.GetAccessClaims(encodedToken, b.Context.DecryptionKeys, accessClaims)
	if err != nil {
		return events.APIGatewayCustomAuthorizerPolicy{}, err
	}

	resources := []string{
		fmt.Sprintf(
			"arn:aws:execute-api:%s:*:%s/%s/*/*",
			b.Context.Region,
			b.Context.ApplicationID,
			b.Context.Stage,
		),
	}

	policy := events.APIGatewayCustomAuthorizerPolicy{
		Version: "2012-10-17",
		Statement: []events.IAMPolicyStatement{
			{
				Action:   []string{"execute-api:Invoke"},
				Effect:   string(allow),
				Resource: resources,
			},
		},
	}

	return policy, nil
}

func (b Policy) BuildContext(encodedToken string) (map[string]interface{}, error) {
	accessClaims := &cognitoAuthorizer.AccessTokenClaims{}
	err := cognitoAuthorizer.GetAccessClaims(encodedToken, b.Context.DecryptionKeys, accessClaims)
	if err != nil {
		return map[string]interface{}{}, err
	}

	context := map[string]interface{}{
		"token_scope": accessClaims.Scope,
	}

	return context, nil
}

var (
	sharedContext *cognitoAuthorizer.Context
)

// Init is called on lambda cold start. In this function we pull Cognito keys to verify tokens.
func init() {
	sharedContext = &cognitoAuthorizer.Context{
		Region:            os.Getenv("REGION"),
		ApplicationID:     os.Getenv("API_APPLICATION_ID"),
		Stage:             os.Getenv("API_STAGE"),
		AllowedUserPoolID: os.Getenv("API_ALLOWED_USER_POOL_ID"),
		CognitoClients:    strings.Split(os.Getenv("COGNITO_CLIENTS"), ","),
		DecryptionKeys:    nil,
	}

	keys, err := cognitoAuthorizer.GetDecryptionKeys(sharedContext.Region, sharedContext.AllowedUserPoolID)
	if err != nil {
		log.WithField("error", err).Error("Unable to get decryption keys.")
	}

	sharedContext.DecryptionKeys = keys

	log.WithFields(log.Fields{
		"region":               sharedContext.Region,
		"application_id":       sharedContext.ApplicationID,
		"stage":                sharedContext.Stage,
		"allowed_user_pool_id": sharedContext.AllowedUserPoolID,
		"cognito_clients":      sharedContext.CognitoClients,
	}).Info("Finished initialization.")
}

func handler(ctx context.Context, event events.APIGatewayCustomAuthorizerRequest) (
	events.APIGatewayCustomAuthorizerResponse, error) {
	log.WithField("method_arn", event.MethodArn).Info("Authorizer lambda invoked.")

	policy := &Policy{
		Context: sharedContext,
	}

	responseBuilder := &cognitoAuthorizer.ResponseBuilder{
		Context:        sharedContext,
		PolicyBuilder:  policy,
		ContextBuilder: policy,
	}

	return responseBuilder.BuildResponse(event.AuthorizationToken)
}

func main() {
	lambda.Start(handler)
}
```
## Authors
- Grzegorz Bednarski, Nordcloud 🇵🇱
- Kamil Piotrowski, Nordcloud 🇵🇱
- Artur Kowalski, Nordcloud 🇵🇱
