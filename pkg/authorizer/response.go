package authorizer

import (
	"errors"

	"github.com/aws/aws-lambda-go/events"
	jwt "github.com/dgrijalva/jwt-go"
	log "github.com/sirupsen/logrus"
)

type PolicyBuilder interface {
	BuildPolicy(encodedToken string) (events.APIGatewayCustomAuthorizerPolicy, error)
}

type ContextBuilder interface {
	BuildContext(encodedToken string) (map[string]interface{}, error)
}

type ResponseBuilder struct {
	Context        *Context
	PolicyBuilder  PolicyBuilder
	ContextBuilder ContextBuilder
}

func (b ResponseBuilder) BuildResponse(encodedToken string) (events.APIGatewayCustomAuthorizerResponse, error) {
	standrdClaims := &jwt.StandardClaims{}
	err := GetStandardClaims(encodedToken, b.Context.DecryptionKeys, standrdClaims)
	if err != nil {
		log.WithField("error", err).Error("Failed to get token standard claims.")
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Unauthorized")
	}

	policy, err := b.PolicyBuilder.BuildPolicy(encodedToken)
	if err != nil {
		log.WithField("error", err).Error("Failed to build policy document.")
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Unauthorized")
	}

	context, err := b.ContextBuilder.BuildContext(encodedToken)
	if err != nil {
		log.WithField("error", err).Error("Failed to build context.")
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Unauthorized")
	}

	return events.APIGatewayCustomAuthorizerResponse{
		PrincipalID:    standrdClaims.Subject,
		PolicyDocument: policy,
		Context:        context,
	}, nil
}
