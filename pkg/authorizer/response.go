package authorizer

import (
	"errors"

	"github.com/aws/aws-lambda-go/events"
	log "github.com/sirupsen/logrus"
)

// PolicyBuilder interface for building API GW custom authorizer policy.
type PolicyBuilder interface {
	BuildPolicy(encodedToken string) (events.APIGatewayCustomAuthorizerPolicy, error)
}

// ContextBuilder interface for building context passed to resource server.
type ContextBuilder interface {
	BuildContext(encodedToken string) (map[string]interface{}, error)
}

// ResponseBuilder struct for building proper custom authorizer response.
type ResponseBuilder struct {
	Context        *Context
	PolicyBuilder  PolicyBuilder
	ContextBuilder ContextBuilder
}

// BuildResponse builds a proper custom authorizer response based on context, policy and context builders.
func (b ResponseBuilder) BuildResponse(encodedToken string) (events.APIGatewayCustomAuthorizerResponse, error) {
	baseClaims := &BaseTokenClaims{}
	err := GetBaseClaims(encodedToken, b.Context.DecryptionKeys, baseClaims)
	if err != nil {
		log.WithField("error", err).Info("Failed to get token standard claims.")
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Unauthorized")
	}

	valid := false
	for _, client := range b.Context.CognitoClients {
		valid = valid || baseClaims.VerifyAudience(client, true) || baseClaims.TokenUse == "access" // Only ID Token has audience field.
	}

	if !valid {
		log.WithField("audience", baseClaims.Audience).Error("Failed to verify token audience.")
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
		PrincipalID:    baseClaims.Subject,
		PolicyDocument: policy,
		Context:        context,
	}, nil
}
