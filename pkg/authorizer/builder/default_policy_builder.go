package builder

import (
	"errors"
	"fmt"
	"strings"

	"bitbucket.org/nordcloud/cognito-authorizer/pkg/authorizer"
	"github.com/aws/aws-lambda-go/events"
	log "github.com/sirupsen/logrus"
)

type PolicyEffect string

const (
	allow PolicyEffect = "allow"
	deny  PolicyEffect = "deny"
)

// DefaultPolicyBuilder Implements Policy builder interface.
// It grants full access for the M2M authorized compute resources
// Other methods like `TokenUse = id` are forbidden
type DefaultPolicyBuilder struct {
	Context *authorizer.Context
	Region  string
}

// BuildPolicy builds proper apigw policy based on scope from claims.
func (p *DefaultPolicyBuilder) BuildPolicy(encodedToken string) (events.APIGatewayCustomAuthorizerPolicy, error) {
	baseClaims := authorizer.BaseTokenClaims{}
	err := authorizer.GetBaseClaims(encodedToken, p.Context.DecryptionKeys, &baseClaims)
	if err != nil {
		log.Error("Failed to get base claims.")
		return events.APIGatewayCustomAuthorizerPolicy{}, err
	}

	var resources []string

	log.WithField("token_use", baseClaims.TokenUse).Debug("Token type.")
	if baseClaims.TokenUse == "access" {
		accessClaims := authorizer.AccessTokenClaims{}
		err = authorizer.GetAccessClaims(encodedToken, p.Context.DecryptionKeys, &accessClaims)
		if err != nil {
			log.Error("Failed to get access claims.")
			return events.APIGatewayCustomAuthorizerPolicy{}, err
		}

		resources = p.buildResourcesForAccessClaims(accessClaims)

	} else if baseClaims.TokenUse == "id" {
		resources = []string{}
	} else {
		log.WithField("token_use", baseClaims.TokenUse).Error("Unkown token use. Aborting")
		return events.APIGatewayCustomAuthorizerPolicy{}, errors.New("unknown token use")
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

func (p *DefaultPolicyBuilder) buildResourcesForAccessClaims(claims authorizer.AccessTokenClaims) []string {
	scopes := strings.Split(claims.Scope, " ")
	log.WithField("scopes", scopes).Info("Generating access for the scope")
	return []string{fmt.Sprintf(
		"arn:aws:execute-api:%s:*:%s/%s/*/*", p.Region, p.Context.ApplicationID, p.Context.Stage,
	)}
}
