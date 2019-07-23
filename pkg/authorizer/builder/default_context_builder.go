package builder

import (
	"strings"

	"github.com/nordcloud/cognito-authorizer/pkg/authorizer"
	log "github.com/sirupsen/logrus"
)

// DefaultContextBuilder implements the ContextBuilder interface
// It creates context with the list of scopes when using M2M authorization
type DefaultContextBuilder struct {
	Context *authorizer.Context
}

// BuildContext builds a context that is passed to resource server.
func (c *DefaultContextBuilder) BuildContext(encodedToken string) (map[string]interface{}, error) {
	baseClaims := authorizer.BaseTokenClaims{}
	err := authorizer.GetBaseClaims(encodedToken, c.Context.DecryptionKeys, &baseClaims)
	if err != nil {
		log.Error("Failed to get base claims.")
		return map[string]interface{}{}, err
	}

	if baseClaims.TokenUse == "access" {
		accessClaims := authorizer.AccessTokenClaims{}
		err := authorizer.GetAccessClaims(encodedToken, c.Context.DecryptionKeys, &accessClaims)
		if err != nil {
			return map[string]interface{}{}, err
		}

		return c.buildContextForAccessClaims(accessClaims)
	}

	idClaims := authorizer.IDTokenClaims{}
	err = authorizer.GetIDClaims(encodedToken, c.Context.DecryptionKeys, &idClaims)

	if err != nil {
		log.Error("Failed to get id claims.")
		return map[string]interface{}{}, err
	}

	return c.buildContextForIDClaims(idClaims)
}

func (c *DefaultContextBuilder) buildContextForAccessClaims(claims authorizer.AccessTokenClaims) (map[string]interface{}, error) {
	var scopesWithoutPrefix []string

	scopes := strings.Split(claims.Scope, " ")
	for _, s := range scopes {
		scopeStr := getScopeFromFullString(s)
		scopesWithoutPrefix = append(scopesWithoutPrefix, scopeStr)
	}

	return map[string]interface{}{
		"scope": strings.Join(scopesWithoutPrefix, " "),
	}, nil
}

func (c *DefaultContextBuilder) buildContextForIDClaims(claims authorizer.IDTokenClaims) (map[string]interface{}, error) {
	return map[string]interface{}{
		"email": claims.Email,
	}, nil
}

func getScopeFromFullString(scopeString string) string {
	segments := strings.Split(scopeString, "/")
	return segments[len(segments)-1]
}
