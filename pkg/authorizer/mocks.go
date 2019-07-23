package authorizer

import (
	"github.com/aws/aws-lambda-go/events"
	"github.com/stretchr/testify/mock"
)

type policyBuilderMock struct {
	mock.Mock
}

func (m *policyBuilderMock) BuildPolicy(encodedToken string) (events.APIGatewayCustomAuthorizerPolicy, error) {
	args := m.Called(encodedToken)
	return args.Get(0).(events.APIGatewayCustomAuthorizerPolicy), args.Error(1)
}

type contextBuilderMock struct {
	mock.Mock
}

func (m *contextBuilderMock) BuildContext(encodedToken string) (map[string]interface{}, error) {
	args := m.Called(encodedToken)
	return args.Get(0).(map[string]interface{}), args.Error(1)
}
