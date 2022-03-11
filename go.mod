module github.com/sijmenaukema/cognito-authorizer/pkg/authorizer

go 1.11

require (
	github.com/aws/aws-lambda-go v1.9.0
	github.com/aws/aws-sdk-go v1.18.6
	github.com/golang-jwt/jwt/v4 v4.3.0
	github.com/nordcloud/cognito-authorizer v0.7.4
	github.com/pkg/errors v0.8.1
	github.com/sirupsen/logrus v1.4.0
	github.com/stretchr/testify v1.3.0
)

replace github.com/nordcloud/cognito-authorizer v0.7.4 => github.com/sijmenaukema/cognito-authorizer v0.7.5