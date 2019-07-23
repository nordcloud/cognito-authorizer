package authorizer

/*
	Package abstracts out work needed to retrieve AWS Cognito JW token claims.
*/

// Context is a preset of data needed to build a response.
type Context struct {
	Region            string
	ApplicationID     string
	Stage             string
	AllowedUserPoolID string
	CognitoClients    []string
	DecryptionKeys    []JWKey
}
