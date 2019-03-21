package authorizer

// Context is a preset of data needed to build a response.
type Context struct {
	Region            string
	ApplicationID     string
	Stage             string
	AllowedUserPoolID string
	CognitoClients    []string
	DecryptionKeys    []JWKey
}
