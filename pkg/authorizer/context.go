package authorizer

type Context struct {
	Region            string
	ApplicationID     string
	Stage             string
	AllowedUserPoolID string
	DecryptionKeys    []JWKey
}
