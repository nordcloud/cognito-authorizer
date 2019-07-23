package auth

/*
	This package delivers the Signer that can be used to sign the http Request

	For now only Cognito M2M signer is implemented. It would be nice to add other ones like IAM signer
*/

import (
	"net/http"
)

// HeaderAdder is an interface to setup Authorization HTTP header.
type HeaderAdder interface {
	Add(key, value string)
}

// RequestAuthorizer interface delivers method to authorize the http.Request
type RequestAuthorizer interface {
	AuthorizeRequest(*http.Request) (*http.Request, error)
	AddAuthorizationHeader(headerAdder HeaderAdder) error
}
