## Cognito M2M signer

Cognito M2M signer generates authorization token using the Cognito Client Secret Key stored in the SSM. It can be used to authorize lambda or other compute resource using the Cognito Machine to Machine authorization.

Use example:

```
ssmSession := session.Must(session.NewSession(&aws.Config{
    Region: aws.String(os.Getenv("REGION")),
}))
sesCli := ssm.New(ssmSession)

&auth.CognitoM2MSigner{
    CognitoAPIURL: os.Getenv("COGNITO_API_URL"),
    ClientID:      os.Getenv("COGNITO_APP_ID"),
    Scope:         "https://scope_identifier_url/full-access",
    SsmClient:     sesCli,
    SsmSecretName: "cognitoM2mSecret",
}
```