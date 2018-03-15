# KUBEGA
**KUBE**rnetes **G**itlab **A**uthenticator is based on [Kubernetes Webhook Token Authentication](https://kubernetes.io/docs/admin/authentication/#webhook-token-authentication).

# Compile for Alpine Linux
`CGO_ENABLED=0 go build`

# Configure kube-gitlab-authn
Set the following environment variable

`GITLAB_API_ENDPOINT: https://gitlab.example.com/api/v4/`
