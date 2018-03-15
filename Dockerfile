FROM alpine:3.5
COPY kube-gitlab-authn /kube-gitlab-authn
ENTRYPOINT ["/kube-gitlab-authn"]
