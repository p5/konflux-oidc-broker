FROM registry.access.redhat.com/ubi9-minimal:latest
COPY oidc-broker /usr/local/bin/oidc-broker
ENTRYPOINT ["/usr/local/bin/oidc-broker"]
