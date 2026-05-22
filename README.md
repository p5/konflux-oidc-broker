# Konflux OIDC Broker

A token broker that enables fine-grained AWS authentication for [Konflux CI](https://konflux-ci.dev) pipelines using OIDC workload identity federation.

## Problem

Konflux pipelines run as Kubernetes ServiceAccounts. When federating to AWS via OIDC, the only identity available is the ServiceAccount name (e.g., `system:serviceaccount:tenant:build-pipeline-frontend`). This limits AWS IAM trust policies to namespace-level scoping — any pipeline in the namespace can assume the same role.

## Solution

The broker validates pipeline SA tokens, looks up the PipelineRun metadata from the Kubernetes API, and issues a new JWT with an enriched `sub` claim:

```
v1:ns:my-tenant:app:my-app:component:frontend:type:build:pipeline:docker-build:task:push:ref:main
```

AWS IAM trust policies can then scope access to specific applications, components, pipeline types, and branches — matching the granularity of GitHub Actions and GitLab CI OIDC.

## Trust Policy Examples

Fields are ordered broadest to narrowest. Use trailing `*` to widen scope rightward — never use `*` in the middle for fields you care about.

```json
// Exact: main branch builds of frontend via docker-build pipeline
"StringLike": {
  "sub": "v1:ns:my-tenant:app:my-app:component:frontend:type:build:pipeline:docker-build:task:*:ref:main"
}

// Any component in an application, main branch only
"StringLike": {
  "sub": "v1:ns:my-tenant:app:my-app:component:*"
}

// Only the push-to-ecr task in build pipelines
"StringLike": {
  "sub": "v1:ns:my-tenant:app:my-app:component:frontend:type:build:pipeline:docker-build:task:push-to-ecr:ref:main"
}

// Any build pipeline, any task, any branch (broadest safe pattern for an app)
"StringLike": {
  "sub": "v1:ns:my-tenant:app:my-app:component:*:type:build:pipeline:*"
}
```

## How It Works

1. A pipeline step sends its projected ServiceAccount token to the broker
2. The broker validates the token and extracts the pod identity from its cryptographic claims
3. The broker walks the Kubernetes ownership chain: pod → TaskRun → PipelineRun
4. Pipeline metadata (application, component, type, ref, etc.) is read from PipelineRun labels and annotations
5. The broker signs a new JWT with the enriched `sub` claim
6. The pipeline uses this JWT with AWS STS `AssumeRoleWithWebIdentity`

All metadata is derived from the Kubernetes API — the client cannot self-report or forge claims.

## Sub Claim Format

```
v1:ns:NAMESPACE:app:APPLICATION:component:COMPONENT:type:TYPE:pipeline:PIPELINE:task:TASK:ref:REF
```

This follows the same convention as [GitHub Actions](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect) and [GitLab CI](https://docs.gitlab.com/ee/ci/secrets/id_token_authentication.html) OIDC `sub` claims. Individual `konflux.dev/*` claims are also included in the JWT for GCP Workload Identity Federation, which supports matching on arbitrary claims.

## Security

- Pod identity is extracted from the SA token's `kubernetes.io` claims, which are cryptographically signed by the Kubernetes API server
- Only pods owned by Tekton TaskRuns (within PipelineRuns with Konflux labels) can obtain enriched tokens
- The broker uses a dedicated audience (`konflux-oidc-broker`) to prevent token confusion
- Delimiter injection is validated — values containing `:` are rejected
- Tokens have a 5-minute TTL
- All token issuance events are audit-logged as structured JSON

## Usage

### Tekton Task (simple — one-shot AWS work)

```yaml
tasks:
  - name: aws-task
    taskRef:
      name: aws-oidc-auth
    params:
      - name: roleArn
        value: arn:aws:iam::123456789012:role/my-role
      - name: image
        value: amazon/aws-cli:latest
      - name: script
        value: |
          aws s3 cp s3://my-bucket/data.tar.gz /tmp/data.tar.gz
```

### StepAction (embed into your own Task)

The `oidc-broker-auth` StepAction is cloud-agnostic. It obtains an enriched JWT from the broker, which you then exchange for cloud-specific credentials. Cloud-specific StepActions like `aws-oidc-auth` handle the exchange.

```yaml
apiVersion: tekton.dev/v1
kind: Task
metadata:
  name: my-custom-task
spec:
  volumes:
    - name: broker-token
      projected:
        sources:
          - serviceAccountToken:
              audience: konflux-oidc-broker
              expirationSeconds: 600
              path: token
    - name: enriched-token
      emptyDir: { medium: Memory, sizeLimit: 64Ki }
    - name: aws-credentials
      emptyDir: { medium: Memory, sizeLimit: 1Mi }
  steps:
    - ref:
        name: oidc-broker-auth
    - ref:
        name: aws-oidc-auth
      params:
        - name: roleArn
          value: arn:aws:iam::123456789012:role/my-role
    - name: use-aws
      image: amazon/aws-cli:latest
      volumeMounts:
        - name: aws-credentials
          mountPath: /var/run/secrets/aws
          readOnly: true
      env:
        - name: AWS_SHARED_CREDENTIALS_FILE
          value: /var/run/secrets/aws/credentials
      script: |
        aws s3 ls s3://my-bucket/
```

## Cloud Providers

### AWS (tested)

AWS STS supports `sub` and `aud` condition keys. Use the `aws-oidc-auth` Task or StepAction as shown above. Trust policies use `StringLike` on the `sub` claim for scoping.

See [Setup](#setup) below for OIDC provider registration and IAM role creation.

### GCP Workload Identity Federation (untested)

GCP can match on **any JWT claim**, not just `sub`. Use `oidc-broker-auth` with a GCP audience, then exchange the token using `gcloud`:

```yaml
steps:
  - ref:
      name: oidc-broker-auth
    params:
      - name: audience
        value: "//iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL/providers/PROVIDER"
  - name: gcp-auth
    image: google/cloud-sdk:slim
    volumeMounts:
      - name: enriched-token
        mountPath: /var/run/secrets/enriched
        readOnly: true
    script: |
      gcloud auth login --cred-file=<(cat <<CRED
      {
        "type": "external_account",
        "audience": "//iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL/providers/PROVIDER",
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "token_url": "https://sts.googleapis.com/v1/token",
        "credential_source": {
          "file": "/var/run/secrets/enriched/token"
        },
        "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/SA@PROJECT.iam.gserviceaccount.com:generateAccessToken"
      }
      CRED
      )
      gcloud storage ls gs://my-bucket/
```

GCP provider setup:

```bash
gcloud iam workload-identity-pools create konflux-pool --location=global

gcloud iam workload-identity-pools providers create-oidc konflux-broker \
  --location=global \
  --workload-identity-pool=konflux-pool \
  --issuer-uri="https://your-jwks-host.example.com" \
  --allowed-audiences="//iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/konflux-pool/providers/konflux-broker" \
  --attribute-mapping="\
    google.subject=assertion.sub,\
    attribute.application=assertion['konflux.dev/application'],\
    attribute.component=assertion['konflux.dev/component'],\
    attribute.ref=assertion['konflux.dev/git-ref'],\
    attribute.pipeline_type=assertion['konflux.dev/pipeline-type']"

# Grant access scoped to a specific application
gcloud iam service-accounts add-iam-policy-binding \
  SA@PROJECT.iam.gserviceaccount.com \
  --role=roles/iam.workloadIdentityUser \
  --member="principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/konflux-pool/attribute.application/my-app"
```

GCP's attribute mapping means trust policies can reference individual claims like `attribute.application` and `attribute.ref` directly — no `StringLike` wildcards needed.

### Azure Workload Identity (untested)

Azure federated identity credentials match on `sub` and `iss` with exact match only (no wildcards). Each component needs its own federated credential:

```bash
az identity federated-credential create \
  --name konflux-frontend \
  --identity-name my-managed-identity \
  --resource-group my-rg \
  --issuer "https://your-jwks-host.example.com" \
  --subject "v1:ns:my-tenant:app:my-app:component:frontend:type:build:pipeline::task::ref:" \
  --audiences "api://AzureADTokenExchange"
```

Usage in a pipeline step:

```yaml
steps:
  - ref:
      name: oidc-broker-auth
    params:
      - name: audience
        value: "api://AzureADTokenExchange"
  - name: azure-auth
    image: mcr.microsoft.com/azure-cli
    volumeMounts:
      - name: enriched-token
        mountPath: /var/run/secrets/enriched
        readOnly: true
    env:
      - name: AZURE_CLIENT_ID
        value: "CLIENT_ID"
      - name: AZURE_TENANT_ID
        value: "TENANT_ID"
    script: |
      export AZURE_FEDERATED_TOKEN_FILE=/var/run/secrets/enriched/token
      az login --service-principal -u "$AZURE_CLIENT_ID" -t "$AZURE_TENANT_ID" \
        --federated-token "$(cat $AZURE_FEDERATED_TOKEN_FILE)"
      az storage blob list --container my-container --account-name myaccount
```

Note: Azure requires exact `sub` match. Wildcard scoping is not supported. You must create a separate federated credential for each component or use empty trailing fields for broader matching.

### HashiCorp Vault (untested)

Vault's JWT/OIDC auth method supports matching on any JWT claim, similar to GCP:

```bash
# Enable JWT auth
vault auth enable jwt

# Configure with broker's JWKS
vault write auth/jwt/config \
  oidc_discovery_url="https://your-jwks-host.example.com"

# Create role scoped to specific application and branch
vault write auth/jwt/role/my-pipeline-role \
  role_type="jwt" \
  bound_audiences="vault.example.com" \
  bound_claims='{"konflux.dev/application":"my-app","konflux.dev/git-ref":"main"}' \
  user_claim="sub" \
  policies="my-pipeline-policy" \
  ttl="15m"
```

Usage in a pipeline step:

```yaml
steps:
  - ref:
      name: oidc-broker-auth
    params:
      - name: audience
        value: "vault.example.com"
  - name: vault-auth
    image: hashicorp/vault
    volumeMounts:
      - name: enriched-token
        mountPath: /var/run/secrets/enriched
        readOnly: true
    script: |
      export VAULT_ADDR="https://vault.example.com"
      VAULT_TOKEN=$(vault write -field=token auth/jwt/login \
        role="my-pipeline-role" \
        jwt="$(cat /var/run/secrets/enriched/token)")
      export VAULT_TOKEN
      vault kv get secret/my-app/config
```

Vault's `bound_claims` supports matching on individual `konflux.dev/*` claims, enabling fine-grained access control without relying on the composite `sub` claim.

## Setup

### 1. Deploy the broker

```bash
kubectl create namespace oidc-broker
kubectl create serviceaccount oidc-broker -n oidc-broker
kubectl create clusterrolebinding oidc-broker-tokenreview \
  --clusterrole=system:auth-delegator \
  --serviceaccount=oidc-broker:oidc-broker
kubectl create clusterrole oidc-broker-reader \
  --verb=get --resource=pods,taskruns.tekton.dev,pipelineruns.tekton.dev
kubectl create clusterrolebinding oidc-broker-reader \
  --clusterrole=oidc-broker-reader \
  --serviceaccount=oidc-broker:oidc-broker

openssl genrsa -out signing-key.pem 2048
kubectl create secret generic oidc-signing-key \
  -n oidc-broker --from-file=signing-key.pem=signing-key.pem
```

### 2. Configure allowed audiences

Set `ALLOWED_AUDIENCES` to a comma-separated list of audiences the broker will accept. Clients must specify the audience in their request. The first value is the default if omitted:

```bash
ALLOWED_AUDIENCES=sts.amazonaws.com,//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider,api://AzureADTokenExchange,vault.example.com
```

### 3. Host JWKS publicly

Upload the broker's JWKS to a publicly accessible URL (e.g., S3 bucket) so cloud providers can validate tokens. The broker serves JWKS at `/keys.json` and discovery at `/.well-known/openid-configuration`.

### 4. Register cloud provider (AWS example)

```bash
aws iam create-open-id-connect-provider \
  --url "https://your-jwks-host.example.com" \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list "$(openssl s_client -connect your-jwks-host.example.com:443 \
    </dev/null 2>/dev/null | openssl x509 -fingerprint -sha1 -noout | \
    sed 's/://g' | cut -d= -f2 | tr '[:upper:]' '[:lower:]')"
```

### 5. Create IAM role

```bash
aws iam create-role --role-name my-pipeline-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::ACCOUNT:oidc-provider/your-jwks-host.example.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "your-jwks-host.example.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "your-jwks-host.example.com:sub": "v1:ns:my-tenant:app:my-app:component:*"
        }
      }
    }]
  }'
```

## Status

This is a prototype. Not yet production-ready.
