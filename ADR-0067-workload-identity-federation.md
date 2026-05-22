---
title: "67. Workload Identity Federation for Pipeline Cloud Access"
status: Proposed
applies_to:
  - pipeline-service
topics:
  - security
  - authentication
  - cloud
  - oidc
---

# 67. Workload Identity Federation for Pipeline Cloud Access

Date: 2026-05-22

## Status

Proposed

Relates to:

- [ADR 22. Secret Management For User Workloads](0022-secret-mgmt-for-user-workloads.md)

## Context

Konflux pipelines frequently need to authenticate with external cloud services (AWS, GCP, Azure, HashiCorp Vault) to push artifacts, pull dependencies, deploy applications, or access secrets. Today, this requires users to create long-lived static credentials (e.g., AWS IAM access keys) and store them as Kubernetes Secrets in their tenant namespace. Every pipeline task that needs cloud access mounts these secrets directly.

This approach has several problems:

- **Static credentials do not expire.** If leaked, they remain valid until manually rotated.
- **Credentials are stored in etcd.** Any user or controller with `get secrets` permission in the namespace can read them.
- **No pipeline-level scoping.** The same credential is available to every pipeline and task in the namespace. A build pipeline and a release pipeline share the same AWS access key.
- **Manual rotation burden.** Users must rotate credentials periodically and update every Secret referencing them.
- **Inconsistent with industry direction.** GitHub Actions, GitLab CI, and CircleCI all support OIDC-based workload identity federation, eliminating static credentials entirely.

OpenShift clusters running Konflux already have OIDC infrastructure. Managed OpenShift (ROSA, OSD) publishes the cluster's ServiceAccount token signing keys at a public OIDC discovery endpoint. Cloud providers can validate these tokens directly via OIDC federation (AWS `AssumeRoleWithWebIdentity`, GCP Workload Identity Federation, Azure Federated Identity Credentials).

However, the ServiceAccount token's `sub` claim only contains the SA name (e.g., `system:serviceaccount:tenant:build-pipeline-frontend`). Since Konflux creates a per-component SA (`build-pipeline-<component>`), cloud IAM trust policies can scope access per-component. But there is no way to scope access by pipeline type, git branch, task, or pipeline name — a build pipeline and a release pipeline for the same component share the same SA identity.

## Decision

Introduce a **Workload Identity Broker** as an optional Konflux add-on. The broker validates pipeline ServiceAccount tokens, enriches them with verified pipeline metadata from the Kubernetes API, and issues new JWTs that cloud providers can consume for fine-grained access control.

### Architecture

```
Pipeline Pod                      Broker                           Cloud Provider
    |                               |                                    |
    |-- projected SA token -------->|                                    |
    |   (aud: konflux-oidc-broker)  |                                    |
    |                               |-- TokenReview -------> K8s API     |
    |                               |<-- authenticated ------|           |
    |                               |                                    |
    |                               |-- GET pod ------------> K8s API    |
    |                               |-- GET taskrun --------> K8s API    |
    |                               |-- GET pipelinerun ----> K8s API    |
    |                               |                                    |
    |                               |-- sign enriched JWT                |
    |<-- enriched JWT (5min TTL) ---|                                    |
    |                                                                    |
    |-- enriched JWT -------------------------------------------------->|
    |<-- temporary credentials -------------------------------------------
```

### Enriched `sub` Claim

The broker constructs a `sub` claim encoding verified pipeline identity, following the same convention as GitHub Actions and GitLab CI OIDC:

```
v1:ns:NAMESPACE:app:APPLICATION:component:COMPONENT:type:TYPE:pipeline:PIPELINE:task:TASK:ref:REF
```

Fields are ordered from broadest to narrowest scope. Cloud IAM trust policies use trailing wildcards from the right to widen access:

```json
{
  "StringLike": {
    "broker.example.com:sub": "v1:ns:my-tenant:app:my-app:component:frontend:type:build:pipeline:*"
  }
}
```

Individual `konflux.dev/*` claims are also included for cloud providers that support matching on arbitrary JWT claims (GCP, Vault).

### Metadata Source

All metadata is derived from the Kubernetes API, never from the client request:

| Field | Source |
|-------|--------|
| `ns` | SA token `kubernetes.io/namespace` claim |
| `app` | PipelineRun label `appstudio.openshift.io/application` |
| `component` | PipelineRun label `appstudio.openshift.io/component` |
| `type` | PipelineRun label `pipelines.appstudio.openshift.io/type` |
| `pipeline` | PipelineRun label `tekton.dev/pipeline` |
| `task` | TaskRun label `tekton.dev/pipelineTask` |
| `ref` | PipelineRun annotation `build.appstudio.redhat.com/target_branch` |

The broker resolves the calling pod's identity from the SA token's `kubernetes.io` claims (cryptographically signed by the K8s API server), then walks the ownership chain: pod → TaskRun → PipelineRun.

### Security Properties

- **No self-reported claims.** The client sends only its SA token. All metadata is looked up from authoritative Kubernetes state.
- **Non-Tekton pods rejected.** Pods without `tekton.dev/taskRun` labels cannot obtain enriched tokens.
- **Dedicated broker audience.** The pipeline projects an SA token with audience `konflux-oidc-broker`, preventing token confusion with tokens intended for other services.
- **Delimiter injection prevented.** Values containing `:` are rejected, preventing field boundary injection in the `sub` claim. Kubernetes label validation (alphanumeric, `-`, `_`, `.` only) provides the primary gate.
- **Short-lived tokens.** Enriched JWTs have a 5-minute TTL — sufficient for a single cloud STS call.
- **Credentials never stored.** Temporary cloud credentials are written to in-memory `emptyDir` volumes and destroyed when the pod terminates.
- **Versioned format.** The `v1:` prefix allows future schema evolution without breaking existing trust policies.

### Deployment Options

**Option A: Standalone add-on (recommended for initial adoption)**

Deploy as an independent Deployment with its own ServiceAccount, signing key, and RBAC. The signing key's public component is hosted at a publicly accessible URL (S3, GCS, or an Ingress) for cloud provider JWKS discovery.

**Option B: Tekton Chains sidecar**

Deploy as a sidecar container in the Tekton Chains pod. Shares Chains' signing key and RBAC (which already includes cluster-wide access to pods, TaskRuns, and PipelineRuns). No additional RBAC needed. The signing key used for artifact attestations is reused for workload identity tokens.

**Option C: Integrated into pipeline-service**

If the broker proves valuable, integrate it directly into the pipeline-service deployment alongside Tekton Chains. This eliminates a separate deployment and leverages existing infrastructure.

### Cloud Provider Compatibility

| Provider | Claim matching | Works with broker? |
|----------|---------------|-------------------|
| AWS | `sub` and `aud` only (`StringLike`) | Yes — composite `sub` claim |
| GCP | Any claim via attribute mapping | Yes — individual `konflux.dev/*` claims |
| Azure | `sub` exact match only | Yes — requires per-component federated credential |
| Vault | Any claim via `bound_claims` | Yes — individual `konflux.dev/*` claims |

### Tekton Integration

Two Tekton resources are provided:

- **`oidc-broker-auth` StepAction** — cloud-agnostic; obtains enriched JWT from the broker
- **`aws-oidc-auth` StepAction** — AWS-specific; exchanges enriched JWT for temporary STS credentials

A wrapper **`aws-oidc-auth` Task** combines both StepActions with a user-supplied script for simple use cases.

### User Experience

**Direct approach (no broker):** Users who only need namespace-level scoping can use the cluster's existing OIDC issuer directly with AWS STS. No broker needed. A standalone Tekton Task (`community-catalog/tasks/aws-oidc-auth`) supports this.

**Broker approach:** Users who need application, component, or branch-level scoping deploy the broker (or request it from their platform team) and use the broker-aware StepActions.

### Configuration

| Parameter | Description |
|-----------|-------------|
| `ISSUER_URL` | Public URL where JWKS is hosted |
| `SIGNING_KEY_PATH` | Path to RSA private key |
| `BROKER_AUDIENCE` | Expected audience in incoming SA tokens (default: `konflux-oidc-broker`) |
| `ALLOWED_AUDIENCES` | Comma-separated list of allowed `aud` values for issued tokens |
| `ALLOWED_NAMESPACES` | Comma-separated namespace allow-list (glob patterns) |
| `TOKEN_TTL` | Enriched token lifetime (default: `5m`) |

## Consequences

- **Users can eliminate static cloud credentials** from their tenant namespaces, reducing the blast radius of secret leaks.
- **Cloud access can be scoped per-application, per-component, and per-branch** rather than per-namespace.
- **The broker becomes a security-critical component.** Its signing key can mint tokens for any pipeline identity. Key management (rotation, storage, access control) must be treated with the same rigor as Tekton Chains' signing key.
- **The broker requires cluster-level RBAC** (`system:auth-delegator` for TokenReview, read access to pods/TaskRuns/PipelineRuns). On managed Konflux clusters, this requires platform team involvement.
- **The JWKS must be publicly accessible** for cloud providers to validate tokens. This is consistent with how OpenShift ROSA/OSD already publishes SA token signing keys.
- **The `sub` claim format becomes a contract.** Changes to the format require a new version prefix (`v2:`) and must maintain backwards compatibility with existing trust policies.
- **Multi-cloud support is inherent.** The same broker serves AWS, GCP, Azure, and Vault. Cloud-specific logic lives in the StepActions, not the broker.
