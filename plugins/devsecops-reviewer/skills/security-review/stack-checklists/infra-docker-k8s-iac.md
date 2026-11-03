# Docker / Kubernetes / IaC checklist

## Dockerfile and compose
- Secrets in `ENV`, `ARG` (visible in image history), `COPY .env`, `RUN echo $TOKEN > ...`, or private keys copied into the image. Safe: BuildKit `--mount=type=secret`, runtime secrets.
- Running as root (no `USER`), `--privileged`, `cap_add: ALL`, `network_mode: host`, mounting `/var/run/docker.sock`.
- Unpinned or untrusted base images (`FROM node:latest`, unknown registries); `curl ... | sh` installs without checksum.
- Debug flags/ports in production images (`FLASK_DEBUG=1`, `NODE_ENV=development`, `--inspect=0.0.0.0`, Java `-agentlib:jdwp`).
- Default credentials in compose (`POSTGRES_PASSWORD: postgres`, `MYSQL_ROOT_PASSWORD: root`, `admin/admin`), databases published on `0.0.0.0` ports.

## Kubernetes / Helm
- `privileged: true`, `allowPrivilegeEscalation: true`, `runAsUser: 0`, `hostPath`, `hostNetwork`, `hostPID`, missing `securityContext`/`readOnlyRootFilesystem`.
- Secrets as plaintext in manifests/`values.yaml` (base64 `Secret` objects are not encryption).
- `ClusterRoleBinding` to `cluster-admin`, wildcard RBAC verbs/resources, default service account with API access.
- Ingress without TLS; `LoadBalancer` services exposing admin/DB ports.

## Terraform / CloudFormation / Bicep
- Hardcoded `access_key`/`secret_key`/passwords; `default` values on sensitive variables.
- Public buckets/containers (`acl = "public-read"`, block public access disabled), security groups `0.0.0.0/0` on SSH/RDP/DB ports.
- Encryption disabled (`encrypted = false`, no KMS), logging disabled, IAM policies with `"Action": "*"` / `"Resource": "*"`.
- Metadata service v1 allowed (`http_tokens = "optional"`) on instances that fetch user URLs (SSRF amplification).
