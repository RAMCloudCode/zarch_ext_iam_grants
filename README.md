# Z-Arch Extension: iam-grants

`iam-grants` manages IAM bindings for service accounts owned by Z-Arch resources.
It is intended for IAM relationships that Z-Arch does not natively manage.

This extension is deployment-lifecycle automation. It is not app runtime logic.

## Scope and Guarantees
- Uses only `await project_context.gcloud(...)` for IAM reads/writes.
- Resolves principals from deployed resources at runtime (no service accounts in config).
- Fails closed by default when a principal service account cannot be resolved.
- Applies only unconditional bindings.
- Is idempotent for unconditional bindings.
- Rejects risky `custom` command shapes.

## Non-Goals
- No service-account creation.
- No fallback to naming conventions for service accounts.
- No conditional-binding creation or mutation.
- No gateway/auth/security policy mutation outside IAM bindings.

## Lifecycle Hooks
This extension executes on:
- `async post_service_deploy`
- `async post_job_deploy`
- `async post_scheduler_deploy`

Each hook evaluates the full configured binding set.

## Install
Development:
```bash
zarch ext install ./extensions/zarch_ext_iam_grants --editable
```

In Z-Arch MCP-driven workflows, install via `install_extension` after the extension
block exists in `zarch.yaml`.

## Config Contract
Canonical location:
- `extensions.<extension_name>` where `type: "iam-grants"`

Canonical shape:
```yaml
extensions:
  iam-grants:
    type: "iam-grants"
    required_roles: []
    config:
      continue_on_error: false
      enable_iamcredentials_api: false
      principal_bindings: []
```

Backward-compatible shape (accepted by parser, not preferred for new configs):
```yaml
extensions:
  iam-grants:
    type: "iam-grants"
    continue_on_error: false
    principal_bindings: []
```

### Field-by-Field Schema
| Path | Type | Required | Default | Notes |
|---|---|---:|---|---|
| `type` | string | yes | none | Must be `"iam-grants"` |
| `required_roles` | list[string] | no | `[]` | Roles needed by the actor running the extension |
| `config` | object | recommended | none | Preferred wrapper for extension settings |
| `config.continue_on_error` | bool/string/int | no | `false` | Boolean parser accepts common forms (`true/false`, `1/0`, `yes/no`) |
| `config.enable_iamcredentials_api` | bool/string/int | no | `false` | When true, enables `iamcredentials.googleapis.com` before applying grants |
| `config.principal_bindings` | list[object] | no | `[]` | Empty list is valid (no-op) |
| `principal_bindings[i].principal.kind` | string | yes | none | One of `service`, `job`, `scheduler` |
| `principal_bindings[i].principal.id` | string | yes | none | Resource ID from `services`/`jobs`/scheduler name |
| `principal_bindings[i].grants` | list[object] | yes | none | Must be non-empty |
| `grants[j].role` | string | yes | none | IAM role name |
| `grants[j].target.kind` | string | yes | none | One of `project`, `secret`, `run_service`, `run_job`, `topic`, `bucket`, `service_account`, `custom` |

## Principal Resolution
The extension resolves service accounts per principal kind using `gcloud describe`:
- `service`: tries `run services describe <id> --format=value(template.serviceAccount)` first, then falls back to `--format=value(spec.template.spec.serviceAccountName)` if empty.
- `job`: tries `run jobs describe <id> --format=value(template.template.serviceAccount)` first, then falls back to `--format=value(spec.template.spec.template.spec.serviceAccountName)` if empty.
- `scheduler`: `scheduler jobs describe <id> --format=value(httpTarget.oidcToken.serviceAccountEmail)`

If resolution fails or returns empty, the grant fails when `continue_on_error=false` and is logged/skipped when `continue_on_error=true`.

No service-account email should be authored in config.

## Target Kinds
### `project`
Required:
- `kind: project`

Optional:
- `project_id`

### `secret`
Required:
- `kind: secret`
- `id` (Secret Manager secret ID)

Optional:
- `project_id`

### `run_service`
Required:
- `kind: run_service`
- `id` (Cloud Run service name)

Optional:
- `project_id`
- `region`

### `run_job`
Required:
- `kind: run_job`
- `id` (Cloud Run job name)

Optional:
- `project_id`
- `region`

### `topic`
Required:
- `kind: topic`
- `id` (Pub/Sub topic name)

Optional:
- `project_id`

### `bucket`
Required:
- `kind: bucket`
- `name` (or `id`; parser normalizes to `name`)

Optional:
- `project_id`

Behavior:
- Bucket names are normalized to `gs://...` when building commands.

### `service_account`
Required:
- `kind: service_account`
- `resource.kind` (`service`, `job`, or `scheduler`)
- `resource.id` (resource ID to resolve to a service account)

Behavior:
- Resolves the target service account from deployed resource metadata.
- Manages IAM with `gcloud iam service-accounts get-iam-policy` and
  `gcloud iam service-accounts add-iam-policy-binding`.

### `custom`
Required:
- `kind: custom`
- `get_policy_command` (non-empty list of strings)
- `add_binding_command` (non-empty list of strings)

Optional:
- `project_id`

Validation and normalization:
- `get_policy_command` must include `get-iam-policy`.
- `add_binding_command` must include `add-iam-policy-binding`.
- `add_binding_command` must not include `--member`, `--role`, or `--condition`.
- Extension auto-appends if absent:
  - `--project` on get/add commands
  - `--format=json` on get command
  - `--member` and `--role` on add command

## Runtime Algorithm
For each hook execution:
1. Parse and validate config.
2. Resolve principal service account from live resource metadata.
3. Build `get-iam-policy` and `add-iam-policy-binding` commands for each grant target.
4. Read IAM policy JSON.
5. If exact unconditional binding exists: skip.
6. If only conditional binding exists for same member+role: fail closed.
7. Otherwise apply binding.
8. Emit summary log: `applied`, `skipped`, `failed`.

## Idempotency and Dedupe
- Idempotency: policy is read before every add; existing unconditional binding is skipped.
- Dedupe in one hook run: key is `(member, role, target_identity)`.
- `target_identity` is scope-aware (`project`, `region`, target ID/name, and custom command shape), preventing false dedupe across scopes.

## Error Handling
- `continue_on_error: false` (default):
  - First failure raises immediately and stops processing.
- `continue_on_error: true`:
  - Failure is logged, processing continues with remaining grants.

## Required Roles (Actor Running Extension)
Set `required_roles` to cover all targeted IAM APIs. Typical mappings:
- Project bindings: `roles/resourcemanager.projectIamAdmin`
- Secret bindings: `roles/secretmanager.admin`
- Cloud Run service/job bindings: `roles/run.admin`
- Pub/Sub topic bindings: `roles/pubsub.admin`
- Storage bucket bindings: `roles/storage.admin`
- Service account bindings: `roles/iam.serviceAccountAdmin`
- API enablement: `roles/serviceusage.serviceUsageAdmin`
- Custom targets: least-privileged admin role for that specific API/resource type

## Generic Example (Sanitized)
Use placeholder IDs and names when sharing publicly:
```yaml
extensions:
  iam-grants:
    type: "iam-grants"
    required_roles:
      - "roles/resourcemanager.projectIamAdmin"
      - "roles/secretmanager.admin"
      - "roles/cloudkms.admin"
      - "roles/artifactregistry.admin"
    config:
      continue_on_error: false
      enable_iamcredentials_api: false
      principal_bindings:
        - principal:
            kind: service
            id: ingest-service
          grants:
            - role: roles/artifactregistry.reader
              target:
                kind: custom
                get_policy_command: [artifacts, repositories, get-iam-policy, app-python-repo, --location, example-region1]
                add_binding_command: [artifacts, repositories, add-iam-policy-binding, app-python-repo, --location, example-region1]
            - role: roles/cloudsql.client
              target: {kind: project}
            - role: roles/cloudsql.instanceUser
              target: {kind: project}
            - role: roles/secretmanager.secretAccessor
              target: {kind: secret, id: app-hmac-key}
            - role: roles/cloudkms.cryptoKeyEncrypter
              target:
                kind: custom
                get_policy_command: [kms, keys, get-iam-policy, app-dek-wrapper, --keyring, app-keyring, --location, example-region1]
                add_binding_command: [kms, keys, add-iam-policy-binding, app-dek-wrapper, --keyring, app-keyring, --location, example-region1]
```

## LLM Authoring Rules (Strict)
1. Never include service-account emails in config.
2. Always set `type: "iam-grants"`.
3. Always place settings under `config`.
4. Keep `continue_on_error` explicit (`false` unless intentional).
5. Keep each `principal_bindings[i].grants` minimal and resource-scoped.
6. Prefer resource-level targets (`secret`, `run_service`, `custom`) over broad `project` grants when possible.
7. For `custom` targets, do not include `--member`, `--role`, or `--condition`.
8. Do not use conditional IAM through this extension.
9. If one principal needs different scopes, use separate grants (or separate principal bindings) instead of broad roles.

## Safety Notes
- This extension mutates IAM policies; review config changes like security changes.
- Favor least privilege and resource scoping.
- Keep `continue_on_error: false` for predictable fail-fast behavior in production.
- Treat `custom` target commands as security-sensitive and review them carefully.

## Tests
Unit tests:
- `extensions/zarch_ext_iam_grants/tests/test_extension.py`

Integration-style, side-effect-free tests:
- `extensions/zarch_ext_iam_grants/tests/test_extension_integration.py`
- Uses in-memory async fake `project_context.gcloud`.
- No real GCP calls, no project side effects.

Run:
```bash
.venv/bin/pytest -q extensions/zarch_ext_iam_grants/tests
```
