from __future__ import annotations

import json
from typing import Any, Dict, Iterable, Mapping

from zarch.extensions.base import ZArchExtension


SUPPORTED_PRINCIPAL_KINDS = {"service", "job", "scheduler"}
SUPPORTED_TARGET_KINDS = {
    "project",
    "secret",
    "run_service",
    "run_job",
    "topic",
    "bucket",
    "service_account",
    "custom",
}

BOOL_TRUE_VALUES = {"true", "1", "yes", "y", "on"}
BOOL_FALSE_VALUES = {"false", "0", "no", "n", "off"}
IAM_CREDENTIALS_API = "iamcredentials.googleapis.com"
CUSTOM_GET_POLICY_VERB = "get-iam-policy"
CUSTOM_ADD_POLICY_VERB = "add-iam-policy-binding"
DISALLOWED_CUSTOM_ADD_FLAGS = ("--member", "--role", "--condition")


class Extension(ZArchExtension):
    """
    Z-Arch extension: iam-grants
    """

    def claim(self, extension_name: str, extension_block: Dict[str, Any]) -> bool:
        return extension_block.get("type") == "iam-grants"

    async def post_service_deploy(
        self,
        project_context,
        extension_configuration: Dict[str, Any],
    ) -> None:
        await self._apply_all_bindings(
            project_context=project_context,
            extension_configuration=extension_configuration,
            hook_name="post_service_deploy",
        )

    async def post_job_deploy(
        self,
        project_context,
        extension_configuration: Dict[str, Any],
    ) -> None:
        await self._apply_all_bindings(
            project_context=project_context,
            extension_configuration=extension_configuration,
            hook_name="post_job_deploy",
        )

    async def post_scheduler_deploy(
        self,
        project_context,
        extension_configuration: Dict[str, Any],
    ) -> None:
        await self._apply_all_bindings(
            project_context=project_context,
            extension_configuration=extension_configuration,
            hook_name="post_scheduler_deploy",
        )

    async def _apply_all_bindings(
        self,
        *,
        project_context,
        extension_configuration: Mapping[str, Any],
        hook_name: str,
    ) -> None:
        settings = self._resolve_settings(extension_configuration)
        principal_bindings = settings["principal_bindings"]
        continue_on_error = settings["continue_on_error"]

        if settings["enable_iamcredentials_api"]:
            try:
                await self._enable_iamcredentials_api(project_context)
            except Exception as exc:
                if continue_on_error:
                    project_context.log(
                        f"iam-grants: failed to enable {IAM_CREDENTIALS_API}: {exc}",
                        level="warn",
                    )
                else:
                    raise

        if not principal_bindings:
            project_context.log(
                f"iam-grants: no principal_bindings configured for {hook_name}.",
                level="info",
            )
            return

        applied = 0
        skipped = 0
        failed = 0
        seen_binding_keys: set[tuple[str, str, str]] = set()

        project_context.log(
            f"iam-grants: evaluating {len(principal_bindings)} principal bindings on {hook_name}.",
            level="info",
        )

        for principal_binding in principal_bindings:
            principal = principal_binding["principal"]
            principal_label = (
                f"{principal['kind']}:{principal['id']}"
            )

            try:
                sa_email = await self._resolve_service_account_email(
                    project_context=project_context,
                    principal=principal,
                )
            except Exception as exc:
                failed += 1
                if continue_on_error:
                    project_context.log(
                        f"iam-grants: failed to resolve service account for {principal_label}: {exc}",
                        level="warn",
                    )
                    continue
                raise

            member = f"serviceAccount:{sa_email}"

            for grant in principal_binding["grants"]:
                role = grant["role"]
                target = grant["target"]
                target_identity = self._target_identity(target, project_context)
                dedupe_key = (member, role, target_identity)
                if dedupe_key in seen_binding_keys:
                    skipped += 1
                    project_context.log(
                        f"iam-grants: duplicate binding skipped for {member} role={role} target={target_identity}",
                        level="info",
                    )
                    continue
                seen_binding_keys.add(dedupe_key)

                try:
                    change_applied = await self._ensure_binding(
                        project_context=project_context,
                        member=member,
                        role=role,
                        target=target,
                    )
                    if change_applied:
                        applied += 1
                    else:
                        skipped += 1
                except Exception as exc:
                    failed += 1
                    if continue_on_error:
                        project_context.log(
                            "iam-grants: failed grant "
                            f"member={member} role={role} target={target_identity}: {exc}",
                            level="warn",
                        )
                        continue
                    raise

        project_context.log(
            "iam-grants: hook complete "
            f"(applied={applied}, skipped={skipped}, failed={failed}).",
            level="info",
        )

    def _resolve_settings(
        self,
        extension_configuration: Mapping[str, Any],
    ) -> Dict[str, Any]:
        if not isinstance(extension_configuration, Mapping):
            raise RuntimeError("iam-grants config must be a mapping.")

        cfg_obj: Mapping[str, Any] = extension_configuration
        nested = extension_configuration.get("config")
        if isinstance(nested, Mapping):
            cfg_obj = nested

        continue_on_error = self._parse_bool(
            cfg_obj.get("continue_on_error", False),
            field_name="continue_on_error",
        )
        enable_iamcredentials_api = self._parse_bool(
            cfg_obj.get("enable_iamcredentials_api", False),
            field_name="enable_iamcredentials_api",
        )
        principal_bindings_raw = cfg_obj.get("principal_bindings", [])
        if principal_bindings_raw is None:
            principal_bindings_raw = []
        if not isinstance(principal_bindings_raw, list):
            raise RuntimeError("principal_bindings must be a list.")

        principal_bindings: list[dict[str, Any]] = []
        for idx, binding_raw in enumerate(principal_bindings_raw):
            if not isinstance(binding_raw, Mapping):
                raise RuntimeError(
                    f"principal_bindings[{idx}] must be an object."
                )
            principal_bindings.append(
                self._parse_principal_binding(binding_raw, idx)
            )

        return {
            "continue_on_error": continue_on_error,
            "enable_iamcredentials_api": enable_iamcredentials_api,
            "principal_bindings": principal_bindings,
        }

    def _parse_principal_binding(
        self,
        binding_raw: Mapping[str, Any],
        index: int,
    ) -> dict[str, Any]:
        principal_raw = binding_raw.get("principal")
        if not isinstance(principal_raw, Mapping):
            raise RuntimeError(
                f"principal_bindings[{index}].principal must be an object."
            )
        principal_kind = str(principal_raw.get("kind", "")).strip().lower()
        principal_id = str(principal_raw.get("id", "")).strip()
        if principal_kind not in SUPPORTED_PRINCIPAL_KINDS:
            raise RuntimeError(
                "principal_bindings[{i}].principal.kind must be one of {kinds}".format(
                    i=index,
                    kinds=sorted(SUPPORTED_PRINCIPAL_KINDS),
                )
            )
        if not principal_id:
            raise RuntimeError(
                f"principal_bindings[{index}].principal.id is required."
            )

        grants_raw = binding_raw.get("grants")
        if not isinstance(grants_raw, list) or not grants_raw:
            raise RuntimeError(
                f"principal_bindings[{index}].grants must be a non-empty list."
            )

        grants: list[dict[str, Any]] = []
        for grant_idx, grant_raw in enumerate(grants_raw):
            if not isinstance(grant_raw, Mapping):
                raise RuntimeError(
                    f"principal_bindings[{index}].grants[{grant_idx}] must be an object."
                )
            role = str(grant_raw.get("role", "")).strip()
            if not role:
                raise RuntimeError(
                    f"principal_bindings[{index}].grants[{grant_idx}].role is required."
                )
            target_raw = grant_raw.get("target")
            if not isinstance(target_raw, Mapping):
                raise RuntimeError(
                    f"principal_bindings[{index}].grants[{grant_idx}].target must be an object."
                )
            grants.append(
                {
                    "role": role,
                    "target": self._parse_target(
                        target_raw=target_raw,
                        binding_index=index,
                        grant_index=grant_idx,
                    ),
                }
            )

        return {
            "principal": {
                "kind": principal_kind,
                "id": principal_id,
            },
            "grants": grants,
        }

    def _parse_target(
        self,
        *,
        target_raw: Mapping[str, Any],
        binding_index: int,
        grant_index: int,
    ) -> dict[str, Any]:
        kind = str(target_raw.get("kind", "")).strip().lower()
        if kind not in SUPPORTED_TARGET_KINDS:
            raise RuntimeError(
                "principal_bindings[{b}].grants[{g}].target.kind must be one of {kinds}".format(
                    b=binding_index,
                    g=grant_index,
                    kinds=sorted(SUPPORTED_TARGET_KINDS),
                )
            )

        target: dict[str, Any] = {"kind": kind}
        if kind == "project":
            project_id = str(target_raw.get("project_id", "")).strip()
            if project_id:
                target["project_id"] = project_id
            return target

        if kind in {"secret", "run_service", "run_job", "topic"}:
            identifier = str(target_raw.get("id", "")).strip()
            if not identifier:
                raise RuntimeError(
                    f"principal_bindings[{binding_index}].grants[{grant_index}].target.id is required for kind={kind}."
                )
            target["id"] = identifier
            project_id = str(target_raw.get("project_id", "")).strip()
            if project_id:
                target["project_id"] = project_id
            region = str(target_raw.get("region", "")).strip()
            if region:
                target["region"] = region
            return target

        if kind == "bucket":
            name = str(
                target_raw.get("name", target_raw.get("id", ""))
            ).strip()
            if not name:
                raise RuntimeError(
                    f"principal_bindings[{binding_index}].grants[{grant_index}].target.name is required for kind=bucket."
                )
            target["name"] = name
            project_id = str(target_raw.get("project_id", "")).strip()
            if project_id:
                target["project_id"] = project_id
            return target

        if kind == "service_account":
            resource_raw = target_raw.get("resource")
            if not isinstance(resource_raw, Mapping):
                raise RuntimeError(
                    f"principal_bindings[{binding_index}].grants[{grant_index}].target.resource must be an object for kind=service_account."
                )
            resource_kind = str(resource_raw.get("kind", "")).strip().lower()
            resource_id = str(resource_raw.get("id", "")).strip()
            if resource_kind not in SUPPORTED_PRINCIPAL_KINDS:
                raise RuntimeError(
                    "principal_bindings[{b}].grants[{g}].target.resource.kind must be one of {kinds}".format(
                        b=binding_index,
                        g=grant_index,
                        kinds=sorted(SUPPORTED_PRINCIPAL_KINDS),
                    )
                )
            if not resource_id:
                raise RuntimeError(
                    f"principal_bindings[{binding_index}].grants[{grant_index}].target.resource.id is required for kind=service_account."
                )
            target["resource"] = {
                "kind": resource_kind,
                "id": resource_id,
            }
            return target

        if kind == "custom":
            get_policy_command = self._parse_command_list(
                target_raw.get("get_policy_command"),
                field_name=(
                    "principal_bindings[{b}].grants[{g}].target.get_policy_command".format(
                        b=binding_index,
                        g=grant_index,
                    )
                ),
            )
            add_binding_command = self._parse_command_list(
                target_raw.get("add_binding_command"),
                field_name=(
                    "principal_bindings[{b}].grants[{g}].target.add_binding_command".format(
                        b=binding_index,
                        g=grant_index,
                    )
                ),
            )
            field_prefix = "principal_bindings[{b}].grants[{g}].target".format(
                b=binding_index,
                g=grant_index,
            )
            self._validate_custom_commands(
                get_policy_command=get_policy_command,
                add_binding_command=add_binding_command,
                field_prefix=field_prefix,
            )
            target["get_policy_command"] = get_policy_command
            target["add_binding_command"] = add_binding_command
            project_id = str(target_raw.get("project_id", "")).strip()
            if project_id:
                target["project_id"] = project_id
            return target

        raise RuntimeError(
            f"Unsupported target kind: {kind}"
        )

    async def _enable_iamcredentials_api(self, project_context) -> None:
        output, code = await project_context.gcloud(
            [
                "services",
                "enable",
                IAM_CREDENTIALS_API,
                "--project",
                project_context.id,
                "--quiet",
            ]
        )
        if code != 0:
            raise RuntimeError(
                f"Failed to enable {IAM_CREDENTIALS_API}: {output}"
            )
        project_context.log(
            f"iam-grants: ensured {IAM_CREDENTIALS_API} is enabled.",
            level="info",
        )

    def _parse_command_list(self, value: Any, *, field_name: str) -> list[str]:
        if not isinstance(value, list) or not value:
            raise RuntimeError(f"{field_name} must be a non-empty list of strings.")
        result: list[str] = []
        for idx, item in enumerate(value):
            if not isinstance(item, str) or not item.strip():
                raise RuntimeError(
                    f"{field_name}[{idx}] must be a non-empty string."
                )
            result.append(item.strip())
        return result

    def _validate_custom_commands(
        self,
        *,
        get_policy_command: list[str],
        add_binding_command: list[str],
        field_prefix: str,
    ) -> None:
        if CUSTOM_GET_POLICY_VERB not in get_policy_command:
            raise RuntimeError(
                f"{field_prefix}.get_policy_command must include '{CUSTOM_GET_POLICY_VERB}'."
            )
        if CUSTOM_ADD_POLICY_VERB not in add_binding_command:
            raise RuntimeError(
                f"{field_prefix}.add_binding_command must include '{CUSTOM_ADD_POLICY_VERB}'."
            )
        for flag in DISALLOWED_CUSTOM_ADD_FLAGS:
            if self._has_flag(add_binding_command, flag):
                raise RuntimeError(
                    f"{field_prefix}.add_binding_command must not include '{flag}'. "
                    "The extension sets principal/role and does not support conditional grants."
                )

    async def _resolve_service_account_email(
        self,
        *,
        project_context,
        principal: Mapping[str, str],
    ) -> str:
        principal_kind = principal["kind"]
        principal_id = principal["id"]
        discovered = ""

        if principal_kind == "service":
            discovered = await self._lookup_service_service_account(
                project_context=project_context,
                service_id=principal_id,
            )
        elif principal_kind == "job":
            discovered = await self._lookup_job_service_account(
                project_context=project_context,
                job_id=principal_id,
            )
        elif principal_kind == "scheduler":
            discovered = await self._lookup_scheduler_service_account(
                project_context=project_context,
                scheduler_id=principal_id,
            )
        else:
            raise RuntimeError(f"Unsupported principal kind: {principal_kind}")

        if discovered:
            return self._normalize_service_account_email(
                discovered,
                project_id=project_context.id,
            )

        raise RuntimeError(
            "Could not resolve service account for "
            f"{principal_kind}:{principal_id}. Resource lookup returned no service account "
            f"(project={project_context.id}, region={project_context.region}). "
            "If this principal may not exist yet, set continue_on_error=true to "
            "log and continue instead of failing fast."
        )

    async def _lookup_service_service_account(
        self,
        *,
        project_context,
        service_id: str,
    ) -> str:
        return await self._lookup_cloud_run_service_account(
            project_context=project_context,
            base_describe_cmd=[
                "run",
                "services",
                "describe",
                service_id,
                "--region",
                project_context.region,
                "--project",
                project_context.id,
            ],
            format_paths=[
                "template.serviceAccount",
                "spec.template.spec.serviceAccountName",
            ],
        )

    async def _lookup_job_service_account(
        self,
        *,
        project_context,
        job_id: str,
    ) -> str:
        return await self._lookup_cloud_run_service_account(
            project_context=project_context,
            base_describe_cmd=[
                "run",
                "jobs",
                "describe",
                job_id,
                "--region",
                project_context.region,
                "--project",
                project_context.id,
            ],
            format_paths=[
                "template.template.serviceAccount",
                "spec.template.spec.template.spec.serviceAccountName",
            ],
        )

    async def _lookup_cloud_run_service_account(
        self,
        *,
        project_context,
        base_describe_cmd: list[str],
        format_paths: list[str],
        ) -> str:
        for format_path in format_paths:
            output, code = await project_context.gcloud(
                [
                    *base_describe_cmd,
                    f"--format=value({format_path})",
                ]
            )
            if code == 0:
                normalized = output.strip()
                if normalized:
                    return normalized
        return ""

    async def _lookup_scheduler_service_account(
        self,
        *,
        project_context,
        scheduler_id: str,
    ) -> str:
        output, code = await project_context.gcloud(
            [
                "scheduler",
                "jobs",
                "describe",
                scheduler_id,
                "--location",
                project_context.region,
                "--project",
                project_context.id,
                "--format=value(httpTarget.oidcToken.serviceAccountEmail)",
            ]
        )
        if code != 0:
            return ""
        return output.strip()

    def _normalize_service_account_email(self, value: str, *, project_id: str) -> str:
        trimmed = value.strip()
        if "@" in trimmed:
            return trimmed
        if not trimmed:
            raise RuntimeError("Service account value is empty.")
        return f"{trimmed}@{project_id}.iam.gserviceaccount.com"

    async def _ensure_binding(
        self,
        *,
        project_context,
        member: str,
        role: str,
        target: Mapping[str, Any],
    ) -> bool:
        get_cmd, add_cmd, target_label = await self._build_target_commands(
            target=target,
            project_context=project_context,
            role=role,
            member=member,
        )

        policy_out, get_code = await project_context.gcloud(get_cmd)
        if get_code != 0:
            raise RuntimeError(
                f"Failed to read IAM policy for target {target_label}: {policy_out}"
            )

        unconditional_exists, conditional_exists = self._policy_binding_state(
            policy_out,
            role=role,
            member=member,
        )
        if unconditional_exists:
            project_context.log(
                f"iam-grants: binding already present for {member} role={role} target={target_label}",
                level="info",
            )
            return False
        if conditional_exists:
            raise RuntimeError(
                "Found an existing conditional IAM binding for "
                f"{member} role={role} on {target_label}. "
                "iam-grants currently manages only unconditional bindings."
            )

        add_out, add_code = await project_context.gcloud(add_cmd)
        if add_code != 0:
            raise RuntimeError(
                f"Failed to apply IAM binding for target {target_label}: {add_out}"
            )

        project_context.log(
            f"iam-grants: granted {role} on {target_label} to {member}",
            level="info",
        )
        return True

    async def _build_target_commands(
        self,
        *,
        target: Mapping[str, Any],
        project_context,
        role: str,
        member: str,
    ) -> tuple[list[str], list[str], str]:
        target_kind = target["kind"]
        project_id = str(target.get("project_id") or project_context.id)
        region = str(target.get("region") or project_context.region)

        if target_kind == "project":
            resource_id = project_id
            get_cmd = [
                "projects",
                "get-iam-policy",
                resource_id,
                "--format=json",
            ]
            add_cmd = [
                "projects",
                "add-iam-policy-binding",
                resource_id,
                "--member",
                member,
                "--role",
                role,
            ]
            return get_cmd, add_cmd, f"project:{resource_id}"

        if target_kind == "secret":
            secret_id = str(target["id"])
            get_cmd = [
                "secrets",
                "get-iam-policy",
                secret_id,
                "--project",
                project_id,
                "--format=json",
            ]
            add_cmd = [
                "secrets",
                "add-iam-policy-binding",
                secret_id,
                "--project",
                project_id,
                "--member",
                member,
                "--role",
                role,
            ]
            return get_cmd, add_cmd, f"secret:{secret_id}"

        if target_kind == "run_service":
            service_id = str(target["id"])
            get_cmd = [
                "run",
                "services",
                "get-iam-policy",
                service_id,
                "--region",
                region,
                "--project",
                project_id,
                "--format=json",
            ]
            add_cmd = [
                "run",
                "services",
                "add-iam-policy-binding",
                service_id,
                "--region",
                region,
                "--project",
                project_id,
                "--member",
                member,
                "--role",
                role,
            ]
            return get_cmd, add_cmd, f"run_service:{service_id}"

        if target_kind == "run_job":
            job_id = str(target["id"])
            get_cmd = [
                "run",
                "jobs",
                "get-iam-policy",
                job_id,
                "--region",
                region,
                "--project",
                project_id,
                "--format=json",
            ]
            add_cmd = [
                "run",
                "jobs",
                "add-iam-policy-binding",
                job_id,
                "--region",
                region,
                "--project",
                project_id,
                "--member",
                member,
                "--role",
                role,
            ]
            return get_cmd, add_cmd, f"run_job:{job_id}"

        if target_kind == "topic":
            topic_id = str(target["id"])
            get_cmd = [
                "pubsub",
                "topics",
                "get-iam-policy",
                topic_id,
                "--project",
                project_id,
                "--format=json",
            ]
            add_cmd = [
                "pubsub",
                "topics",
                "add-iam-policy-binding",
                topic_id,
                "--project",
                project_id,
                "--member",
                member,
                "--role",
                role,
            ]
            return get_cmd, add_cmd, f"topic:{topic_id}"

        if target_kind == "bucket":
            bucket_name = str(target["name"]).strip()
            bucket_resource = self._normalize_bucket_resource(bucket_name)
            get_cmd = [
                "storage",
                "buckets",
                "get-iam-policy",
                bucket_resource,
                "--project",
                project_id,
                "--format=json",
            ]
            add_cmd = [
                "storage",
                "buckets",
                "add-iam-policy-binding",
                bucket_resource,
                "--project",
                project_id,
                "--member",
                member,
                "--role",
                role,
            ]
            return get_cmd, add_cmd, f"bucket:{bucket_resource}"

        if target_kind == "service_account":
            resource = target["resource"]
            service_account_email = await self._resolve_service_account_email(
                project_context=project_context,
                principal=resource,
            )
            get_cmd = [
                "iam",
                "service-accounts",
                "get-iam-policy",
                service_account_email,
                "--project",
                project_id,
                "--format=json",
            ]
            add_cmd = [
                "iam",
                "service-accounts",
                "add-iam-policy-binding",
                service_account_email,
                "--project",
                project_id,
                "--member",
                member,
                "--role",
                role,
            ]
            return get_cmd, add_cmd, f"service_account:{service_account_email}"

        if target_kind == "custom":
            get_cmd = list(target["get_policy_command"])
            add_cmd = list(target["add_binding_command"])

            if not self._has_flag(get_cmd, "--project"):
                get_cmd.extend(["--project", project_id])
            if not self._has_flag(add_cmd, "--project"):
                add_cmd.extend(["--project", project_id])

            if not self._has_flag(get_cmd, "--format"):
                get_cmd.append("--format=json")
            if not self._has_flag(add_cmd, "--member"):
                add_cmd.extend(["--member", member])
            if not self._has_flag(add_cmd, "--role"):
                add_cmd.extend(["--role", role])

            return get_cmd, add_cmd, f"custom:project={project_id}"

        raise RuntimeError(f"Unsupported target kind: {target_kind}")

    def _policy_binding_state(
        self,
        policy_output: str,
        *,
        role: str,
        member: str,
    ) -> tuple[bool, bool]:
        if not policy_output.strip():
            return False, False
        try:
            policy = json.loads(policy_output)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Failed to parse IAM policy JSON: {exc}") from exc

        bindings = policy.get("bindings", [])
        if not isinstance(bindings, list):
            return False, False

        conditional_exists = False
        for binding in bindings:
            if not isinstance(binding, Mapping):
                continue
            if binding.get("role") != role:
                continue
            members = binding.get("members", [])
            if isinstance(members, list) and member in members:
                if "condition" in binding and binding.get("condition") is not None:
                    conditional_exists = True
                    continue
                return True, conditional_exists
        return False, conditional_exists

    def _target_identity(self, target: Mapping[str, Any], project_context) -> str:
        target_kind = target["kind"]
        project_id = str(target.get("project_id") or project_context.id)
        region = str(target.get("region") or project_context.region)
        if target_kind == "project":
            return f"project:{project_id}"
        if target_kind in {"secret", "topic"}:
            return f"{target_kind}:project={project_id}:id={target.get('id')}"
        if target_kind in {"run_service", "run_job"}:
            return (
                f"{target_kind}:project={project_id}:region={region}:id={target.get('id')}"
            )
        if target_kind == "bucket":
            return "bucket:project={project}:name={name}".format(
                project=project_id,
                name=self._normalize_bucket_resource(str(target.get("name", ""))),
            )
        if target_kind == "service_account":
            resource = target.get("resource", {})
            if not isinstance(resource, Mapping):
                return f"service_account:project={project_id}:resource=unknown"
            return (
                "service_account:project={project}:region={region}:resource={kind}:{id}".format(
                    project=project_id,
                    region=region,
                    kind=resource.get("kind"),
                    id=resource.get("id"),
                )
            )
        if target_kind == "custom":
            get_cmd = " ".join(target.get("get_policy_command", []))
            add_cmd = " ".join(target.get("add_binding_command", []))
            return f"custom:project={project_id}:get={get_cmd}|add={add_cmd}"
        return f"{target_kind}:unknown"

    def _normalize_bucket_resource(self, name: str) -> str:
        trimmed = name.strip()
        if not trimmed:
            raise RuntimeError("Bucket name is required.")
        return trimmed if trimmed.startswith("gs://") else f"gs://{trimmed}"

    def _has_flag(self, args: Iterable[str], flag_name: str) -> bool:
        for arg in args:
            if arg == flag_name or arg.startswith(flag_name + "="):
                return True
        return False

    def _parse_bool(self, value: Any, *, field_name: str) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return bool(value)
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in BOOL_TRUE_VALUES:
                return True
            if normalized in BOOL_FALSE_VALUES:
                return False
        raise RuntimeError(f"Invalid boolean for {field_name}: {value!r}")
