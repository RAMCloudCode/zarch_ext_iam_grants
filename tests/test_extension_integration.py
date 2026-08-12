import asyncio
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from zarch_ext_iam_grants.extension import Extension


class InMemoryIamContext:
    """Integration-style fake context with in-memory IAM policies and no external side effects."""

    def __init__(self, *, project_id="demo-project", region="us-east4"):
        self.id = project_id
        self.region = region
        self.logs = []
        self.gcloud_calls = []
        self._service_sas = {}
        self._job_sas = {}
        self._scheduler_sas = {}
        self._policies = {}
        self._failing_targets = set()

    def set_service_account(self, *, kind: str, resource_id: str, email: str) -> None:
        if kind == "service":
            self._service_sas[resource_id] = email
            return
        if kind == "job":
            self._job_sas[resource_id] = email
            return
        if kind == "scheduler":
            self._scheduler_sas[resource_id] = email
            return
        raise ValueError(f"Unknown kind: {kind}")

    def fail_add_for(self, target_key: tuple[str, str, str]) -> None:
        self._failing_targets.add(target_key)

    def log(self, message, level=None):
        self.logs.append((message, level))

    async def gcloud(self, args):
        self.gcloud_calls.append(list(args))

        # Discovery calls
        if args[:3] == ["run", "services", "describe"]:
            service_id = args[3]
            email = self._service_sas.get(service_id)
            if not email:
                return ("not found", 1)
            return (email + "\n", 0)
        if args[:3] == ["run", "jobs", "describe"]:
            job_id = args[3]
            email = self._job_sas.get(job_id)
            if not email:
                return ("not found", 1)
            return (email + "\n", 0)
        if args[:3] == ["scheduler", "jobs", "describe"]:
            scheduler_id = args[3]
            email = self._scheduler_sas.get(scheduler_id)
            if not email:
                return ("not found", 1)
            return (email + "\n", 0)

        # Project IAM
        if args[:2] == ["projects", "get-iam-policy"]:
            project_id = args[2]
            return (self._policy_json(("project", project_id, "")), 0)
        if args[:2] == ["projects", "add-iam-policy-binding"]:
            project_id = args[2]
            key = ("project", project_id, "")
            return self._apply_add_binding(key, args)

        # Secret IAM
        if args[:2] == ["secrets", "get-iam-policy"]:
            secret_id = args[2]
            project_id = self._flag_value(args, "--project")
            return (self._policy_json(("secret", project_id, secret_id)), 0)
        if args[:2] == ["secrets", "add-iam-policy-binding"]:
            secret_id = args[2]
            project_id = self._flag_value(args, "--project")
            key = ("secret", project_id, secret_id)
            return self._apply_add_binding(key, args)

        return ("{}", 0)

    def _policy_json(self, key: tuple[str, str, str]) -> str:
        policy = self._policies.setdefault(key, {"bindings": []})
        return json.dumps(policy)

    def _apply_add_binding(self, key: tuple[str, str, str], args: list[str]) -> tuple[str, int]:
        if key in self._failing_targets:
            return ("injected failure", 1)

        member = self._flag_value(args, "--member")
        role = self._flag_value(args, "--role")
        policy = self._policies.setdefault(key, {"bindings": []})
        for binding in policy["bindings"]:
            if binding.get("role") != role:
                continue
            members = binding.setdefault("members", [])
            if member not in members:
                members.append(member)
            return ("ok", 0)
        policy["bindings"].append({"role": role, "members": [member]})
        return ("ok", 0)

    def _flag_value(self, args: list[str], flag: str) -> str:
        for idx, arg in enumerate(args):
            if arg == flag and idx + 1 < len(args):
                return args[idx + 1]
            if arg.startswith(flag + "="):
                return arg.split("=", 1)[1]
        raise AssertionError(f"Missing expected flag {flag} in args: {args}")


def test_integration_end_to_end_idempotent_for_service_hook():
    ext = Extension()
    ctx = InMemoryIamContext()
    ctx.set_service_account(
        kind="service",
        resource_id="example-report-service",
        email="example-report-service-sa@demo-project.iam.gserviceaccount.com",
    )

    cfg = {
        "config": {
            "continue_on_error": False,
            "principal_bindings": [
                {
                    "principal": {"kind": "service", "id": "example-report-service"},
                    "grants": [
                        {"role": "roles/logging.logWriter", "target": {"kind": "project"}},
                        {
                            "role": "roles/secretmanager.secretAccessor",
                            "target": {"kind": "secret", "id": "db-password"},
                        },
                    ],
                }
            ],
        }
    }

    asyncio.run(ext.post_service_deploy(ctx, cfg))
    adds_after_first = [
        c for c in ctx.gcloud_calls if "add-iam-policy-binding" in c
    ]
    assert len(adds_after_first) == 2

    asyncio.run(ext.post_service_deploy(ctx, cfg))
    adds_after_second = [
        c for c in ctx.gcloud_calls if "add-iam-policy-binding" in c
    ]
    assert len(adds_after_second) == 2, "second run should be idempotent"


def test_integration_continue_on_error_true_keeps_progress():
    ext = Extension()
    ctx = InMemoryIamContext()
    ctx.set_service_account(
        kind="service",
        resource_id="example-report-service",
        email="example-report-service-sa@demo-project.iam.gserviceaccount.com",
    )
    ctx.fail_add_for(("secret", "demo-project", "db-password"))

    cfg = {
        "config": {
            "continue_on_error": True,
            "principal_bindings": [
                {
                    "principal": {"kind": "service", "id": "example-report-service"},
                    "grants": [
                        {
                            "role": "roles/secretmanager.secretAccessor",
                            "target": {"kind": "secret", "id": "db-password"},
                        },
                        {"role": "roles/logging.logWriter", "target": {"kind": "project"}},
                    ],
                }
            ],
        }
    }

    asyncio.run(ext.post_service_deploy(ctx, cfg))
    project_adds = [
        c for c in ctx.gcloud_calls if c[:3] == ["projects", "add-iam-policy-binding", "demo-project"]
    ]
    assert project_adds, "project grant should still apply after prior failure"


def test_integration_continue_on_error_false_stops_progress():
    ext = Extension()
    ctx = InMemoryIamContext()
    ctx.set_service_account(
        kind="service",
        resource_id="example-report-service",
        email="example-report-service-sa@demo-project.iam.gserviceaccount.com",
    )
    ctx.fail_add_for(("secret", "demo-project", "db-password"))

    cfg = {
        "config": {
            "continue_on_error": False,
            "principal_bindings": [
                {
                    "principal": {"kind": "service", "id": "example-report-service"},
                    "grants": [
                        {
                            "role": "roles/secretmanager.secretAccessor",
                            "target": {"kind": "secret", "id": "db-password"},
                        },
                        {"role": "roles/logging.logWriter", "target": {"kind": "project"}},
                    ],
                }
            ],
        }
    }

    with pytest.raises(RuntimeError, match="Failed to apply IAM binding"):
        asyncio.run(ext.post_service_deploy(ctx, cfg))

    project_adds = [
        c for c in ctx.gcloud_calls if c[:3] == ["projects", "add-iam-policy-binding", "demo-project"]
    ]
    assert not project_adds, "fail-fast should stop subsequent grants"
