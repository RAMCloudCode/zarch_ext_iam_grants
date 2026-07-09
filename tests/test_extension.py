import asyncio
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from zarch_ext_iam_grants.extension import Extension


class DummyContext:
    def __init__(self, *, project_id="demo-project", region="us-east4", responder=None):
        self.id = project_id
        self.region = region
        self._responder = responder or (lambda args: ("{}", 0))
        self.gcloud_calls = []
        self.logs = []

    async def gcloud(self, args):
        self.gcloud_calls.append(list(args))
        return self._responder(args)

    def log(self, message, level=None):
        self.logs.append((message, level))


def test_resolve_settings_parses_expected_shape():
    ext = Extension()
    cfg = {
        "continue_on_error": "false",
        "principal_bindings": [
            {
                "principal": {"kind": "service", "id": "cashcheck-report"},
                "grants": [
                    {
                        "role": "roles/logging.logWriter",
                        "target": {"kind": "project"},
                    },
                    {
                        "role": "roles/storage.objectViewer",
                        "target": {"kind": "bucket", "name": "demo-bucket"},
                    },
                ],
            }
        ],
    }

    resolved = ext._resolve_settings(cfg)
    assert resolved["continue_on_error"] is False
    assert resolved["enable_iamcredentials_api"] is False
    assert len(resolved["principal_bindings"]) == 1
    assert resolved["principal_bindings"][0]["principal"]["kind"] == "service"
    assert resolved["principal_bindings"][0]["grants"][1]["target"]["kind"] == "bucket"


def test_resolve_settings_defaults_to_fail_fast():
    ext = Extension()
    cfg = {
        "principal_bindings": [
            {
                "principal": {"kind": "service", "id": "cashcheck-report"},
                "grants": [
                    {"role": "roles/logging.logWriter", "target": {"kind": "project"}}
                ],
            }
        ]
    }
    resolved = ext._resolve_settings(cfg)
    assert resolved["continue_on_error"] is False


def test_resolve_settings_parses_service_account_target_and_api_enable():
    ext = Extension()
    cfg = {
        "config": {
            "continue_on_error": "false",
            "enable_iamcredentials_api": "true",
            "principal_bindings": [
                {
                    "principal": {"kind": "service", "id": "cashcheck-ingest"},
                    "grants": [
                        {
                            "role": "roles/iam.serviceAccountTokenCreator",
                            "target": {
                                "kind": "service_account",
                                "resource": {
                                    "kind": "service",
                                    "id": "cashcheck-ingest",
                                },
                            },
                        }
                    ],
                }
            ],
        }
    }

    resolved = ext._resolve_settings(cfg)

    assert resolved["enable_iamcredentials_api"] is True
    target = resolved["principal_bindings"][0]["grants"][0]["target"]
    assert target == {
        "kind": "service_account",
        "resource": {
            "kind": "service",
            "id": "cashcheck-ingest",
        },
    }


def test_resolve_settings_rejects_invalid_target_shape():
    ext = Extension()
    cfg = {
        "principal_bindings": [
            {
                "principal": {"kind": "job", "id": "cashcheck-compute"},
                "grants": [
                    {
                        "role": "roles/run.invoker",
                        "target": {"kind": "run_service"},
                    }
                ],
            }
        ]
    }

    with pytest.raises(RuntimeError, match="target.id is required"):
        ext._resolve_settings(cfg)


def test_custom_target_requires_policy_verbs():
    ext = Extension()
    cfg = {
        "principal_bindings": [
            {
                "principal": {"kind": "service", "id": "cashcheck-report"},
                "grants": [
                    {
                        "role": "roles/viewer",
                        "target": {
                            "kind": "custom",
                            "get_policy_command": ["secrets", "describe", "s1"],
                            "add_binding_command": [
                                "secrets",
                                "add-iam-policy-binding",
                                "s1",
                            ],
                        },
                    }
                ],
            }
        ]
    }
    with pytest.raises(RuntimeError, match="get_policy_command must include 'get-iam-policy'"):
        ext._resolve_settings(cfg)


def test_custom_target_rejects_member_role_or_condition_flags():
    ext = Extension()
    cfg = {
        "principal_bindings": [
            {
                "principal": {"kind": "service", "id": "cashcheck-report"},
                "grants": [
                    {
                        "role": "roles/viewer",
                        "target": {
                            "kind": "custom",
                            "get_policy_command": [
                                "secrets",
                                "get-iam-policy",
                                "s1",
                            ],
                            "add_binding_command": [
                                "secrets",
                                "add-iam-policy-binding",
                                "s1",
                                "--member=serviceAccount:bad@demo-project.iam.gserviceaccount.com",
                            ],
                        },
                    }
                ],
            }
        ]
    }
    with pytest.raises(RuntimeError, match="must not include '--member'"):
        ext._resolve_settings(cfg)


def test_build_target_commands_for_run_service_shape():
    ext = Extension()
    ctx = DummyContext(project_id="proj-123", region="us-central1")

    get_cmd, add_cmd, label = asyncio.run(ext._build_target_commands(
        target={"kind": "run_service", "id": "session"},
        project_context=ctx,
        role="roles/run.invoker",
        member="serviceAccount:svc@proj-123.iam.gserviceaccount.com",
    ))

    assert get_cmd[:4] == ["run", "services", "get-iam-policy", "session"]
    assert "--region" in get_cmd
    assert "--project" in get_cmd
    assert add_cmd[:4] == ["run", "services", "add-iam-policy-binding", "session"]
    assert "--member" in add_cmd
    assert "--role" in add_cmd
    assert label == "run_service:session"


def test_build_target_commands_for_service_account_shape():
    ext = Extension()

    def responder(args):
        if args[:4] == ["run", "services", "describe", "cashcheck-ingest"]:
            return ("cashcheck-ingest-sa@proj-123.iam.gserviceaccount.com\n", 0)
        return ("{}", 0)

    ctx = DummyContext(project_id="proj-123", region="us-central1", responder=responder)

    get_cmd, add_cmd, label = asyncio.run(ext._build_target_commands(
        target={
            "kind": "service_account",
            "resource": {"kind": "service", "id": "cashcheck-ingest"},
        },
        project_context=ctx,
        role="roles/iam.serviceAccountTokenCreator",
        member="serviceAccount:cashcheck-ingest-sa@proj-123.iam.gserviceaccount.com",
    ))

    assert get_cmd == [
        "iam",
        "service-accounts",
        "get-iam-policy",
        "cashcheck-ingest-sa@proj-123.iam.gserviceaccount.com",
        "--project",
        "proj-123",
        "--format=json",
    ]
    assert add_cmd == [
        "iam",
        "service-accounts",
        "add-iam-policy-binding",
        "cashcheck-ingest-sa@proj-123.iam.gserviceaccount.com",
        "--project",
        "proj-123",
        "--member",
        "serviceAccount:cashcheck-ingest-sa@proj-123.iam.gserviceaccount.com",
        "--role",
        "roles/iam.serviceAccountTokenCreator",
    ]
    assert label == "service_account:cashcheck-ingest-sa@proj-123.iam.gserviceaccount.com"


def test_custom_target_appends_member_role_and_project():
    ext = Extension()
    ctx = DummyContext(project_id="proj-123")

    get_cmd, add_cmd, label = asyncio.run(ext._build_target_commands(
        target={
            "kind": "custom",
            "get_policy_command": ["healthcare", "datasets", "get-iam-policy", "ds1"],
            "add_binding_command": ["healthcare", "datasets", "add-iam-policy-binding", "ds1"],
        },
        project_context=ctx,
        role="roles/viewer",
        member="serviceAccount:svc@proj-123.iam.gserviceaccount.com",
    ))

    assert get_cmd[:4] == ["healthcare", "datasets", "get-iam-policy", "ds1"]
    assert "--project" in get_cmd
    assert "--format=json" in get_cmd
    assert add_cmd[:4] == ["healthcare", "datasets", "add-iam-policy-binding", "ds1"]
    assert "--project" in add_cmd
    assert "--member" in add_cmd
    assert "--role" in add_cmd
    assert label == "custom:project=proj-123"


def test_idempotency_skips_add_when_binding_exists():
    ext = Extension()

    def responder(args):
        if args[:4] == ["run", "services", "describe", "cashcheck-report"]:
            return ("svc-sa@demo-project.iam.gserviceaccount.com\n", 0)
        if args[:3] == ["projects", "get-iam-policy", "demo-project"]:
            return (
                '{"bindings":[{"role":"roles/logging.logWriter","members":["serviceAccount:svc-sa@demo-project.iam.gserviceaccount.com"]}]}',
                0,
            )
        if args[:3] == ["projects", "add-iam-policy-binding", "demo-project"]:
            return ("should-not-run", 1)
        return ("{}", 0)

    ctx = DummyContext(responder=responder)
    cfg = {
        "continue_on_error": False,
        "principal_bindings": [
            {
                "principal": {"kind": "service", "id": "cashcheck-report"},
                "grants": [
                    {
                        "role": "roles/logging.logWriter",
                        "target": {"kind": "project"},
                    }
                ],
            }
        ],
    }

    asyncio.run(ext._apply_all_bindings(
        project_context=ctx,
        extension_configuration=cfg,
        hook_name="post_service_deploy",
    ))
    add_calls = [
        c for c in ctx.gcloud_calls if c[:3] == ["projects", "add-iam-policy-binding", "demo-project"]
    ]
    assert add_calls == []


def test_service_account_token_creator_idempotency_skips_existing_binding():
    ext = Extension()
    sa_email = "cashcheck-ingest-sa@demo-project.iam.gserviceaccount.com"
    member = f"serviceAccount:{sa_email}"

    def responder(args):
        if args[:4] == ["run", "services", "describe", "cashcheck-ingest"]:
            return (sa_email + "\n", 0)
        if args[:3] == ["iam", "service-accounts", "get-iam-policy"]:
            return (
                '{"bindings":[{"role":"roles/iam.serviceAccountTokenCreator","members":["'
                + member
                + '"]}]}',
                0,
            )
        if args[:3] == ["iam", "service-accounts", "add-iam-policy-binding"]:
            return ("should-not-run", 1)
        return ("{}", 0)

    ctx = DummyContext(responder=responder)
    cfg = {
        "continue_on_error": False,
        "principal_bindings": [
            {
                "principal": {"kind": "service", "id": "cashcheck-ingest"},
                "grants": [
                    {
                        "role": "roles/iam.serviceAccountTokenCreator",
                        "target": {
                            "kind": "service_account",
                            "resource": {
                                "kind": "service",
                                "id": "cashcheck-ingest",
                            },
                        },
                    }
                ],
            }
        ],
    }

    asyncio.run(ext._apply_all_bindings(
        project_context=ctx,
        extension_configuration=cfg,
        hook_name="post_service_deploy",
    ))
    add_calls = [
        c for c in ctx.gcloud_calls if c[:3] == ["iam", "service-accounts", "add-iam-policy-binding"]
    ]
    assert add_calls == []


def test_enable_iamcredentials_api_runs_before_empty_binding_return():
    ext = Extension()

    def responder(args):
        if args[:3] == ["services", "enable", "iamcredentials.googleapis.com"]:
            return ("ok", 0)
        return ("{}", 0)

    ctx = DummyContext(responder=responder)
    cfg = {
        "enable_iamcredentials_api": True,
        "continue_on_error": False,
        "principal_bindings": [],
    }

    asyncio.run(ext._apply_all_bindings(
        project_context=ctx,
        extension_configuration=cfg,
        hook_name="post_service_deploy",
    ))

    assert [
        "services",
        "enable",
        "iamcredentials.googleapis.com",
        "--project",
        "demo-project",
        "--quiet",
    ] in ctx.gcloud_calls


def test_lookup_service_service_account_prefers_v2_format():
    ext = Extension()

    def responder(args):
        if args[:4] == ["run", "services", "describe", "cashcheck-ingest"]:
            if "--format=value(template.serviceAccount)" in args:
                return ("cashcheck-ingest-sa@demo-project.iam.gserviceaccount.com\n", 0)
            if "--format=value(spec.template.spec.serviceAccountName)" in args:
                return ("legacy-should-not-be-used@demo-project.iam.gserviceaccount.com\n", 0)
        return ("{}", 0)

    ctx = DummyContext(responder=responder)
    resolved = asyncio.run(ext._lookup_service_service_account(
        project_context=ctx,
        service_id="cashcheck-ingest",
    ))

    assert resolved == "cashcheck-ingest-sa@demo-project.iam.gserviceaccount.com"
    legacy_calls = [
        c for c in ctx.gcloud_calls if "--format=value(spec.template.spec.serviceAccountName)" in c
    ]
    assert legacy_calls == []


def test_lookup_service_service_account_falls_back_to_legacy_format():
    ext = Extension()

    def responder(args):
        if args[:4] == ["run", "services", "describe", "cashcheck-ingest"]:
            if "--format=value(template.serviceAccount)" in args:
                return ("\n", 0)
            if "--format=value(spec.template.spec.serviceAccountName)" in args:
                return ("cashcheck-ingest-sa@demo-project.iam.gserviceaccount.com\n", 0)
        return ("{}", 0)

    ctx = DummyContext(responder=responder)
    resolved = asyncio.run(ext._lookup_service_service_account(
        project_context=ctx,
        service_id="cashcheck-ingest",
    ))

    assert resolved == "cashcheck-ingest-sa@demo-project.iam.gserviceaccount.com"
    v2_calls = [c for c in ctx.gcloud_calls if "--format=value(template.serviceAccount)" in c]
    legacy_calls = [
        c for c in ctx.gcloud_calls if "--format=value(spec.template.spec.serviceAccountName)" in c
    ]
    assert len(v2_calls) == 1
    assert len(legacy_calls) == 1


def test_lookup_job_service_account_prefers_v2_format():
    ext = Extension()

    def responder(args):
        if args[:4] == ["run", "jobs", "describe", "cashcheck-compute"]:
            if "--format=value(template.template.serviceAccount)" in args:
                return ("cashcheck-compute-sa@demo-project.iam.gserviceaccount.com\n", 0)
            if "--format=value(spec.template.spec.template.spec.serviceAccountName)" in args:
                return ("legacy-should-not-be-used@demo-project.iam.gserviceaccount.com\n", 0)
        return ("{}", 0)

    ctx = DummyContext(responder=responder)
    resolved = asyncio.run(ext._lookup_job_service_account(
        project_context=ctx,
        job_id="cashcheck-compute",
    ))

    assert resolved == "cashcheck-compute-sa@demo-project.iam.gserviceaccount.com"
    legacy_calls = [
        c
        for c in ctx.gcloud_calls
        if "--format=value(spec.template.spec.template.spec.serviceAccountName)" in c
    ]
    assert legacy_calls == []


def test_lookup_job_service_account_falls_back_to_legacy_format():
    ext = Extension()

    def responder(args):
        if args[:4] == ["run", "jobs", "describe", "cashcheck-compute"]:
            if "--format=value(template.template.serviceAccount)" in args:
                return ("\n", 0)
            if "--format=value(spec.template.spec.template.spec.serviceAccountName)" in args:
                return ("cashcheck-compute-sa@demo-project.iam.gserviceaccount.com\n", 0)
        return ("{}", 0)

    ctx = DummyContext(responder=responder)
    resolved = asyncio.run(ext._lookup_job_service_account(
        project_context=ctx,
        job_id="cashcheck-compute",
    ))

    assert resolved == "cashcheck-compute-sa@demo-project.iam.gserviceaccount.com"
    v2_calls = [
        c for c in ctx.gcloud_calls if "--format=value(template.template.serviceAccount)" in c
    ]
    legacy_calls = [
        c
        for c in ctx.gcloud_calls
        if "--format=value(spec.template.spec.template.spec.serviceAccountName)" in c
    ]
    assert len(v2_calls) == 1
    assert len(legacy_calls) == 1


def test_service_account_lookup_fails_when_resource_has_no_sa():
    ext = Extension()

    def responder(args):
        if args[:4] == ["run", "services", "describe", "cashcheck-report"]:
            return ("not found", 1)
        return ("{}", 0)

    ctx = DummyContext(responder=responder)
    cfg = {
        "continue_on_error": False,
        "principal_bindings": [
            {
                "principal": {"kind": "service", "id": "cashcheck-report"},
                "grants": [
                    {
                        "role": "roles/logging.logWriter",
                        "target": {"kind": "project"},
                    }
                ],
            }
        ],
    }

    with pytest.raises(RuntimeError, match="Resource lookup returned no service account"):
        asyncio.run(ext._apply_all_bindings(
            project_context=ctx,
            extension_configuration=cfg,
            hook_name="post_service_deploy",
        ))


def test_continue_on_error_true_skips_unresolved_principal_and_continues():
    ext = Extension()

    def responder(args):
        if args[:4] == ["run", "services", "describe", "missing-service"]:
            return ("not found", 1)
        if args[:4] == ["run", "services", "describe", "cashcheck-report"]:
            if "--format=value(template.serviceAccount)" in args:
                return ("cashcheck-report-sa@demo-project.iam.gserviceaccount.com\n", 0)
            return ("\n", 0)
        if args[:3] == ["projects", "get-iam-policy", "demo-project"]:
            return ('{"bindings":[]}', 0)
        if args[:3] == ["projects", "add-iam-policy-binding", "demo-project"]:
            return ("ok", 0)
        return ("{}", 0)

    ctx = DummyContext(responder=responder)
    cfg = {
        "continue_on_error": True,
        "principal_bindings": [
            {
                "principal": {"kind": "service", "id": "missing-service"},
                "grants": [
                    {
                        "role": "roles/logging.logWriter",
                        "target": {"kind": "project"},
                    }
                ],
            },
            {
                "principal": {"kind": "service", "id": "cashcheck-report"},
                "grants": [
                    {
                        "role": "roles/logging.logWriter",
                        "target": {"kind": "project"},
                    }
                ],
            },
        ],
    }

    asyncio.run(ext._apply_all_bindings(
        project_context=ctx,
        extension_configuration=cfg,
        hook_name="post_service_deploy",
    ))

    add_calls = [
        c for c in ctx.gcloud_calls if c[:3] == ["projects", "add-iam-policy-binding", "demo-project"]
    ]
    assert len(add_calls) == 1

    warning_logs = [
        msg
        for msg, level in ctx.logs
        if level == "warn" and "failed to resolve service account for service:missing-service" in msg
    ]
    assert warning_logs


def test_scoped_dedupe_keeps_distinct_project_targets():
    ext = Extension()

    def responder(args):
        if args[:4] == ["run", "services", "describe", "cashcheck-report"]:
            return ("svc-sa@demo-project.iam.gserviceaccount.com\n", 0)
        if args[:3] == ["secrets", "get-iam-policy", "s1"]:
            return ('{"bindings":[]}', 0)
        if args[:3] == ["secrets", "add-iam-policy-binding", "s1"]:
            return ("ok", 0)
        return ("{}", 0)

    ctx = DummyContext(responder=responder)
    cfg = {
        "continue_on_error": False,
        "principal_bindings": [
            {
                "principal": {"kind": "service", "id": "cashcheck-report"},
                "grants": [
                    {
                        "role": "roles/secretmanager.secretAccessor",
                        "target": {"kind": "secret", "id": "s1", "project_id": "proj-a"},
                    },
                    {
                        "role": "roles/secretmanager.secretAccessor",
                        "target": {"kind": "secret", "id": "s1", "project_id": "proj-b"},
                    },
                ],
            }
        ],
    }

    asyncio.run(ext._apply_all_bindings(
        project_context=ctx,
        extension_configuration=cfg,
        hook_name="post_service_deploy",
    ))
    add_calls = [
        c
        for c in ctx.gcloud_calls
        if c[:3] == ["secrets", "add-iam-policy-binding", "s1"]
    ]
    assert len(add_calls) == 2
    assert add_calls[0][4] == "proj-a"
    assert add_calls[1][4] == "proj-b"


def test_conditional_binding_fails_closed():
    ext = Extension()

    def responder(args):
        if args[:4] == ["run", "services", "describe", "cashcheck-report"]:
            return ("svc-sa@demo-project.iam.gserviceaccount.com\n", 0)
        if args[:3] == ["projects", "get-iam-policy", "demo-project"]:
            return (
                '{"bindings":[{"role":"roles/logging.logWriter","members":["serviceAccount:svc-sa@demo-project.iam.gserviceaccount.com"],"condition":{"title":"exp"}}]}',
                0,
            )
        if args[:3] == ["projects", "add-iam-policy-binding", "demo-project"]:
            return ("should-not-run", 1)
        return ("{}", 0)

    ctx = DummyContext(responder=responder)
    cfg = {
        "continue_on_error": False,
        "principal_bindings": [
            {
                "principal": {"kind": "service", "id": "cashcheck-report"},
                "grants": [
                    {
                        "role": "roles/logging.logWriter",
                        "target": {"kind": "project"},
                    }
                ],
            }
        ],
    }

    with pytest.raises(RuntimeError, match="conditional IAM binding"):
        asyncio.run(ext._apply_all_bindings(
            project_context=ctx,
            extension_configuration=cfg,
            hook_name="post_service_deploy",
        ))
    add_calls = [
        c for c in ctx.gcloud_calls if c[:3] == ["projects", "add-iam-policy-binding", "demo-project"]
    ]
    assert add_calls == []


def test_warn_and_continue_allows_subsequent_grants():
    ext = Extension()

    def responder(args):
        if args[:4] == ["run", "services", "describe", "cashcheck-report"]:
            return ("svc-sa@demo-project.iam.gserviceaccount.com\n", 0)
        if args[:3] == ["secrets", "get-iam-policy", "s1"]:
            return ('{"bindings":[]}', 0)
        if args[:3] == ["secrets", "add-iam-policy-binding", "s1"]:
            return ("boom", 1)
        if args[:3] == ["projects", "get-iam-policy", "demo-project"]:
            return ('{"bindings":[]}', 0)
        if args[:3] == ["projects", "add-iam-policy-binding", "demo-project"]:
            return ("ok", 0)
        return ("{}", 0)

    ctx = DummyContext(responder=responder)
    cfg = {
        "continue_on_error": True,
        "principal_bindings": [
            {
                "principal": {"kind": "service", "id": "cashcheck-report"},
                "grants": [
                    {
                        "role": "roles/secretmanager.secretAccessor",
                        "target": {"kind": "secret", "id": "s1"},
                    },
                    {
                        "role": "roles/logging.logWriter",
                        "target": {"kind": "project"},
                    },
                ],
            }
        ],
    }

    asyncio.run(ext._apply_all_bindings(
        project_context=ctx,
        extension_configuration=cfg,
        hook_name="post_service_deploy",
    ))
    project_add_calls = [
        c for c in ctx.gcloud_calls if c[:3] == ["projects", "add-iam-policy-binding", "demo-project"]
    ]
    assert project_add_calls, "subsequent grants should still execute"


def test_fail_fast_raises_on_grant_error():
    ext = Extension()

    def responder(args):
        if args[:4] == ["run", "services", "describe", "cashcheck-report"]:
            return ("svc-sa@demo-project.iam.gserviceaccount.com\n", 0)
        if args[:3] == ["secrets", "get-iam-policy", "s1"]:
            return ('{"bindings":[]}', 0)
        if args[:3] == ["secrets", "add-iam-policy-binding", "s1"]:
            return ("boom", 1)
        return ("{}", 0)

    ctx = DummyContext(responder=responder)
    cfg = {
        "continue_on_error": False,
        "principal_bindings": [
            {
                "principal": {"kind": "service", "id": "cashcheck-report"},
                "grants": [
                    {
                        "role": "roles/secretmanager.secretAccessor",
                        "target": {"kind": "secret", "id": "s1"},
                    }
                ],
            }
        ],
    }

    with pytest.raises(RuntimeError, match="Failed to apply IAM binding"):
        asyncio.run(ext._apply_all_bindings(
            project_context=ctx,
            extension_configuration=cfg,
            hook_name="post_service_deploy",
        ))


def test_scheduler_hook_calls_apply_bindings(monkeypatch):
    ext = Extension()
    ctx = DummyContext()
    cfg = {"continue_on_error": True, "principal_bindings": []}
    captured = {}

    async def fake_apply_all_bindings(*, project_context, extension_configuration, hook_name):
        captured["project_context"] = project_context
        captured["extension_configuration"] = extension_configuration
        captured["hook_name"] = hook_name

    monkeypatch.setattr(ext, "_apply_all_bindings", fake_apply_all_bindings)
    asyncio.run(ext.post_scheduler_deploy(ctx, cfg))

    assert captured["project_context"] is ctx
    assert captured["extension_configuration"] is cfg
    assert captured["hook_name"] == "post_scheduler_deploy"
