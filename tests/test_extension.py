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

    def gcloud(self, args):
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

    get_cmd, add_cmd, label = ext._build_target_commands(
        target={"kind": "run_service", "id": "session"},
        project_context=ctx,
        role="roles/run.invoker",
        member="serviceAccount:svc@proj-123.iam.gserviceaccount.com",
    )

    assert get_cmd[:4] == ["run", "services", "get-iam-policy", "session"]
    assert "--region" in get_cmd
    assert "--project" in get_cmd
    assert add_cmd[:4] == ["run", "services", "add-iam-policy-binding", "session"]
    assert "--member" in add_cmd
    assert "--role" in add_cmd
    assert label == "run_service:session"


def test_custom_target_appends_member_role_and_project():
    ext = Extension()
    ctx = DummyContext(project_id="proj-123")

    get_cmd, add_cmd, label = ext._build_target_commands(
        target={
            "kind": "custom",
            "get_policy_command": ["healthcare", "datasets", "get-iam-policy", "ds1"],
            "add_binding_command": ["healthcare", "datasets", "add-iam-policy-binding", "ds1"],
        },
        project_context=ctx,
        role="roles/viewer",
        member="serviceAccount:svc@proj-123.iam.gserviceaccount.com",
    )

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

    ext._apply_all_bindings(
        project_context=ctx,
        extension_configuration=cfg,
        hook_name="post_service_deploy",
    )
    add_calls = [
        c for c in ctx.gcloud_calls if c[:3] == ["projects", "add-iam-policy-binding", "demo-project"]
    ]
    assert add_calls == []


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
        ext._apply_all_bindings(
            project_context=ctx,
            extension_configuration=cfg,
            hook_name="post_service_deploy",
        )


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

    ext._apply_all_bindings(
        project_context=ctx,
        extension_configuration=cfg,
        hook_name="post_service_deploy",
    )
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
        ext._apply_all_bindings(
            project_context=ctx,
            extension_configuration=cfg,
            hook_name="post_service_deploy",
        )
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

    ext._apply_all_bindings(
        project_context=ctx,
        extension_configuration=cfg,
        hook_name="post_service_deploy",
    )
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
        ext._apply_all_bindings(
            project_context=ctx,
            extension_configuration=cfg,
            hook_name="post_service_deploy",
        )


def test_scheduler_hook_calls_apply_bindings(monkeypatch):
    ext = Extension()
    ctx = DummyContext()
    cfg = {"continue_on_error": True, "principal_bindings": []}
    captured = {}

    def fake_apply_all_bindings(*, project_context, extension_configuration, hook_name):
        captured["project_context"] = project_context
        captured["extension_configuration"] = extension_configuration
        captured["hook_name"] = hook_name

    monkeypatch.setattr(ext, "_apply_all_bindings", fake_apply_all_bindings)
    ext.post_scheduler_deploy(ctx, cfg)

    assert captured["project_context"] is ctx
    assert captured["extension_configuration"] is cfg
    assert captured["hook_name"] == "post_scheduler_deploy"
