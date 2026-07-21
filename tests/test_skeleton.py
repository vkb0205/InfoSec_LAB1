"""Initial smoke tests for the Mini Vault project skeleton."""


def test_project_skeleton_imports() -> None:
    import src.errors  # noqa: F401
    import src.core.vault  # noqa: F401
    import src.auth.service  # noqa: F401
    import src.kv.service  # noqa: F401
    import src.transit.service  # noqa: F401
    import src.storage.repository  # noqa: F401
