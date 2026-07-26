"""Import smoke tests for the Mini Vault skeleton and Feature 0.1 modules."""


def test_imports_smoke() -> None:
    import main  # noqa: F401
    import src.errors  # noqa: F401
    import src.crypto_utils  # noqa: F401
    import src.core.vault  # noqa: F401
    import src.storage.repository  # noqa: F401
    import src.kv.service  # noqa: F401
    import src.transit.service  # noqa: F401
