from __future__ import annotations

try:
    import boto3  # type: ignore
except ImportError:  # pragma: no cover
    class _MissingBoto3:
        class Session:  # type: ignore[no-redef]
            def __init__(self, *args, **kwargs) -> None:
                raise RuntimeError("boto3 is required for AWS collectors; install it via backend/requirements.txt")

    boto3 = _MissingBoto3()  # type: ignore[assignment]

__all__ = ["boto3"]
