class SecauditError(Exception):
    """Base error for the engine."""


class ScopeError(SecauditError):
    """An operation was refused by the scope/authorization policy."""


class PathError(ScopeError):
    """A path failed validation (outside scope, symlink escape, bad characters)."""
