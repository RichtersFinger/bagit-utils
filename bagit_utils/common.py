
"""Common definitions."""

from typing import Optional, Any
from dataclasses import dataclass, field


def quote_list(data: list[str], quote: Optional[str] = None) -> str:
    """Returns `data` reformatted into enumeration of quoted values."""
    return ", ".join(
        map(lambda d: f"""{quote or "'"}{d}{quote or "'"}""", data)
    )


@dataclass
class Issue:
    """
    Record class for validation issues.

    Keyword arguments:
    level -- issue severity (one of 'info', 'warning', and 'error')
    message -- issue description
    origin -- issue origin identifier
    """

    level: str
    message: str
    origin: Optional[str] = None


@dataclass
class ValidationReport:
    """Record class for validation reports."""

    valid: Optional[bool] = None
    issues: list[Issue] = field(default_factory=list)
    bag: Optional[Any] = None  # instance of Bag
