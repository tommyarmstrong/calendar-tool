"""
Shared data models.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Message:
    role: str  # "system" | "user" | "assistant" | "tool"
    content: str
