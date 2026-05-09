from __future__ import annotations
from abc import ABC, abstractmethod
from mcpmap.models import Server, Finding


class BaseCheck(ABC):
    id: str = "BASE"
    intrusive: bool = False  # set True for INJECT/SSRF/anything that mutates target state

    @abstractmethod
    async def run(self, server: Server) -> Finding | None:
        ...
