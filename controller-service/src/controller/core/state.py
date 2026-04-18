"""Application container: lifespan-scoped services for the controller app."""

from __future__ import annotations

import logging

from controller.core.settings import Settings
from controller.services.ssh.session_store import VtyshSessionStore


class AppContainer:
    """Holds shared settings and service singletons for one app instance."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.logger = logging.getLogger("controller")
        self._vtysh_session_store = VtyshSessionStore()
        #: Session ids created at startup from ``settings.dut_ssh_targets`` (see ``GET /dut/vtysh/sessions``).
        self.bootstrap_session_ids: set[str] = set()

    @property
    def vtysh_session_store(self) -> VtyshSessionStore:
        return self._vtysh_session_store

    def apply_settings(self, new_settings: Settings) -> None:
        """Replace in-memory settings after config file changes (active sessions unchanged)."""
        self.settings = new_settings

    async def shutdown(self) -> None:
        await self._vtysh_session_store.close_all()
