def require_data(context: Context) -> Context:
    return context.data

class State(ABC):
    """Abstract FSM state. Concrete states implement :meth:`run`.

    Return an event string to trigger a transition via ``TRANSITIONS``,
    or ``None`` to halt (terminal / wait states).
    """

    name: str = "STATE"

    @property
    def context(self) -> "Context":
        return self._context

    @context.setter
    def context(self, context: "Context") -> None:
        self._context = context

    @abstractmethod
    async def run(self) -> str | None: ...


class AbortMixin:
    """Convenience helper for marking the context as failed mid-flight."""

    async def abort(
        self,
        reason: str,
    ) -> None:
        ctx = _require_data(self.context)  # type: ignore[attr-defined]
        ctx.state = PlayerState.FAILED
        ctx.reason = reason
        self.context.logger.warning(  # type: ignore[attr-defined]
            "FSM abort tx=%s reason=%s", ctx.transaction_id, reason,
        )

class CollecDUTs(State):
    name: str = "COLLECT_DUTS"
    # TODO: parse the script file, collect devices
    pass

class PrepareTestSequence(State):
    name: str = "PREPARE_TEST_SEQUENCE"
    # TODO: read all uploaded configs and create a commands list for each device.
    # TODO: create a list of tuples (device, configure_commands). Check if we have enough connections for all devices.
    pass

class InitializeDUTConnections(State):
    name: str = "INITIALIZE_DUT_CONNECTIONS"
    # TODO: get required connections for collected devices from the appcontainer (_vtysh_session_store)
    # TODO: prepare a logfile and writer for each device.
    pass

class RunMonitorSessions(State):
    name: str = "RUN_MONITOR_SESSIONS"
    # TODO: runt pre-configure commands. Then run monitor sessions for collected devices in parallel.
    pass

class RunConfigureCommands(State):
    name: str = "RUN_CONFIGURE_COMMANDS"
    # TODO: run configure commands for collected devices sequentially iterating over the list of tuples (device, configure_commands).
    pass

class SaveLogs(State):
    name: str = "SAVE_LOGS"
    # TODO: save logs for collected devices sequentially iterating over the list of tuples (device, logfile) in a folder named after the transaction_id.
    pass

class End(State):
    name: str = "END"
    # TODO: end the test. cleanup if needed.
    pass

#### EXAMPLE TRANSITIONS ####
TRANSITIONS = {
    (COLLECT_DUTS, "success"): PrepareTestSequence,
    (COLLECT_DUTS, "error"): Abort,
    (PREPARE_TEST_SEQUENCE, "success"): InitializeDUTConnections,
    (PREPARE_TEST_SEQUENCE, "error"): Abort,
    (INITIALIZE_DUT_CONNECTIONS, "success"): RunMonitorSessions,
    (INITIALIZE_DUT_CONNECTIONS, "error"): Abort,
    (RUN_MONITOR_SESSIONS, "success"): RunConfigureCommands,
    (RUN_MONITOR_SESSIONS, "error"): Abort,
    (RUN_CONFIGURE_COMMANDS, "success"): SaveLogs,
}