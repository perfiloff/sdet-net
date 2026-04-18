from abc import ABC, abstractmethod


class RouterClient(ABC):
    """Abstract router client interface for executing commands on remote devices."""

    @abstractmethod
    async def login(self):
        """Establish connection to the router."""
        pass
    
    async def get_shell(self):
        """Get an interactive shell session."""
        raise NotImplementedError("Shell access not implemented for this router client.")
    
    async def configure(self, commands: list[str]):
        """Execute configuration commands on the router."""
        raise NotImplementedError("Configuration mode not implemented for this router client.")
    
    async def show(self, command: str) -> str:
        """Execute a show command and return the output."""
        raise NotImplementedError("Show command execution not implemented for this router client.")
    
    async def logout(self):
        """Close the connection to the router."""
        pass
    