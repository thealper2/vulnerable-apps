from enum import Enum
from typing import Optional

from pydantic import BaseModel, constr, validator


class CommandType(str, Enum):
    """Enum for allowed command types in whitelist approach"""

    LS = "ls"
    PING = "ping"
    WHOAMI = "whoami"


class CommandRequest(BaseModel):
    """Base model for command execution requests"""

    command: str

    @validator("command")
    def command_not_empty(cls, v):
        if not v.strip():
            raise ValueError("Command cannot be empty")
        return v.strip()


class WhitelistCommandRequest(CommandRequest):
    """Request model for whitelist endpoint with additional validation"""

    @validator("command")
    def command_in_whitelist(cls, v):
        allowed_commands = [cmd.value for cmd in CommandType]
        if v not in allowed_commands:
            raise ValueError(
                f"Command not allowed. Allowed commands: {', '.join(allowed_commands)}"
            )
        return v


class LengthRestrictedRequest(CommandRequest):
    """Request model with length restriction"""

    command: constr(max_length=20)


class BlacklistKeywordsRequest(CommandRequest):
    """Request model with blacklisted keywords validation"""

    @validator("command")
    def check_blacklisted_keywords(cls, v):
        blacklist = ["rm", ";", "&&", "||", ">", "<", "|", "&"]
        for keyword in blacklist:
            if keyword in v:
                raise ValueError(f"Input contains blacklisted keyword: {keyword}")
        return v


class MappedCommandRequest(BaseModel):
    """Request model for command mapping endpoint"""

    command_type: CommandType
    args: Optional[constr(max_length=50)] = None
