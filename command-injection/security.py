import re
import shlex
import subprocess
from typing import List, Tuple

from models import CommandType


def sanitize_input_regex(input_str: str) -> str:
    """Sanitize input by removing dangerous characters using regex"""
    dangerous_chars = r"[;&|><`$\{\}\(\)\n]"
    return re.sub(dangerous_chars, "", input_str)


def escape_shell_input(input_str: str) -> str:
    """Escape shell metacharacters in input"""
    return shlex.quote(input_str)


def execute_safely_with_subprocess(command: str, shell=False) -> Tuple[str, str, int]:
    """
    Execute command safely using subprocess
    Returns: (stdout, stderr, return_code)
    """
    try:
        if shell:
            # Still dangerous, only use for demonstration of vulnerable endpoint
            result = subprocess.run(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        else:
            # Split command into parts for safer execution
            command_parts = shlex.split(command)
            result = subprocess.run(
                command_parts,
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        return (result.stdout, result.stderr, result.returncode)
    except Exception as e:
        return ("", str(e), -1)


def get_mapped_command(command_type: CommandType, args: str = None) -> List[str]:
    """Map predefined commands to their executable forms"""
    command_map = {
        CommandType.LS: ["ls"],
        CommandType.PING: ["ping", "-c", "4"],
        CommandType.WHOAMI: ["whoami"],
    }

    base_command = command_map[command_type]
    if args and command_type == CommandType.PING:
        return base_command + [args]
    return base_command
