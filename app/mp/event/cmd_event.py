import copy
import re
import uuid

from datetime import datetime
import os
import yaml
import base64

from cryptography.fernet import Fernet
from rich.prompt import Prompt

from app.core.command import Command, CommandContext
from app.mp.cmd_mp import mp
from app.mp.mp.cmd import validate_siem
from app.app import validate_mp_connect, get_string_from_fmt, validate_enable, EVENTS
from app.core.func import console_clear_up, validate_pipe, get_file_list_by_pattern
from app.mp.asset.iface_asset import iface_MP_Asset
from app.mp.asset.iface_asset_group import iface_MP_Group
from app.mp.asset.iface_asset_scan import iface_MP_Scan
from app.mp.asset.iface_asset_scope import iface_MP_Scope

from rich import print as rich_print
from rich.progress import Progress


# MaxPatrol Asset Tree instance
@Command.with_help("MaxPatrol Event commands tree")
@Command.with_name("event")
@Command
def mp_event(_command_context: CommandContext) -> CommandContext:
    """
    Event tree root
    """
    return CommandContext(state=False, state_msg="Wrong command")


mp.add(mp_event)
