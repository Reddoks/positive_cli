import logging
import os
import datetime
import sys
from pathlib import Path
from tinydb import TinyDB, Query
import tinydb_encrypted_jsonstorage as tae

from prompt_toolkit.history import History
from cryptography.fernet import Fernet
from typing import Iterable
from rich import print as rich_print

import base64

import app.completer
from app.core.prompt import Prompt, input_prompt
from app.core.command import core, CommandContext, Command
from app.core.func import fmt_std_output, get_string_from_fmt, json_setter
from app.settings.iface_settings import iface_Settings

app.ENABLE_STATUS = ''

app.CONTEXT = None
app.LAST_CONTEXT = None
app.CONTEXT_OFFSET = 0


def run(args: str) -> None:
    """
    Main function
    """
    logger = logging.getLogger("core")
    logger.debug("CLI Version: {}".format(app.VERSION))
    if "--disarm" in args:
        app.app.GLOBAL_DISARM = True
        args = args.replace("--disarm", "")
    if len(args) > 0:
        app.ARG_RUN = True
        logger.info("Running from arguments: {}".format(args))
        if '&&' in args:
            logger.debug("Chain found in prompt string. Running chain")
            prompt_chain = args.split('&&')
            for item in prompt_chain:
                command = item.strip()
                result_context = core(command_context=CommandContext(tail_string=command))
                fmt_std_output(result_context)
        else:
            result_context = core(command_context=CommandContext(tail_string=args))
            fmt_std_output(result_context)
    else:
        rich_print("[bright_black]Positive CLI using encryption to store local data.")
        rich_print("[bright_black]If you are started CLI first time, enter and remember CLI secret")
        key_source = input_prompt("Please enter CLI secret: ", is_password=True)

        code_bytes = key_source.encode("utf-8")
        app.SECRET_KEY = base64.urlsafe_b64encode(code_bytes.ljust(32)[:32])

        # DB Init
        db_path = os.path.join(Path.home(), 'pt_cli.encrypted')
        app.DB = TinyDB(encryption_key=key_source, path=db_path, storage=tae.EncryptedJSONStorage)
        app.DBQUERY = Query()
        app.SETTINGS = iface_Settings(db=app.DB, dbquery=app.DBQUERY)

        app.HISTORY_PATH = os.path.join(app.SETTINGS.data.get("history_path"), '.history.encrypted')
        # Validate logging level value
        log_level = "INFO"
        if (app.SETTINGS.data.get("log_level") == "DEBUG" or app.SETTINGS.data.get("log_level") == "ERROR"
                or app.SETTINGS.data.get("log_level") == "INFO"):
            log_level = app.SETTINGS.data.get("log_level")
        else:
            rich_print("[red]Logging level is incorrect: {}. Set to INFO".format(app.SETTINGS.data.get("log_level")))
        logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s:\t%(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p',  # level="DEBUG")
                            filename=os.path.join(app.SETTINGS.data.get("log_path"), "pt_cli.log"),
                            level=log_level)

        prompt = Prompt(completer=app.completer.completer, style=app.completer.style, history_file=app.HISTORY_PATH,
                        welcome_msg="\nWelcome to Positive CLI!\nPlease, don`t use in "
                                    "production environment without testing.",
                        prefix_constructor=prefix)
        prompt.run()


def prefix() -> list:
    """
    CLI Prefix constructor
    """
    command_prompt = [
        ('class:context', "[")
    ]
    if app.PROFILE_MP:
        command_prompt.append(tuple(('class:object', 'MP(' + str(app.PROFILE_MP) + ')')))
    if app.PROFILE_NAD:
        if len(command_prompt) > 1:
            command_prompt.append(tuple(('class:object', ' ')))
        command_prompt.append(tuple(('class:object', 'NAD')))
    command_prompt.append(tuple(('class:context', "] ")))
    command_prompt.append(tuple(('class:label', app.ENABLE_STATUS + "pt > ")))
    return command_prompt


@Command.with_help("Enable potential dangerous commands")
@Command.with_name("enable")
@Command
def hlpr_enable(_command_context: CommandContext) -> CommandContext:
    """
    Enable helper
    """
    logger = logging.getLogger("core.cmd")
    app.ENABLE_STATUS = "#"
    logger.warning("Non restricted mode enabled")
    rich_print("[bright_cyan]Non-restricted mode enabled. Be careful")
    return CommandContext(state=True)


@Command.with_help("Disable potential dangerous commands")
@Command.with_name("disable")
@Command
def hlpr_disable(_command_context: CommandContext) -> CommandContext:
    """
    Disable helper
    """
    logger = logging.getLogger("core.cmd")
    app.ENABLE_STATUS = ""
    logger.warning("Restricted mode activated")
    rich_print("[bright_cyan]Restricted mode activated")
    return CommandContext(state=True)


core.add(hlpr_enable)
core.add(hlpr_disable)


def validate_enable(_command: Command, _context: CommandContext) -> bool:
    """
    Enable state validator
    """
    if app.ENABLE_STATUS == "" and _context.tail_string != "--help" and _context.tail_string != "help":
        rich_print("[yellow]Can be used only in enabled mode")
        return False
    return True


# Only if MaxPatrol connected
def validate_mp_connect(_command: Command, _context: CommandContext) -> bool:
    """
    Connection state validator
    """
    if not app.PROFILE_MP and _context.tail_string != "--help" and _context.tail_string != "help":
        rich_print("[yellow]Can be used only when API connected")
        return False
    return True


# Summary collector
class EventCollector:
    def __init__(self):
        """
        CLI event collector
        """
        self.events = []

    def push(self, status: str, action: str, instance: str, name: str, instance_id: str, details: str) -> None:
        """
        Push event to current stack
        """
        # Looks for duplicates
        event = {
            "action": action,
            "status": status,
            "instance": instance,
            "name": name,
            "id": instance_id,
            "details": details
        }
        exist = False
        for item in self.events:
            if item == event:
                exist = True
        if not exist:
            self.events.append(event)

    def checkout(self) -> None:
        """
        Release events stack
        """
        if len(self.events) > 0:
            print("-----")
            print("Summary:")
            print(get_string_from_fmt(self.events, "table"))
            self.events = []


class EncryptedFileHistory(History):
    """
    :class:`.History` class that stores all strings in a file.
    """

    def __init__(self, filename: str) -> None:
        self.filename = filename
        super().__init__()

    def load_history_strings(self) -> Iterable[str]:
        strings: list[str] = []
        lines: list[str] = []

        def add() -> None:
            if lines:
                # Join and drop trailing newline.
                string = "".join(lines)

                strings.append(string)

        if os.path.exists(self.filename):
            cipher_suite = Fernet(app.SECRET_KEY)
            try:
                with open(self.filename, "rb") as f:
                    for line in f:
                        line = line[:-1]
                        decrypted = cipher_suite.decrypt(line)
                        clear_line = decrypted.decode("utf-8")
                        cont_split = clear_line.split("\n")
                        for ln in cont_split:
                            if ln.startswith("+"):
                                lines.append(ln[1:])
                            else:
                                add()
                                lines = []
                    add()
            except BaseException as err:
                rich_print("[red]Unable to decrypt History database. "
                           "Probably you entered wrong encryption secret.")
                print(err)
                f.close()
                os._exit(1)

# Reverse the order, because newest items have to go first.
        return reversed(strings)

    def store_string(self, string: str) -> None:
        # Save to file.
        cipher_suite = Fernet(app.SECRET_KEY)
        with open(self.filename, "ab") as f:
            def write(t: bytes) -> None:
                f.write(t)
                f.write('\n'.encode('utf-8'))

            container = ""
            container += "\n# %s\n" % datetime.datetime.now()
            for line in string.split("\n"):
                container += "+%s\n" % line
            encrypted = cipher_suite.encrypt(container.encode("utf-8"))
            write(encrypted)


# Event Collector
EVENTS = EventCollector()
