import json

from app import app

from rich import print
import os
from pathlib import Path
from tinydb import TinyDB, Query
import tinydb_encrypted_jsonstorage as tae

from rich import print as rich_print
from rich.progress import Progress
from app.settings import iface_Settings

import base64

import app.completer
from app.core.prompt import input_prompt
from app.core.command import core, CommandContext


class ProbeTask:
    def __init__(self, pipeline: dict):
        self.overall_state = True
        self.failed_steps = []
        self.pipeline = pipeline
        self.name = ""
        self.steps_count = 0
        self.details = False

    def probe(self, build=False):
        # Getting pipeline parameters
        self.name = self.pipeline.get("name")
        self.steps_count = len(self.pipeline.get("steps"))
        self.details = self.pipeline.get("details")
        rich_print("[yellow]Run probing pipeline: {}".format(self.name))
        rich_print("[bright_black]Total probes: {}".format(self.steps_count))
        print("--")
        # Run probes
        if not self.details:
            with Progress() as progress:
                task = progress.add_task("Running probes...", total=self.steps_count)
                for item in self.pipeline.get("steps"):
                    if item.get("probe") == "command":
                        state, probe_result = self.command_probe(item, build=build, details=self.details)
                    if build:
                        print("State: {}, Type: {}, Fmt: {}".format(probe_result.get("state"),
                                                                    probe_result.get("type"),
                                                                    probe_result.get("fmt")))
                        continue
                    if not state:
                        self.overall_state = False
                        self.failed_steps.append(item)
                        print("[red]Step failed. Failure trace:")
                        for itm in probe_result:
                            print(itm)
                    progress.update(task, advance=1)
        else:
            for item in self.pipeline.get("steps"):
                if item.get("probe") == "command":
                    state, probe_result = self.command_probe(item, build=build, details=self.details)
                    if build:
                        rich_print("[green] BUILD")
                        print("State: {}, Type: {}, Fmt: {}".format(probe_result.get("state"),
                                                                    probe_result.get("type"),
                                                                    probe_result.get("fmt")))
                        continue
                    if state:
                        rich_print("[green] OK")
                    else:
                        rich_print("[red] FAIL")
                        self.overall_state = False
                        self.failed_steps.append(item)
                        rich_print("[yellow]Failure trace:")
                        if probe_result == "Bool result":
                            rich_print("[red]Bool Result")
                        if probe_result == "Core failure":
                            rich_print("[red]Bool Result")
                        if not probe_result == "Bool result" or probe_result == "Core failure":
                            for itm in probe_result:
                                print(itm)
        print(" ")
        if self.overall_state:
            rich_print("[green]Testing pipline {} finished with success".format(self.pipeline.get("name")))
            return True
        else:
            rich_print("[red]Testing pipline {} finished with failures".format(self.pipeline.get("name")))
            rich_print("[red]Failed steps: {}".format(len(self.failed_steps)))
            return False

    @staticmethod
    def command_probe(step: dict, build=False, details=True) -> [bool, str | dict | None]:
        failures = ["Executed command line: {}".format(step.get("command"))]
        state = True
        # Execute command
        result_context = exec_cmd_string(step.get("command"))
        if details:
            rich_print("Command probe. Probing string: [bright_cyan]{} ...".format(step.get("command")), end="")
        if build:
            return True, {
                "state": result_context.state,
                "type": type(result_context.context_data),
                "fmt": result_context.data_fmt,
                "data": result_context.context_data
            }
        if isinstance(result_context, bool) and not step.get("state"):
            return True, "Bool result"
        elif isinstance(result_context, bool) and step.get("state"):
            return False, "Bool result"
        if not result_context.state:
            if result_context.state_msg == "Core failure":
                return False, "Core failure"
        # Analyze
        if result_context.state != step.get("state"):
            state = False
            failures.append("Wrong context state: {} instead {}".format(result_context.state, step.get("state")))
        if "type" in step:
            if isinstance(step.get("type"), list):
                value = step.get("type")
            else:
                value = [step.get("type")]
            valid = False
            for item in value:
                if type(result_context.context_data) == item:
                    valid = True
            if not valid:
                state = False
                failures.append("Wrong context type: {} instead {}".format(type(result_context.context_data),
                                                                           step.get("type")))
        if "fmt" in step:
            if isinstance(step.get("fmt"), list):
                value = step.get("fmt")
            else:
                value = [step.get("fmt")]
            valid = False
            for item in value:
                if result_context.data_fmt == item:
                    valid = True
            if not valid:
                state = False
                failures.append("Wrong context format: {} instead {}".format(result_context.data_fmt,
                                                                             step.get("fmt")))
        if "reduce" in step:
            if ((not result_context.data_transform and step.get("reduce")) or
                    (result_context.data_transform and not step.get("reduce"))):
                state = False
                failures.append("Wrong context reducer: {} instead {}".format(result_context.data_transform,
                                                                              step.get("reduce")))
        if not state:
            failures.append("Context data: {}".format(str(result_context.__dict__)))
            return False, failures
        return True, " "


class ContextCondition:
    """
    Testing condition class
    """

    def __init__(self, target_state=None, context_data_type=None, context_fmt=None, context_reduce=False,
                 echo_context=False):
        self.target_state = target_state
        self.context_data_type = context_data_type
        self.context_fmt = context_fmt
        self.context_reduce = context_reduce
        self.echo = echo_context

    # Run test probe method
    def probe(self, context: CommandContext) -> ([bool, str]):
        """
        Test runner
        :return: Result and message
        """
        result = True
        message = ""
        if self.echo:
            if context:
                if context.__dict__:
                    print(context.__dict__)
            else:
                print("Context: {}".format(context))
        if context:
            if context.state != self.target_state:
                result = False
                message = "      Wrong state: {}".format(context.state)
            if self.context_data_type:
                if isinstance(self.context_data_type, list):
                    is_valid = False
                    for item in self.context_data_type:
                        if isinstance(context.context_data, item):
                            is_valid = True
                    if not is_valid:
                        result = False
                        message = ("      Wrong context data type: {}\n"
                                   "      Data: {}".format(type(context.context_data), context.context_data))
                else:
                    if not isinstance(context.context_data, self.context_data_type):
                        result = False
                        message = ("      Wrong context data type: {}\n"
                                   "      Data: {}".format(type(context.context_data), context.context_data))
            if self.context_fmt:
                if isinstance(self.context_fmt, list):
                    is_valid = False
                    for item in self.context_fmt:
                        if context.data_fmt == item:
                            is_valid = True
                    if not is_valid:
                        result = False
                        message = "      Wrong format: {}".format(context.data_fmt)
                else:
                    if context.data_fmt != self.context_fmt:
                        result = False
                        message = "      Wrong format: {}".format(context.data_fmt)
            if context.data_transform and not self.context_reduce:
                result = False
                message = "      Reducer is present - expecting: No"
            if not context.data_transform and self.context_reduce:
                result = False
                message = "      Reducer is missing - expecting: Yes"
        else:
            if self.target_state and self.context_data_type:
                result = False
                message = "Failed context"
            else:
                result = True
        return result, message


def func_probe(func: any, params: dict, expect: dict | list) -> None:
    """
    Function test
    :param func: testing function
    :param params: params for function
    :param expect: expected result
    """

    def check_result(reslt: dict | list, expct: dict | list):
        if reslt == expct:
            return True
        return False

    print("Params: {}".format(params))
    print("Trying to run {}...".format(func.__name__), end="")
    try:
        result = func(params)
    except BaseException as err:
        print("[bold red]FAIL[/bold red]")
        print(err)
        return
    if isinstance(expect, list):
        for item in expect:
            good = check_result(result, item)
            if good:
                break
    else:
        good = check_result(result, expect)
        if not good:
            print("[bold red]FAIL[/bold red]")
            print("Result: {}".format(result))
            print("Expect: {}".format(expect))
        else:
            print("[bold green]OK[/bold green]")
            print("Result: {}".format(result))


def exec_cmd_string(cmd_string: str) -> CommandContext:
    result_context = None
    try:
        # Looking for chain
        if '&&' in cmd_string:
            prompt_chain = cmd_string.split('&&')
            for item in prompt_chain:
                command = item.strip()
                result_context = core(command_context=CommandContext(tail_string=command))
        else:
            result_context = core(command_context=CommandContext(tail_string=cmd_string))
        return result_context
    except Exception as err:
        print("[bold red]FAIL[/bold red]")
        print("Core failure:")
        print(err)
        return CommandContext(state=False, state_msg="Core failure")


def prompt_probe(name: str, prompt_string: str, target_state=None, target_context_type=None, target_fmt=None,
                 target_reduce=False, echo_context=False, run_before=False):  # noqa
    """
    Command line command test
    :param name: Test name
    :param prompt_string: Command line string
    :param target_state: Expected context state
    :param target_context_type: Expected context type
    :param target_fmt: Expected format
    :param target_reduce: Expected reduce presence
    :param echo_context: Output context or not
    """
    result_context = None
    try:
        # Looking for chain
        if '&&' in prompt_string:
            prompt_chain = prompt_string.split('&&')
            for item in prompt_chain:
                command = item.strip()
                result_context = core(command_context=CommandContext(tail_string=command))
        else:
            result_context = core(command_context=CommandContext(tail_string=prompt_string))
    except Exception as err:
        print("[bold red]FAIL[/bold red]")
        print("Core failure:")
        print(err)
        return

    conditions = ContextCondition(target_state=target_state, context_data_type=target_context_type,
                                  context_fmt=target_fmt, context_reduce=target_reduce, echo_context=echo_context)
    result, message = conditions.probe(result_context)
    if result:
        print("   Run {}...".format(name), end="")
        print("[bold green]OK[/bold green]")
    else:
        print("   Run {}...".format(name), end="")
        print("[bold red]FAIL[/bold red]")
        print("   Details:")
        print(message)
    return result_context


def probing_auth():
    """
    API authentication
    """
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

    app.HISTORY_PATH = os.path.join(app.SETTINGS.data["history_path"], '.history.encrypted')

    result = exec_cmd_string("mp api connect Home Box")
    if result.state:
        rich_print("[green]Connection success")
    else:
        rich_print("[red]Connection failed: {}".format(result.state_msg))


def api_auth():
    """
    API authentication
    """
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

    app.HISTORY_PATH = os.path.join(app.SETTINGS.data["history_path"], '.history.encrypted')

    prompt_probe(
        name="Command: mp api connect ",
        prompt_string='mp api connect Home Box',
        target_state=True,
        run_before=True
    )
