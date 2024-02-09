import base64
import json
import os
import yaml

from cryptography.fernet import Fernet
from rich.progress import Progress
from rich.prompt import Prompt
from rich import print as rich_print

import app
from app import app
from app.app import validate_mp_connect, validate_enable, EVENTS
from app.core.command import Command, CommandContext
from app.core.func import get_file_list_by_pattern, console_clear_up
from app.mp.asset.iface_asset_group import iface_MP_Group
from app.mp.asset.iface_asset_query import iface_MP_AssetQuery
from app.mp.task.iface_task import iface_MP_Task
from app.mp.task.iface_task_credential import iface_MP_TaskCredential
from app.mp.task.iface_task_dictionary import iface_MP_TaskDictionary
from app.mp.task.iface_task_profile import iface_MP_TaskProfile
from app.mp.policy.iface_policy import iface_MP_Policy
from app.mp.template.iface_template import iface_MP_Template
from app.mp.report.iface_report_template import iface_MP_Report_Template
from app.mp.report.iface_report_task import iface_MP_Report_Task
from app.mp.dashboard.iface_dashboard import iface_MP_Dashboard
from app.mp.user.iface_user_roles import iface_MP_UserRole
from app.mp.user.iface_user import iface_MP_User
from app.mp.cmd_mp import mp


@Command.validate(validate_mp_connect)
@Command.with_help("Get MaxPatrol system information")
@Command.with_name("info")
@Command
def mp_info(_command_context: CommandContext) -> CommandContext:
    """
    MaxPatrol system information
    """
    mp_info.logger.debug("Run MaxPatrol information")
    response = app.API_MP.get(app.API_MP.url_license)
    if not response.state:
        mp_info.logger.error("MaxPatrol information load failed: {}".format(response.message))
        return CommandContext(state=False, state_msg="MaxPatrol information load failed: {}".format(response.message))
    licenses = {
        "licenses": {
            "valid": [],
            "invalid": []
        }
    }
    for item in response.message.json().get["valid"]:
        licenses["licenses"]["valid"].append(item)
    for item in response["message"].json()["invalid"]:
        licenses["licenses"]["invalid"].append(item)
    return CommandContext(context_data=licenses, data_fmt="yaml")


@Command.validate([validate_mp_connect, validate_enable])
@Command.with_help("Import MaxPatrol data from file(s). Only JSON or YAML content supported")
@Command.with_options([
    {"key": "arg", "required": True, "help": "Source filename, may be different specification types"},
    {"key": "disarm", "required": False, "help": "Run in test mode"},
    {"key": "encryption", "required": False, "help": "Import encrypted specification(s)"}
])
@Command.with_name("import")
@Command
def mp_import(command_context: CommandContext) -> CommandContext:
    """
    Import from multiple sources
    """

    # Read file content
    def read_file(path: str, encrypt: bool) -> dict | list | None:
        mp_import.logger.debug("Run mp import read file: {}".format(path))
        mode = "r"
        encoding = "utf-8"
        cipher_suite = None
        if encrypt:
            mp_import.logger.debug("With encryption")
            try:
                source_key = Prompt.ask("Secret key", password=True)
            except KeyboardInterrupt:
                print("Operation interrupted")
                return None
            code_bytes = source_key.encode("utf-8")
            secret_key = base64.urlsafe_b64encode(code_bytes.ljust(32)[:32])
            cipher_suite = Fernet(secret_key)
            mode = "rb"
            encoding = None
        try:
            with open(path, mode, encoding=encoding) as file:
                # Try to read JSON structure from file
                if encrypt:
                    try:
                        encrypted = file.read()
                        data = cipher_suite.decrypt(encrypted)
                        data = data.decode('utf-8')
                    except BaseException as er:
                        rich_print("[red]Something went wrong. Probably secret key is invalid")
                        print("Error: {}".format(er))
                        return
                else:
                    data = file.read()
            mp_import.logger.debug("Read process completed")
        except BaseException as er:
            path, name = os.path.split(path)
            rich_print("[red]Unable to read file {}".format(name))
            print("Error: {}".format(er))
            return None
        try:
            json_data = json.loads(data)
            mp_import.logger.debug("Loaded JSON from file {}".format(command_context.get_arg()),
                                   exc_info=False)
            return json_data
        except BaseException as er:
            mp_import.logger.debug("File does not contains valid JSON", exc_info=False)
            mp_import.logger.debug("Error info: {}".format(er))
            # Try to read YAML structure from file
            try:
                # Reset read cursor
                yaml_data = yaml.safe_load(data)
                mp_import.logger.debug("Loaded YAML from file {}".format(command_context.get_arg()),
                                       exc_info=False)
                return yaml_data
            except BaseException as er:
                mp_import.logger.debug("File does not contains valid YAML", exc_info=False)
                mp_import.logger.debug("Error info: {}".format(er))
                path, name = os.path.split(path)
                rich_print("[red]File {} does not contains valid JSON or YAML data".format(name))
                return

    def apply_to_specs(data: dict | list, spec: dict) -> dict | None:
        if isinstance(data, dict):
            # Check cli-mixin is present
            if not data.get("cli-mixin"):
                return spec
            if not data["cli-mixin"].get("kind"):
                return spec
            kind_key = data["cli-mixin"].get("kind")
            if not spec.get(kind_key):
                spec[kind_key] = []
            spec[kind_key].append(data)
        if isinstance(data, list):
            for itm in data:
                # Check cli-mixin is present
                if not itm.get("cli-mixin"):
                    return spec
                if not itm["cli-mixin"].get("kind"):
                    return spec
                kind_key = itm["cli-mixin"].get("kind")
                if not spec.get(kind_key):
                    spec[kind_key] = []
                spec[kind_key].append(itm)
        return spec

    # Looking multiple files
    specs = {}
    disarm = "disarm" in command_context.get_kwarg()
    mp_import.logger.debug("Disarm state: {}".format(disarm))
    targets = get_file_list_by_pattern(command_context.get_arg())
    if not targets:
        return CommandContext(state=False, state_msg="No files found")
    # If we have multiple - iterate on list
    if len(targets) > 0:
        for target in targets:
            encryption = False
            if "encryption" in command_context.get_kwarg():
                encryption = True
            # Reading files
            iterated_data = read_file(target, encryption)
            if not iterated_data:
                continue
            specs = apply_to_specs(iterated_data, specs)
    print("Found specifications for following instances:")
    for key, value in specs.items():
        print("- {} ({})".format(key, len(value)))
    try:
        decision = Prompt.ask("Are you sure to continue with import all instances? ",
                              choices=["y", "n"], default="n")
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    match decision:
        case "n":
            return CommandContext(state=False, state_msg="Operation interrupted")
    # Import credentials
    if specs.get("credential"):
        # Init credential API
        try:
            iface_cred = iface_MP_TaskCredential()
        except KeyboardInterrupt:
            return CommandContext(state=False, state_msg="Operation interrupted")
        except BaseException as err:
            return CommandContext(state=False, state_msg="MP task credential API init failed: {}".format(err))
        with Progress() as progress:
            count = len(specs.get("credential"))
            task = progress.add_task("Creating credentials...", total=count)
            for item in specs.get("credential"):
                progress.update(task, advance=1)
                response = iface_cred.create(raw_spec=item, disarm=disarm)
                if not response.state:
                    if response.message == "Operation interrupted":
                        return CommandContext(state=False, state_msg="Operation interrupted")
                    mp_import.logger.error("Failed to create credential {}: {}".format(item.get("name"),
                                                                                       response.message))
                    rich_print("[red]Failed to create credential {}: {}".format(item.get("name"),
                                                                                response.message))
                    EVENTS.push(status="Fail", action="Create", instance="Credential",
                                name=item["name"], instance_id=item["id"],
                                details=str(response.message))
                    continue
                print(response.message)
        console_clear_up()
    if specs.get("user_role"):
        # Init credential API
        try:
            iface_user_role = iface_MP_UserRole()
        except KeyboardInterrupt:
            return CommandContext(state=False, state_msg="Operation interrupted")
        except BaseException as err:
            return CommandContext(state=False, state_msg="MP task user role API init failed: {}".format(err))
        with Progress() as progress:
            count = len(specs.get("user_role"))
            task = progress.add_task("Creating user roles...", total=count)
            for item in specs.get("user_role"):
                progress.update(task, advance=1)
                response = iface_user_role.create(source_spec=item, disarm=disarm)
                if not response.state:
                    if response.message == "Operation interrupted":
                        return CommandContext(state=False, state_msg="Operation interrupted")
                    mp_import.logger.error("Failed to create user role {}: {}".format(item.get("name"),
                                                                                      response.message))
                    rich_print("[red]Failed to create user role {}: {}".format(item.get("name"),
                                                                               response.message))
                    EVENTS.push(status="Fail", action="Create", instance="User Role",
                                name=item["name"], instance_id=item["id"],
                                details=str(response.message))
                    continue
                print(response.message)
        console_clear_up()
    if specs.get("user"):
        # Init credential API
        try:
            iface_user = iface_MP_User()
        except KeyboardInterrupt:
            return CommandContext(state=False, state_msg="Operation interrupted")
        except BaseException as err:
            return CommandContext(state=False, state_msg="MP user API init failed: {}".format(err))
        with Progress() as progress:
            count = len(specs.get("user"))
            task = progress.add_task("Creating users...", total=count)
            for item in specs.get("user"):
                progress.update(task, advance=1)
                response = iface_user.create(source_spec=item, disarm=disarm)
                if not response.state:
                    if response.message == "Operation interrupted":
                        return CommandContext(state=False, state_msg="Operation interrupted")
                    mp_import.logger.error("Failed to create user {}: {}".format(item.get("name"),
                                                                                 response.message))
                    rich_print("[red]Failed to create user {}: {}".format(item.get("name"),
                                                                          response.message))
                    EVENTS.push(status="Fail", action="Create", instance="User",
                                name=item["name"], instance_id=item["id"],
                                details=str(response.message))
                    continue
                print(response.message)
        console_clear_up()
    if specs.get("dictionary"):
        try:
            iface_dict = iface_MP_TaskDictionary()
        except KeyboardInterrupt:
            return CommandContext(state=False, state_msg="Operation interrupted")
        except BaseException as err:
            mp_import.logger.error("MP task dictionary API init failed: {}".format(err))
            return CommandContext(state=False, state_msg="MP task dictionary API init failed: {}".format(err))
        with Progress() as progress:
            count = len(specs.get("dictionary"))
            task = progress.add_task("Creating dictionaries...", total=count)
            for item in specs.get("dictionary"):
                progress.update(task, advance=1)
                response = iface_dict.create(raw_spec=item, disarm=disarm)
                if not response.state:
                    if response.message == "Operation interrupted":
                        return CommandContext(state=False, state_msg="Operation interrupted")
                    mp_import.logger.error("Failed to create dictionary {}: {}".format(item.get("name"),
                                                                                       response.message))
                    rich_print("[red]Failed to create dictionary {}: {}".format(item.get("name"),
                                                                                response.message))
                    EVENTS.push(status="Fail", action="Create", instance="Dictionary",
                                name=item["name"], instance_id=item["id"],
                                details=str(response.message))
                    continue
                print(response.message)
        console_clear_up()
    if specs.get("profile"):
        try:
            iface_profile = iface_MP_TaskProfile()
        except KeyboardInterrupt:
            return CommandContext(state=False, state_msg="Operation interrupted")
        except BaseException as err:
            mp_import.logger.error("MP task profile API init failed: {}".format(err))
            return CommandContext(state=False, state_msg="MP task profile API init failed: {}".format(err))
        with Progress() as progress:
            count = len(specs.get("profile"))
            task = progress.add_task("Creating profiles...", total=count)
            for item in specs.get("profile"):
                progress.update(task, advance=1)
                response = iface_profile.create(raw_spec=item, disarm=disarm)
                if not response.state:
                    if response.message == "Operation interrupted":
                        return CommandContext(state=False, state_msg="Operation interrupted")
                    mp_import.logger.error("Failed to create profile {}: {}".format(item.get("name"),
                                                                                    response.message))
                    rich_print("[red]Failed to create profile {}: {}".format(item.get("name"), response.message))
                    EVENTS.push(status="Fail", action="Create", instance="Profile",
                                name=item["name"], instance_id=item["id"],
                                details=str(response.message))
                    continue
                print(response.message)
        console_clear_up()
    if specs.get("group"):
        try:
            iface_group = iface_MP_Group()
        except KeyboardInterrupt:
            return CommandContext(state=False, state_msg="Operation interrupted")
        except BaseException as err:
            mp_import.logger.error("MP group API init failed: {}".format(err))
            return CommandContext(state=False, state_msg="MP group API init failed: {}".format(err))
        with Progress() as progress:
            count = len(specs.get("group"))
            task = progress.add_task("Creating groups...", total=count)
            for item in specs.get("group"):
                if item.get("name") == "Root":
                    continue
                progress.update(task, advance=1)
                iface_group.reload()
                result = iface_group.create(item, disarm=disarm)
                if not result.state:
                    if result.message == "Operation interrupted":
                        return CommandContext(state=False, state_msg="Operation interrupted")
                    mp_import.logger.error("Failed to create group: {}".format(item.get("name")))
                    mp_import.logger.error(result.message)
                    rich_print("[red]Failed to create group {}: {}".format(item.get("name"), result.message))
                    EVENTS.push(status="Fail", action="Create", instance="Group",
                                name=item.get("name"), instance_id="N/A",
                                details=result.message)
                    continue
                else:
                    print("Group {} created".format(item.get("name")))
        console_clear_up()
    if specs.get("query"):
        try:
            iface_query = iface_MP_AssetQuery()
        except KeyboardInterrupt:
            return CommandContext(state=False, state_msg="Operation interrupted")
        except BaseException as err:
            mp_import.logger.error("MP asset queries API init failed: {}".format(err))
            return CommandContext(state=False, state_msg="MP asset queries API init failed: {}".format(err))
        with Progress() as progress:
            count = len(specs.get("query"))
            task = progress.add_task("Creating asset queries...", total=count)
            for item in specs.get("query"):
                # Reload query list
                iface_query.list = iface_query.reload()
                progress.update(task, advance=1)
                result = iface_query.create(item, disarm=disarm)
                if not result.state:
                    if result.message == "Operation interrupted":
                        return CommandContext(state=False, state_msg="Operation interrupted")
                    mp_import.logger.error("Failed to create query: {}".format(item.get("displayName")))
                    mp_import.logger.error(result.message)
                    rich_print("[red]Failed to create query {}: "
                               "{}".format(item.get("displayName"), result.message))
                    EVENTS.push(status="Fail", action="Create", instance="Query",
                                name=item.get("displayName"), instance_id=item.get("id"),
                                details=result.message)
                    continue
                else:
                    print("Asset query {} created".format(item.get("displayName")))
        console_clear_up()
    if specs.get("task"):
        try:
            iface_task = iface_MP_Task()
        except KeyboardInterrupt:
            return CommandContext(state=False, state_msg="Operation interrupted")
        except BaseException as err:
            mp_import.logger.error("MP task API init failed: {}".format(err))
            return CommandContext(state=False, state_msg="MP task API init failed: {}".format(err))
        drop_aec = False
        try:
            decision = Prompt.ask("Would you like to drop original AECs in tasks specs? ",
                                  choices=["y", "n"], default="y")
        except KeyboardInterrupt:
            return CommandContext(state=False, state_msg="Operation interrupted")
        match decision:
            case "y":
                drop_aec = True
        for item in specs.get("task"):
            response = iface_task.create(source_spec=item, drop_aec=drop_aec, disarm=disarm)
            if not response.state:
                if response.message == "Operation interrupted":
                    return CommandContext(state=False, state_msg="Operation interrupted")
                mp_import.logger.error("Failed to create task {}: {}".format(item.get("name"), response.message))
                rich_print("[red]Failed to create task {}: {}".format(item.get("name"), response.message))
                EVENTS.push(status="Fail", action="Create", instance="Task",
                            name=item.get("name"), instance_id=item.get("id"), details=response.message)
                continue
            print(response.message)
    if specs.get("policy_rule"):
        try:
            iface_policy = iface_MP_Policy()
        except KeyboardInterrupt:
            return CommandContext(state=False, state_msg="Operation interrupted")
        except BaseException as err:
            mp_import.logger.error("MP policy API init failed: {}".format(err))
            return CommandContext(state=False, state_msg="MP policy API init failed: {}".format(err))
        for item in specs.get("policy_rule"):
            response = iface_policy.create(source_spec=item, disarm=disarm)
            if not response.state:
                if response.message == "Operation interrupted":
                    return CommandContext(state=False, state_msg="Operation interrupted")
                mp_import.logger.error("Failed to create policy rule {}: {}".format(item.get("name"),
                                                                                    response.message))
                rich_print("[red]Failed to create policy rule {}: {}".format(item.get("name"), response.message))
                EVENTS.push(status="Fail", action="Create", instance="Rule",
                            name=item.get("name"), instance_id=item.get("id"), details=response.message)
                continue
            print(response.message)
    if specs.get("template"):
        try:
            iface_template = iface_MP_Template()
        except KeyboardInterrupt:
            return CommandContext(state=False, state_msg="Operation interrupted")
        except BaseException as err:
            mp_import.logger.error("MP template API init failed: {}".format(err))
            return CommandContext(state=False, state_msg="MP template API init failed: {}".format(err))
        for item in specs.get("template"):
            response = iface_template.create(source_spec=item, disarm=disarm)
            if not response.state:
                if response.message == "Operation interrupted":
                    return CommandContext(state=False, state_msg="Operation interrupted")
                mp_import.logger.error("Failed to create template {}: {}".format(item.get("name"),
                                                                                 response.message))
                rich_print("[red]Failed to create template {}: {}".format(item.get("name"), response.message))
                EVENTS.push(status="Fail", action="Create", instance="Template",
                            name=item.get("name"), instance_id=item.get("id"), details=response.message)
                continue
            print(response.message)
    if specs.get("report_template"):
        try:
            iface_report_template = iface_MP_Report_Template()
        except KeyboardInterrupt:
            return CommandContext(state=False, state_msg="Operation interrupted")
        except BaseException as err:
            mp_import.logger.error("MP report template API init failed: {}".format(err))
            return CommandContext(state=False, state_msg="MP report template API init failed: {}".format(err))
        for item in specs.get("report_template"):
            response = iface_report_template.create(source_spec=item, disarm=disarm)
            if not response.state:
                if response.message == "Operation interrupted":
                    return CommandContext(state=False, state_msg="Operation interrupted")
                mp_import.logger.error("Failed to create report template {}: {}".format(item.get("name"),
                                                                                        response.message))
                rich_print("[red]Failed to create report template {}: {}".format(item.get("name"), response.message))
                EVENTS.push(status="Fail", action="Create", instance="Report Template",
                            name=item.get("name"), instance_id=item.get("id"), details=response.message)
                continue
            print(response.message)
    if specs.get("report_task"):
        try:
            iface_report_task = iface_MP_Report_Task()
        except KeyboardInterrupt:
            return CommandContext(state=False, state_msg="Operation interrupted")
        except BaseException as err:
            mp_import.logger.error("MP report task API init failed: {}".format(err))
            return CommandContext(state=False, state_msg="MP report task API init failed: {}".format(err))
        for item in specs.get("report_task"):
            response = iface_report_task.create(source_spec=item, disarm=disarm)
            if not response.state:
                if response.message == "Operation interrupted":
                    return CommandContext(state=False, state_msg="Operation interrupted")
                mp_import.logger.error("Failed to create report task {}: {}".format(item.get("name"),
                                                                                    response.message))
                rich_print("[red]Failed to create report task {}: {}".format(item.get("name"), response.message))
                EVENTS.push(status="Fail", action="Create", instance="Report Task",
                            name=item.get("name"), instance_id=item.get("id"), details=response.message)
                continue
            print(response.message)
    if specs.get("dashboard"):
        try:
            iface_dashboard = iface_MP_Dashboard()
        except KeyboardInterrupt:
            return CommandContext(state=False, state_msg="Operation interrupted")
        except BaseException as err:
            mp_import.logger.error("MP dashboard API init failed: {}".format(err))
            return CommandContext(state=False, state_msg="MP dashboard API init failed: {}".format(err))
        for item in specs.get("dashboard"):
            response = iface_dashboard.create(source_spec=item, disarm=disarm)
            if not response.state:
                if response.message == "Operation interrupted":
                    return CommandContext(state=False, state_msg="Operation interrupted")
                mp_import.logger.error("Failed to create dashboard {}: {}".format(item.get("name"),
                                                                                  response.message))
                rich_print("[red]Failed to create dashboard {}: {}".format(item.get("name"),
                                                                           response.message))
                EVENTS.push(status="Fail", action="Create", instance="Dashboard",
                            name=item.get("name"), instance_id=item.get("id"), details=response.message)
                continue
            print(response.message)
    EVENTS.checkout()
    return CommandContext(state=True, state_msg="Import completed")


mp.add(mp_info)
mp.add(mp_import)
