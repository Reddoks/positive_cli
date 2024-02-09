from rich.progress import Progress
from rich import print as rich_print
from rich.prompt import Prompt

from app.app import validate_mp_connect, validate_enable, EVENTS
from app.core.command import Command, CommandContext
from app.core.func import validate_pipe, console_clear_up
from app.mp.func import func_check_mixin
from app.mp.task.iface_task_credential import iface_MP_TaskCredential

from app.mp.task.cmd_task_root import mp_task


@Command.with_help("MaxPatrol credential commands tree")
@Command.with_name("credential")
@Command
def mp_task_credential(_command_context: CommandContext) -> CommandContext:
    """
    Task credential tree root
    """
    return CommandContext(state=False, state_msg="Wrong command")


@Command.validate(validate_mp_connect)
@Command.with_help("Get MaxPatrol task credentials list")
@Command.with_name("list")
@Command
def mp_task_credential_list(command_context: CommandContext) -> CommandContext:
    """
    Task credential list
    """
    mp_task_credential_list.logger.debug("Run mp task credential list")
    try:
        iface_cred = iface_MP_TaskCredential()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_task_credential_list.logger.error("MP task credential API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP task credential API init failed: {}".format(err))
    if isinstance(iface_cred.list, list):
        return command_context.instead(context_data=iface_cred.list, data_fmt="table",
                                       data_transform=iface_cred.reduce_list,
                                       data_islist_transform=True)
    else:
        return command_context.instead(context_data=iface_cred.list, data_fmt="table",
                                       data_transform=iface_cred.reduce_list)


@Command.validate(validate_mp_connect)
@Command.with_options([
    {"key": "arg", "required": False, "help": "Credential ID or name"},
])
@Command.with_help("Get MaxPatrol task credential information")
@Command.with_name("info")
@Command
def mp_task_credential_info(command_context: CommandContext) -> CommandContext:
    """
    Task credential information
    """
    mp_task_credential_info.logger.debug("Run mp task credential info")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["type", "id", "name", "description"]
        },
        {
            "type": "dict",
            "fields": ["type", "id", "name", "description"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_task_credential_info.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_cred = iface_MP_TaskCredential()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_task_credential_info.logger.error("MP task credential API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP task credential API init failed: {}".format(err))
    credential_info = False
    if command_context.context_data:
        mp_task_credential_info.logger.debug("Processing context data")
        if isinstance(command_context.context_data, str):
            credential_info = iface_cred.info(pattern=command_context.context_data)
        elif isinstance(command_context.context_data, dict):
            credential_info = iface_cred.info(dct=command_context.context_data)
        else:
            credential_info = iface_cred.info(lst=command_context.context_data)
        if not credential_info.state:
            mp_task_credential_info.logger.debug("No credential information found")
            return CommandContext(state=False, state_msg=credential_info.message)
        else:
            credential_info = credential_info.message
    if command_context.get_arg():
        mp_task_credential_info.logger.debug("Processing argument data")
        credential_info = iface_cred.info(pattern=command_context.get_arg())
        if not credential_info.state:
            mp_task_credential_info.logger.debug("No credential information found")
            return CommandContext(state=False, state_msg=credential_info.message)
        else:
            credential_info = credential_info.message
    if credential_info:
        EVENTS.checkout()
        return command_context.instead(context_data=credential_info, data_fmt="yaml",
                                       data_transform=iface_MP_TaskCredential.reduce_info,
                                       data_islist_transform=True, force_transform=False, table_transform=True)
    else:
        EVENTS.checkout()
        return CommandContext(state=False, state_msg="No credential information found")


@Command.validate([validate_mp_connect, validate_enable, validate_pipe])
@Command.with_options([
    {"key": "disarm", "required": False, "help": "Run in test mode"},
])
@Command.with_help("Create MaxPatrol scanning profile from specification")
@Command.with_name("create")
@Command
def mp_task_credential_create(command_context: CommandContext) -> CommandContext:
    """
    Task credential create
    """
    mp_task_credential_create.logger.debug("Run mp task credential create")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["type", "name", "description"]
        },
        {
            "type": "dict",
            "fields": ["type", "name", "description"]
        }
    ])
    if not valid:
        mp_task_credential_create.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    # Check mixin
    mixin = func_check_mixin(data=command_context.context_data, kind="credential")
    if not mixin:
        mp_task_credential_create.logger.error("Mixin validation failed")
        return CommandContext(state=False, state_msg="Mixin validation failed - wrong specification?")
    disarm = "disarm" in command_context.get_kwarg()
    mp_task_credential_create.logger.debug("Disarm state: {}".format(disarm))
    # Init credential API
    try:
        iface_cred = iface_MP_TaskCredential()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        return CommandContext(state=False, state_msg="MP task credential API init failed: {}".format(err))
    # Looking for list of credential specs
    if isinstance(command_context.context_data, list):
        with Progress() as progress:
            count = len(command_context.context_data)
            task = progress.add_task("Creating credentials...", total=count)
            for item in command_context.context_data:
                progress.update(task, advance=1)
                response = iface_cred.create(raw_spec=item, disarm=disarm)
                if not response.state:
                    if response.message == "Operation interrupted":
                        return CommandContext(state=False, state_msg="Operation interrupted")
                    mp_task_credential_create.logger.error("Failed to create credential: {}".format(response.message))
                    rich_print("[red]Failed to create credential: {}".format(response.message))
                    EVENTS.push(status="Fail", action="Create", instance="Credential",
                                name=item.get("name"), instance_id=item.get("id"),
                                details=str(response.message))
                    continue
        console_clear_up()
    else:
        response = iface_cred.create(raw_spec=command_context.context_data, disarm=disarm)
        if not response.state:
            mp_task_credential_create.logger.error("Failed to create credential: {}".format(response.message))
            EVENTS.push(status="Fail", action="Create", instance="Credential",
                        name=command_context.context_data.get("name"),
                        instance_id=command_context.context_data.get("id"),
                        details=str(response.message))
            rich_print("[red]Failed to create credential: {}".format(response.message))
    EVENTS.checkout()
    mp_task_credential_create.logger.debug("Credential creation completed")
    return CommandContext(state=True)


@Command.validate([validate_mp_connect, validate_enable])
@Command.with_options([
    {"key": "arg", "required": False, "help": "Credential ID or name regex"},
    {"key": "quiet", "required": False, "help": "Delete without confirmation"},
    {"key": "disarm", "required": False, "help": "Run in test mode"},
])
@Command.with_help("Delete MaxPatrol task credential")
@Command.with_name("delete")
@Command
def mp_task_credential_delete(command_context: CommandContext) -> CommandContext:
    """
    Task credential delete
    """
    mp_task_credential_delete.logger.debug("Run mp task credential delete")
    quiet = False
    confirm_all = False
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["type", "id", "name", "description"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_task_credential_delete.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_cred = iface_MP_TaskCredential()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_task_credential_delete.logger.error("MP task credential API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP task credential API init failed: {}".format(err))
    if "quiet" in command_context.get_kwarg():
        mp_task_credential_delete.logger.debug("Quiet mode")
        quiet = True
    if "disarm" in command_context.get_kwarg():
        mp_task_credential_delete.logger.debug("Disarm mode")
        disarm = True
        quiet = True
    else:
        disarm = False
    credential_info = False
    if command_context.context_data:
        if isinstance(command_context.context_data, str):
            credential_info = iface_cred.info(pattern=command_context.context_data)
        if isinstance(command_context.context_data, list):
            credential_info = iface_cred.info(lst=command_context.context_data)
        if not credential_info.state:
            mp_task_credential_delete.logger.debug("No credential information found")
            return CommandContext(state=False, state_msg="No credential information found")
    if command_context.get_arg():
        credential_info = iface_cred.info(pattern=command_context.get_arg())
        if not credential_info.state:
            mp_task_credential_delete.logger.debug("No credential information found")
            return CommandContext(state=False, state_msg="No credential information found")
    if not credential_info:
        mp_task_credential_delete.logger.debug("No credential information found")
        return CommandContext(state=False, state_msg="No credential information found")
    credential_info = credential_info.message
    for item in credential_info:
        if not quiet and not confirm_all:
            try:
                decision = Prompt.ask("Are you sure to delete credential {}? ".format(item.get("name")),
                                      choices=["y", "n", "a"], default="n")
            except KeyboardInterrupt:
                return CommandContext(state=False, state_msg="Operation interrupted")
            match decision:
                case "n":
                    continue
                case "a":
                    confirm_all = True
        response = iface_cred.delete(item.get("id"), disarm=disarm)
        if response.state:
            print("MaxPatrol credential {} deleted".format(item.get("name")))
            mp_task_credential_delete.logger.info("MaxPatrol credential {} deleted".format(item.get("name")))
            continue
        else:
            return CommandContext(parent=command_context.parent, state=False,
                                  state_msg=response.message)
    EVENTS.checkout()
    return CommandContext(state=True)


mp_task_credential.add(mp_task_credential_list)
mp_task_credential.add(mp_task_credential_info)
mp_task_credential.add(mp_task_credential_create)
mp_task_credential.add(mp_task_credential_delete)
mp_task.add(mp_task_credential)
