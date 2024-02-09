from rich.progress import Progress
from rich import print as rich_print
from rich.prompt import Prompt

from app.app import validate_mp_connect, validate_enable, EVENTS
from app.core.command import Command, CommandContext
from app.core.func import validate_pipe, console_clear_up
from app.mp.func import func_check_mixin
from app.mp.task.iface_task_dictionary import iface_MP_TaskDictionary

from app.mp.task.cmd_task_root import mp_task


@Command.with_help("MaxPatrol dictionaries commands tree")
@Command.with_name("dictionary")
@Command
def mp_task_dictionary(_command_context: CommandContext) -> CommandContext:
    """
    Task dictionary tree root
    """
    return CommandContext(state=False, state_msg="Wrong command")


@Command.validate(validate_mp_connect)
@Command.with_options([
    {"key": "user_only", "required": False, "help": "Get only custom dictionaries"}
])
@Command.with_help("Get MaxPatrol task dictionaries list")
@Command.with_name("list")
@Command
def mp_task_dictionary_list(command_context: CommandContext) -> CommandContext:
    """
    Task dictionary list
    """
    mp_task_dictionary_list.logger.debug("Run mp task dictionary list")
    try:
        iface_dict = iface_MP_TaskDictionary()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_task_dictionary_list.logger.error("MP task dictionary API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP task dictionary API init failed: {}".format(err))
    dictionary_list = iface_dict.list
    if "user_only" in command_context.get_kwarg():
        dictionary_list = iface_dict.remove_builtin(dictionary_list)
    return command_context.instead(context_data=dictionary_list, data_fmt="table")


@Command.validate(validate_mp_connect)
@Command.with_options([
    {"key": "arg", "required": False, "help": "Dictionary ID or name"}
])
@Command.with_help("Get MaxPatrol task dictionary information")
@Command.with_name("info")
@Command
def mp_task_dictionary_info(command_context: CommandContext) -> CommandContext:
    """
    Task dictionary information
    """
    mp_task_dictionary_info.logger.debug("Run mp task dictionary info")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "name", "isSystem"]
        },
        {
            "type": "dict",
            "fields": ["id", "name", "isSystem"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_task_dictionary_info.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_dict = iface_MP_TaskDictionary()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_task_dictionary_info.logger.error("MP task dictionary API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP task dictionary API init failed: {}".format(err))
    dictionary_info = False
    if command_context.context_data:
        mp_task_dictionary_info.logger.debug("Processing context data")
        if isinstance(command_context.context_data, str):
            dictionary_info = iface_dict.info(pattern=command_context.context_data)
        elif isinstance(command_context.context_data, dict):
            dictionary_info = iface_dict.info(dct=command_context.context_data)
        else:
            dictionary_info = iface_dict.info(lst=command_context.context_data)
        if not dictionary_info.state:
            mp_task_dictionary_info.logger.debug("No dictionary information found")
            return CommandContext(state=False, state_msg="No dictionary information found")
    if command_context.get_arg():
        mp_task_dictionary_info.logger.debug("Processing argument data")
        dictionary_info = iface_dict.info(pattern=command_context.get_arg())
        if not dictionary_info.state:
            mp_task_dictionary_info.logger.debug("No dictionary information found")
            return CommandContext(state=False, state_msg="No dictionary information found")
    if dictionary_info:
        dictionary_info = dictionary_info.message
        EVENTS.checkout()
        return command_context.instead(context_data=dictionary_info, data_fmt="yaml",
                                       data_transform=iface_MP_TaskDictionary.reduce_info,
                                       data_islist_transform=True, force_transform=False,
                                       table_transform=True)
    else:
        EVENTS.checkout()
        return CommandContext(state=False, state_msg="No dictionary information found")


@Command.validate([validate_mp_connect, validate_enable, validate_pipe])
@Command.with_options([
    {"key": "disarm", "required": False, "help": "Run in test mode"},
])
@Command.with_help("Create MaxPatrol dictionary from specification")
@Command.with_name("create")
@Command
def mp_task_dictionary_create(command_context: CommandContext) -> CommandContext:
    """
    Create dictionary from specification
    """
    mp_task_dictionary_create.logger.debug("Run mp task dictionary create")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "name", "isSystem", "content"]
        },
        {
            "type": "dict",
            "fields": ["id", "name", "isSystem", "content"]
        }
    ])
    if not valid:
        mp_task_dictionary_create.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    # Check mixin
    mixin = func_check_mixin(data=command_context.context_data, kind="dictionary", params={})
    if not mixin:
        mp_task_dictionary_create.logger.error("Mixin validation failed")
        return CommandContext(state=False, state_msg="Mixin validation failed - wrong specification?")
    disarm = "disarm" in command_context.get_kwarg()
    mp_task_dictionary_create.logger.debug("Disarm state: {}".format(disarm))
    try:
        iface_dict = iface_MP_TaskDictionary()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_task_dictionary_create.logger.error("MP task dictionary API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP task dictionary API init failed: {}".format(err))
    # Looking for list of profile specs
    if isinstance(command_context.context_data, list):
        with Progress() as progress:
            count = len(command_context.context_data)
            task = progress.add_task("Creating dictionaries...", total=count)
            for item in command_context.context_data:
                progress.update(task, advance=1)
                response = iface_dict.create(raw_spec=item, disarm=disarm)
                if not response.state:
                    if response.message == "Operation interrupted":
                        return CommandContext(state=False, state_msg="Operation interrupted")
                    mp_task_dictionary_create.logger.error("Failed to create dictionary: {}".format(response.message))
                    rich_print("[red]Failed to create dictionary: {}".format(response.message))
                    EVENTS.push(status="Fail", action="Create", instance="Dictionary",
                                name=item.get("name"), instance_id=item.get("id"),
                                details=str(response.message))
                    continue
                print(response.message)
        console_clear_up()
    else:
        response = iface_dict.create(raw_spec=command_context.context_data, disarm=disarm)
        if not response.state:
            mp_task_dictionary_create.logger.error("Failed to create dictionary: {}".format(response.message))
            rich_print("[red]Failed to create dictionary: {}".format(response.message))
            EVENTS.push(status="Fail", action="Create", instance="Dictionary",
                        name=command_context.context_data.get("name"),
                        instance_id=command_context.context_data.get("id"),
                        details=str(response.message))
    EVENTS.checkout()
    mp_task_dictionary_create.logger.debug("Dictionary creation completed")
    return CommandContext(state=True)


@Command.validate([validate_mp_connect, validate_enable])
@Command.with_options([
    {"key": "arg", "required": False, "help": "Dictionary ID or name"},
    {"key": "quiet", "required": False, "help": "Delete without confirmation"},
    {"key": "disarm", "required": False, "help": "Run in test mode"},
])
@Command.with_help("Delete MaxPatrol dictionary")
@Command.with_name("delete")
@Command
def mp_task_dictionary_delete(command_context: CommandContext) -> CommandContext:
    """
    Delete dictionary
    """
    mp_task_dictionary_delete.logger.debug("Run mp dictionary delete")
    quiet = False
    confirm_all = False
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "name", "isSystem"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_task_dictionary_delete.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_dict = iface_MP_TaskDictionary()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_task_dictionary_delete.logger.error("MP task profile API init failed: {}".format(err))
        return CommandContext(state=False)
    if command_context.get_kwarg():
        if "quiet" in command_context.get_kwarg():
            mp_task_dictionary_delete.logger.debug("Quiet mode")
            quiet = True
    disarm = "disarm" in command_context.get_kwarg()
    if disarm:
        mp_task_dictionary_delete.logger.debug("Disarm mode")
        quiet = True
    dictionary_info = False
    if command_context.context_data:
        if isinstance(command_context.context_data, str):
            dictionary_info = iface_dict.info(pattern=command_context.context_data)
        if isinstance(command_context.context_data, list):
            dictionary_info = iface_dict.info(lst=command_context.context_data)
        if not dictionary_info.state:
            mp_task_dictionary_delete.logger.debug("No dictionary information found")
            return CommandContext(state=False, state_msg="No dictionary information found")
    if command_context.get_arg():
        dictionary_info = iface_dict.info(pattern=command_context.get_arg())
        if not dictionary_info.state:
            mp_task_dictionary_delete.logger.debug("No dictionary information found")
            return CommandContext(state=False, state_msg="No dictionary information found")
    if not dictionary_info:
        mp_task_dictionary_delete.logger.debug("No dictionary information found")
        return CommandContext(state=False, state_msg="No dictionary information found")
    dictionary_info = dictionary_info.message
    for item in dictionary_info:
        if item.get("isSystem"):
            rich_print("[yellow]Dictionary {} is system dictionary. Skip.".format(item.get("name")))
            mp_task_dictionary_delete.logger.debug("Dictionary {} is system dictionary. Skip.".format(item.get("name")))
            continue
        if not quiet and not confirm_all:
            try:
                decision = Prompt.ask("Are you sure to delete dictionary {}? ".format(item.get("name")),
                                      choices=["y", "n", "a"], default="n")
            except KeyboardInterrupt:
                return CommandContext(state=False, state_msg="Operation interrupted")
            match decision:
                case "n":
                    continue
                case "a":
                    confirm_all = True
        response = iface_dict.delete(item.get("id"), disarm=disarm)
        if response.state:
            print("MaxPatrol dictionary {} deleted".format(item.get("name")))
            mp_task_dictionary_delete.logger.info("MaxPatrol dictionary {} deleted".format(item.get("name")))
            continue
        else:
            return CommandContext(parent=command_context.parent, state=False,
                                  state_msg=response.message)
    return CommandContext(state=True)


mp_task_dictionary.add(mp_task_dictionary_list)
mp_task_dictionary.add(mp_task_dictionary_info)
mp_task_dictionary.add(mp_task_dictionary_create)
mp_task_dictionary.add(mp_task_dictionary_delete)
mp_task.add(mp_task_dictionary)
