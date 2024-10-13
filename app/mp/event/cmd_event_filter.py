import time

from rich.progress import Progress
from rich.prompt import Prompt
from rich import print as rich_print

from app.app import EVENTS
from app.app import validate_mp_connect, validate_enable
from app.core.command import Command, CommandContext
from app.core.func import validate_pipe, console_clear_up
from app.mp.func import func_check_mixin
from app.mp.mp.cmd import validate_siem
from app.mp.event.iface_event_filter import iface_MP_EventFilter
from app.mp.event.cmd_event import mp_event


# MaxPatrol Event Filter Tree instance
@Command.with_help("MaxPatrol event filter query commands tree")
@Command.with_name("filter")
@Command
def mp_event_filter(_command_context: CommandContext) -> CommandContext:
    """
    Event filters tree root
    """
    return CommandContext(state=False, state_msg="Wrong command")


@Command.validate([validate_mp_connect, validate_siem])
@Command.with_help("Get event filters list")
@Command.with_options([
    {"key": "arg", "required": False, "help": "Root filter list element ID or name"},
    {"key": "user_only", "required": False, "help": "Get only user filters"}
])
@Command.with_name("list")
@Command
def mp_event_filter_list(command_context: CommandContext) -> CommandContext:
    """
    Event filters list
    """
    mp_event_filter_list.logger.debug("Run mp event filter list")
    try:
        iface_filter = iface_MP_EventFilter()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_event_filter_list.logger.error("MP event filters API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP event filters API init failed: {}".format(err))
    try:
        time.sleep(2)
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    if command_context.get_arg():
        event_filter = iface_filter.get_by_pattern(pattern=command_context.get_arg())
        if not event_filter:
            return CommandContext(state=False, state_msg="No event filters found")
        if len(event_filter) > 1:
            event_filter = iface_filter.select_list_item(event_filter)
        else:
            event_filter = event_filter[0]
        if not event_filter:
            return CommandContext(state=False, state_msg="No event filters found")
        filter_tree = iface_filter.get_by_id(event_filter.get("id"))
        if filter_tree:
            if "user_only" in command_context.get_kwarg():
                filter_tree = iface_filter.remove_builtin([filter_tree])
            return command_context.instead(context_data=filter_tree, data_fmt="tree",
                                           data_transform=iface_filter.reduce_list)
        else:
            return CommandContext(state=False, state_msg="No event filters found")
    if command_context.is_piped:
        if command_context.piped_next == "select":
            reduced = iface_filter.reduce_list(iface_filter.list)
            return command_context.instead(context_data=reduced, data_fmt="tree",
                                           data_transform=None,
                                           data_islist_transform=False, force_transform=False)
    filter_tree = iface_filter.list
    if "user_only" in command_context.get_kwarg():
        filter_tree = iface_filter.remove_builtin(filter_tree)
    return command_context.instead(context_data=filter_tree, data_fmt="tree",
                                   data_transform=iface_filter.reduce_list)


@Command.validate([validate_mp_connect, validate_siem])
@Command.with_help("Get event filters information")
@Command.with_options([
    {"key": "arg", "required": False, "help": "Filter ID or name"},
    {"key": "user_only", "required": False, "help": "Get only user filters"}
])
@Command.with_name("info")
@Command
def mp_event_filter_info(command_context: CommandContext) -> CommandContext:
    """
    Event filters information
    """
    mp_event_filter.logger.debug("Run mp event filter info")
    valid = command_context.validate([
        {
            "type": "list",
            #"fields": ["id", "name", "meta", "permissions", "type"]
            "fields": ["id"]
        },
        {
            "type": "dict",
            #"fields": ["id", "name", "meta", "permissions", "type"]
            "fields": ["id"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_event_filter_info.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_filter = iface_MP_EventFilter()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_event_filter_info.logger.error("MP event filters API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP event filters API init failed: {}".format(err))
    filter_info = None
    if command_context.context_data:
        mp_event_filter_info.logger.debug("Processing context data")
        if isinstance(command_context.context_data, str):
            filter_info = iface_filter.info(pattern=command_context.context_data,
                                            user_only="user_only" in command_context.get_kwarg())
        elif isinstance(command_context.context_data, dict):
            filter_info = iface_filter.info(dct=command_context.context_data,
                                            user_only="user_only" in command_context.get_kwarg())
        else:
            filter_info = iface_filter.info(lst=command_context.context_data,
                                            user_only="user_only" in command_context.get_kwarg())
        if not filter_info.state:
            mp_event_filter_info.logger.debug("No event filters information found")
            return CommandContext(state=False, state_msg=filter_info.message)
        else:
            filter_info = filter_info.message
    if command_context.get_arg():
        mp_event_filter_info.logger.debug("Processing argument data")
        filter_info = iface_filter.info(pattern=command_context.get_arg(),
                                        user_only="user_only" in command_context.get_kwarg())
        if not filter_info.state:
            mp_event_filter_info.logger.debug("No event filters information found")
            return CommandContext(state=False, state_msg=filter_info.message)
        else:
            filter_info = filter_info.message
    if filter_info:
        EVENTS.checkout()
        return command_context.instead(context_data=filter_info, data_fmt="yaml",
                                       data_transform=iface_filter.reduce_info,
                                       data_islist_transform=True, force_transform=False, table_transform=True)
    else:
        return CommandContext(state=False, state_msg="Something went wrong")


@Command.validate([validate_mp_connect, validate_siem, validate_pipe, validate_enable])
@Command.with_help("Create MaxPatrol Event Filter from specification")
@Command.with_name("create")
@Command
def mp_event_filter_create(command_context: CommandContext) -> CommandContext:
    """
    Create filter from specification
    """
    mp_event_filter_create.logger.debug("Run mp event filter create")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["name"],
            "some_fields": ["source", "pdqlQuery", "isRemoved", "meta"]
        },
        {
            "type": "dict",
            "fields": ["name"],
            "some_fields": ["source", "pdqlQuery", "isRemoved", "meta"]
        }
    ])
    if not valid:
        mp_event_filter_create.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    # Check mixin
    mixin = func_check_mixin(data=command_context.context_data, kind="event_filter", params={})
    if not mixin:
        mp_event_filter_create.logger.error("Mixin validation failed")
        return CommandContext(state=False, state_msg="Mixin validation failed. Wrong specification?")
    disarm = "disarm" in command_context.get_kwarg()
    mp_event_filter_create.logger.debug("Disarm state: " + str(disarm))
    try:
        iface_filter = iface_MP_EventFilter()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_event_filter_create.logger.error("MP event filters API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP event filters API init failed: {}".format(err))
    rich_print("[yellow]Please be aware, in some cases event filters will be created in current user context")
    if isinstance(command_context.context_data, list):
        with Progress() as progress:
            count = len(command_context.context_data)
            task = progress.add_task("Creating event filters...", total=count)
            for item in command_context.context_data:
                # Reload filters list
                iface_filter.list = iface_filter.reload()
                progress.update(task, advance=1)
                result = iface_filter.create(item, disarm=disarm)
                if not result.state:
                    if result.message == "Operation interrupted":
                        return CommandContext(state=False, state_msg="Operation interrupted")
                    mp_event_filter_create.logger.error("Failed to create filter: {}".format(item.get("name")))
                    mp_event_filter_create.logger.error(result.message)
                    EVENTS.push(status="Fail", action="Create", instance="Event filter",
                                name=item.get("name"), instance_id=item.get("id"),
                                details=result.message)
                    continue
                else:
                    print("Event filter {} created".format(item.get("name")))
        console_clear_up()
    else:
        result = iface_filter.create(command_context.context_data, disarm=disarm)
        if not result.state:
            mp_event_filter_create.logger.error("Failed to create event filter: "
                                                "{}".format(command_context.context_data.get("name")))
            mp_event_filter_create.logger.error(result.message)
        else:
            print("Event filter {} created".format(command_context.context_data.get("name")))
    EVENTS.checkout()
    mp_event_filter.logger.debug("Event filter creation complete")
    return CommandContext(state=True)


@Command.validate([validate_mp_connect, validate_siem, validate_enable])
@Command.with_options([
    {"key": "arg", "required": False, "help": "Filter ID or name"},
    {"key": "quiet", "required": False, "help": "Delete without confirmation"}
])
@Command.with_help("Delete event filter")
@Command.with_name("delete")
@Command
def mp_event_filter_delete(command_context: CommandContext) -> CommandContext:
    """
    Delete event filter
    """
    mp_event_filter_delete.logger.debug("Run mp event filter delete")
    quiet = False
    confirm_all = False
    valid = command_context.validate([
        {
            "type": "list",
            #"fields": ["id", "name", "meta", "permissions", "type"]
            "fields": ["id"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_event_filter_delete.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_filter = iface_MP_EventFilter()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_event_filter_delete.logger.error("MP event filters API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP event filters API init failed: {}".format(err))
    if command_context.get_kwarg():
        if "quiet" in command_context.get_kwarg():
            mp_event_filter_delete.logger.debug("Quiet mode")
            quiet = True
    disarm = "disarm" in command_context.get_kwarg()
    if disarm:
        mp_event_filter_delete.logger.debug("Disarm mode")
        quiet = True
    filter_info = False
    if command_context.context_data:
        mp_event_filter_delete.logger.debug("Process context data")
        if isinstance(command_context.context_data, str):
            filter_info = iface_filter.info(pattern=command_context.context_data, user_only=False)
        if isinstance(command_context.context_data, list):
            filter_info = iface_filter.info(lst=command_context.context_data, user_only=False)
        if not filter_info.state:
            mp_event_filter_delete.logger.debug("No filter information found")
            return CommandContext(state=False, state_msg="No filter information found")
        else:
            filter_info = filter_info.message
    if command_context.get_arg():
        filter_info = iface_filter.info(pattern=command_context.get_arg(), user_only=False)
        if not filter_info.state:
            mp_event_filter_delete.logger.debug("No filter information found")
            return CommandContext(state=False, state_msg="No filter information found")
        else:
            filter_info = filter_info.message
    if not filter_info:
        return CommandContext(state=False, state_msg="No filter information found")
    filter_info = iface_filter.remove_childs(filter_info)  # noqa
    for item in filter_info:
        hierarchy_len = len(item["cli-mixin"]["hierarchy"])
        if item.get("source") == "system" or hierarchy_len == 1:
            EVENTS.push(status="Fail", action="Delete", instance="Event filter",
                        name=item.get("name"), instance_id="N/A",
                        details="Event filter {} is built-in. Can`t delete".format(item.get("name")))
            mp_event_filter_delete.logger.debug("Event filter {} is built-in. Can`t delete".format(item.get("name")))
            continue
        if not quiet and not confirm_all:
            try:
                decision = Prompt.ask("Are you sure to delete event filter {}? ".format(item.get("name")),
                                      choices=["y", "n", "a"], default="n")
            except KeyboardInterrupt:
                return CommandContext(state=False, state_msg="Operation interrupted")
            match decision:
                case "n":
                    continue
                case "a":
                    confirm_all = True
        response = iface_filter.delete(item.get("id"), is_folder=item.get("isFolder"), disarm=disarm)
        if response.state:
            print("MaxPatrol event filter {} deleted".format(item.get("name")))
            mp_event_filter_delete.logger.info("MaxPatrol event filter {} deleted".format(item.get("name")))
            continue
        else:
            return CommandContext(parent=command_context.parent, state=False,
                                  state_msg=response.message)
    return CommandContext(state=True)


mp_event_filter.add(mp_event_filter_list)
mp_event_filter.add(mp_event_filter_info)
mp_event_filter.add(mp_event_filter_create)
mp_event_filter.add(mp_event_filter_delete)
mp_event.add(mp_event_filter)
