import time

from rich.progress import Progress
from rich.prompt import Prompt

from app.app import EVENTS
from app.app import validate_mp_connect, validate_enable
from app.core.command import Command, CommandContext
from app.core.func import validate_pipe, console_clear_up
from app.mp.func import func_check_mixin, func_select_list_item
from app.mp.asset.iface_asset_group import iface_MP_Group
from app.mp.asset.cmd_asset_root import mp_asset


@Command.with_help("MaxPatrol Asset Group commands tree")
@Command.with_name("group")
@Command
def mp_asset_group(_command_context: CommandContext) -> CommandContext:
    """
    Asset groups tree root
    """
    return CommandContext(state=False, state_msg="Wrong command")


@Command.validate(validate_mp_connect)
@Command.with_help("Get asset groups list")
@Command.with_options([
    {"key": "arg", "required": False, "help": "Root group ID or name"},
])
@Command.with_name("list")
@Command
def mp_asset_group_list(command_context: CommandContext) -> CommandContext:
    """
    Asset groups list
    """
    mp_asset_group_list.logger.debug("Run mp asset group list")
    try:
        iface_group = iface_MP_Group()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_asset_group_list.logger.error("MP group API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP group API init failed: {}".format(err))
    try:
        time.sleep(2)
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    if command_context.get_arg():
        group = iface_group.get_by_pattern(pattern=command_context.get_arg())
        if not group:
            return CommandContext(state=False, state_msg="No group found")
        if len(group) > 1:
            group = func_select_list_item(group)
        else:
            group = group[0]
        if not group:
            return CommandContext(state=False, state_msg="No group found")
        group_tree = iface_group.get_by_id(group.get("id"))
        if group_tree:
            return command_context.instead(context_data=group_tree, data_fmt="tree",
                                           data_transform=iface_group.reduce_list)
        else:
            return CommandContext(state=False, state_msg="No group found")
    if command_context.is_piped:
        if command_context.piped_next == "select":
            reduced = iface_group.reduce_list(iface_group.list)
            return command_context.instead(context_data=reduced, data_fmt="tree",
                                           data_transform=None,
                                           data_islist_transform=False, force_transform=False)
    return command_context.instead(context_data=iface_group.list, data_fmt="tree",
                                   data_transform=iface_group.reduce_list)


@Command.validate(validate_mp_connect)
@Command.with_help("Get asset group information")
@Command.with_options([
    {"key": "arg", "required": False, "help": "Group ID or name"},
])
@Command.with_name("info")
@Command
def mp_asset_group_info(command_context: CommandContext) -> CommandContext:
    """
    Asset group(s) information
    """
    mp_asset_group_info.logger.debug("Run mp asset group info")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "name", "groupType", "children", "isRoot"]
        },
        {
            "type": "dict",
            "fields": ["id", "name", "groupType", "children", "isRoot"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_asset_group_info.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_group = iface_MP_Group()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_asset_group_info.logger.error("MP group API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP group API init failed: {}".format(err))
    group_info = False
    if command_context.context_data:
        mp_asset_group_info.logger.debug("Processing context data")
        if isinstance(command_context.context_data, str):
            group_info = iface_group.info(pattern=command_context.context_data)
        elif isinstance(command_context.context_data, dict):
            group_info = iface_group.info(dct=command_context.context_data)
        else:
            group_info = iface_group.info(lst=command_context.context_data)
        if not group_info.state:
            mp_asset_group_info.logger.debug("No group information found")
            return CommandContext(state=False, state_msg=group_info.message)
        else:
            group_info = group_info.message
    if command_context.get_arg():
        mp_asset_group_info.logger.debug("Processing argument data")
        group_info = iface_group.info(pattern=command_context.get_arg())
        if not group_info.state:
            mp_asset_group_info.logger.debug("No group information found")
            return CommandContext(state=False, state_msg=group_info.message)
        else:
            group_info = group_info.message
    if group_info:
        EVENTS.checkout()
        return command_context.instead(context_data=group_info, data_fmt="yaml",
                                       data_transform=iface_group.reduce_info,
                                       data_islist_transform=True, force_transform=False, table_transform=True)
    else:
        return CommandContext(state=False)


@Command.validate([validate_mp_connect, validate_pipe, validate_enable])
@Command.with_help("Create MaxPatrol Group from specification")
@Command.with_name("create")
@Command
def mp_asset_group_create(command_context: CommandContext) -> CommandContext:
    """
    Create asset groups
    """
    mp_asset_group_create.logger.debug("Run mp asset group create")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "name", "groupType", "metrics"]
        },
        {
            "type": "dict",
            "fields": ["id", "name", "groupType", "metrics"]
        }
    ])
    if not valid:
        mp_asset_group_create.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    # Check mixin
    mixin = func_check_mixin(data=command_context.context_data, kind="group", params={})
    if not mixin:
        mp_asset_group_create.logger.error("Mixin validation failed")
        return CommandContext(state=False, state_msg="Mixin validation failed. Wrong specification?")
    disarm = "disarm" in command_context.get_kwarg()
    mp_asset_group_create.logger.debug("Disarm state: {}".format(disarm))
    try:
        iface_group = iface_MP_Group()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_asset_group_create.logger.error("MP group API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP group API init failed: {}".format(err))
    # Looking for list of group specs
    if isinstance(command_context.context_data, list):
        with Progress() as progress:
            count = len(command_context.context_data)
            task = progress.add_task("Creating groups...", total=count)
            for item in command_context.context_data:
                if item.get("name") == "Root":
                    continue
                progress.update(task, advance=1)
                iface_group.reload()
                result = iface_group.create(item, disarm=disarm)
                if not result.state:
                    if result.message == "Operation interrupted":
                        return CommandContext(state=False, state_msg="Operation interrupted")
                    mp_asset_group_create.logger.error("Failed to create group: {}".format(item.get("name")))
                    mp_asset_group_create.logger.error(result.message)
                    print(result.message)
                    continue
                else:
                    print("Group {} created".format(item.get("name")))
        console_clear_up()
    else:
        result = iface_group.create(command_context.context_data, disarm=disarm)
        if not result.state:
            mp_asset_group_create.logger.error("Failed to create group: {}"
                                               .format(command_context.context_data.get("name")))
            mp_asset_group_create.logger.error(result.message)
            print(result.message)
        else:
            print("Group {} created".format(command_context.context_data.get("name")))
    EVENTS.checkout()
    mp_asset_group_create.logger.debug("Group creation complete")
    return CommandContext(state=True)


@Command.validate([validate_mp_connect, validate_enable])
@Command.with_options([
    {"key": "arg", "required": False, "help": "Group ID or name"},
    {"key": "disarm", "required": False, "help": "Run in test mode"},
    {"key": "quiet", "required": False, "help": "Delete without confirmation"}
])
@Command.with_help("Delete MaxPatrol Group")
@Command.with_name("delete")
@Command
def mp_asset_group_delete(command_context: CommandContext) -> CommandContext:
    """
    Delete asset groups
    """
    mp_asset_group_delete.logger.debug("Run mp asset group delete")
    quiet = False
    confirm_all = False
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "name", "groupType", "children", "isRoot"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_asset_group_delete.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_group = iface_MP_Group()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_asset_group_delete.logger.error("MP group API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP group API init failed: {}".format(err))
    if command_context.get_kwarg():
        if "quiet" in command_context.get_kwarg():
            mp_asset_group_delete.logger.debug("Quiet mode")
            quiet = True
    disarm = "disarm" in command_context.get_kwarg()
    if disarm:
        mp_asset_group_delete.logger.debug("Disarm mode")
        quiet = True
    group_info = None
    if command_context.context_data:
        mp_asset_group_delete.logger.debug("Process context data")
        if isinstance(command_context.context_data, str):
            group_info = iface_group.info(pattern=command_context.context_data)
        if isinstance(command_context.context_data, list):
            group_info = iface_group.info(lst=command_context.context_data)
        if not group_info.state:
            mp_asset_group_delete.logger.debug("No group information found")
            return CommandContext(state=False, state_msg="No group information found")
        else:
            group_info = group_info.message
    if command_context.get_arg():
        group_info = iface_group.info(pattern=command_context.get_arg())
        if not group_info.state:
            mp_asset_group_delete.logger.debug("No group information found")
            return CommandContext(state=False, state_msg="No group information found")
        else:
            group_info = group_info.message
    if not group_info:
        return CommandContext(state=False, state_msg="No group information found")
    group_info = iface_group.remove_childs(group_info)
    for item in group_info:
        if item.get("name") == "Root":
            continue
        if not quiet and not confirm_all:
            try:
                decision = Prompt.ask("Are you sure to delete group {}? ".format(item.get("name")),
                                      choices=["y", "n", "a"], default="n")
            except KeyboardInterrupt:
                return CommandContext(state=False, state_msg="Operation interrupted")
            match decision:
                case "n":
                    continue
                case "a":
                    confirm_all = True
        response = iface_group.delete(item.get("id"), disarm=disarm)
        if response.state:
            print("MaxPatrol group {} deleted".format(item.get("name")))
            mp_asset_group_delete.logger.info("MaxPatrol group {} deleted".format(item.get("name")))
            continue
        else:
            return CommandContext(parent=command_context.parent, state=False,
                                  state_msg=response.message)
    EVENTS.checkout()
    return CommandContext(state=True)


mp_asset_group.add(mp_asset_group_list)
mp_asset_group.add(mp_asset_group_info)
mp_asset_group.add(mp_asset_group_create)
mp_asset_group.add(mp_asset_group_delete)
mp_asset.add(mp_asset_group)
