import time

from rich.progress import Progress
from rich.prompt import Prompt
from rich import print as rich_print

from app.app import EVENTS
from app.app import validate_mp_connect, validate_enable
from app.core.command import Command, CommandContext
from app.core.func import validate_pipe, console_clear_up
from app.mp.func import func_check_mixin
from app.mp.asset.iface_asset_query import iface_MP_AssetQuery
from app.mp.asset.cmd_asset_root import mp_asset


# MaxPatrol Query Tree instance
@Command.with_help("MaxPatrol asset query commands tree")
@Command.with_name("query")
@Command
def mp_asset_query(_command_context: CommandContext) -> CommandContext:
    """
    Asset queries tree root
    """
    return CommandContext(state=False, state_msg="Wrong command")


@Command.validate(validate_mp_connect)
@Command.with_help("Get asset query list")
@Command.with_options([
    {"key": "arg", "required": False, "help": "Root query list element ID or name"},
    {"key": "user_only", "required": False, "help": "Get only user queries"}
])
@Command.with_name("list")
@Command
def mp_asset_query_list(command_context: CommandContext) -> CommandContext:
    """
    Asset queries list
    """
    mp_asset_query_list.logger.debug("Run mp asset query list")
    try:
        iface_query = iface_MP_AssetQuery()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_asset_query_list.logger.error("MP asset queries API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP asset queries API init failed: {}".format(err))
    try:
        time.sleep(2)
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    if command_context.get_arg():
        query = iface_query.get_by_pattern(pattern=command_context.get_arg())
        if not query:
            return CommandContext(state=False, state_msg="No queries found")
        if len(query) > 1:
            query = iface_query.select_list_item(query)
        else:
            query = query[0]
        if not query:
            return CommandContext(state=False, state_msg="No queries found")
        query_tree = iface_query.get_by_id(query.get("id"))
        if query_tree:
            if "user_only" in command_context.get_kwarg():
                query_tree = iface_query.remove_builtin([query_tree])
            return command_context.instead(context_data=query_tree, data_fmt="tree",
                                           data_transform=iface_query.reduce_list)
        else:
            return CommandContext(state=False, state_msg="No queries found")
    if command_context.is_piped:
        if command_context.piped_next == "select":
            reduced = iface_query.reduce_list(iface_query.list)
            return command_context.instead(context_data=reduced, data_fmt="tree",
                                           data_transform=None,
                                           data_islist_transform=False, force_transform=False)
    query_tree = iface_query.list
    if "user_only" in command_context.get_kwarg():
        query_tree = iface_query.remove_builtin(query_tree)
    return command_context.instead(context_data=query_tree, data_fmt="tree",
                                   data_transform=iface_query.reduce_list)


@Command.validate(validate_mp_connect)
@Command.with_help("Get asset query information")
@Command.with_options([
    {"key": "arg", "required": False, "help": "Query ID or name"},
    {"key": "user_only", "required": False, "help": "Get only user queries"}
])
@Command.with_name("info")
@Command
def mp_asset_query_info(command_context: CommandContext) -> CommandContext:
    """
    Asset queries information
    """
    mp_asset_query_info.logger.debug("Run mp asset group info")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "displayName", "isFolder", "parentId", "type"]
        },
        {
            "type": "dict",
            "fields": ["id", "displayName", "isFolder", "parentId", "type"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_asset_query_info.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_query = iface_MP_AssetQuery()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_asset_query_info.logger.error("MP asset queries API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP asset queries API init failed: {}".format(err))
    query_info = False
    if command_context.context_data:
        mp_asset_query_info.logger.debug("Processing context data")
        if isinstance(command_context.context_data, str):
            query_info = iface_query.info(pattern=command_context.context_data,
                                          user_only="user_only" in command_context.get_kwarg())
        elif isinstance(command_context.context_data, dict):
            query_info = iface_query.info(dct=command_context.context_data,
                                          user_only="user_only" in command_context.get_kwarg())
        else:
            query_info = iface_query.info(lst=command_context.context_data,
                                          user_only="user_only" in command_context.get_kwarg())
        if not query_info.state:
            mp_asset_query_info.logger.debug("No asset query information found")
            return CommandContext(state=False, state_msg=query_info.message)
        else:
            query_info = query_info.message
    if command_context.get_arg():
        mp_asset_query_info.logger.debug("Processing argument data")
        query_info = iface_query.info(pattern=command_context.get_arg(),
                                      user_only="user_only" in command_context.get_kwarg())
        if not query_info.state:
            mp_asset_query_info.logger.debug("No asset query information found")
            return CommandContext(state=False, state_msg=query_info.message)
        else:
            query_info = query_info.message
    if query_info:
        EVENTS.checkout()
        return command_context.instead(context_data=query_info, data_fmt="yaml",
                                       data_transform=iface_query.reduce_info,
                                       data_islist_transform=True, force_transform=False, table_transform=True)
    else:
        return CommandContext(state=False, state_msg="Something went wrong")


@Command.validate([validate_mp_connect, validate_pipe, validate_enable])
@Command.with_help("Create MaxPatrol Group from specification")
@Command.with_name("create")
@Command
def mp_asset_query_create(command_context: CommandContext) -> CommandContext:
    """
    Create query from specification
    """
    mp_asset_query_create.logger.debug("Run mp asset query create")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["displayName", "isFolder", "type"]
        },
        {
            "type": "dict",
            "fields": ["displayName", "isFolder", "type"]
        }
    ])
    if not valid:
        mp_asset_query_create.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    # Check mixin
    mixin = func_check_mixin(data=command_context.context_data, kind="query", params={})
    if not mixin:
        mp_asset_query_create.logger.error("Mixin validation failed")
        return CommandContext(state=False, state_msg="Mixin validation failed. Wrong specification?")
    disarm = "disarm" in command_context.get_kwarg()
    mp_asset_query_create.logger.debug("Disarm state: " + str(disarm))
    try:
        iface_query = iface_MP_AssetQuery()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_asset_query_create.logger.error("MP asset queries API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP asset queries API init failed: {}".format(err))
    rich_print("[yellow]Please be aware, in some cases queries will be created in current user context")
    # Looking for list of group specs
    if isinstance(command_context.context_data, list):
        with Progress() as progress:
            count = len(command_context.context_data)
            task = progress.add_task("Creating asset queries...", total=count)
            for item in command_context.context_data:
                # Reload query list
                iface_query.list = iface_query.reload()
                progress.update(task, advance=1)
                result = iface_query.create(item, disarm=disarm)
                if not result.state:
                    if result.message == "Operation interrupted":
                        return CommandContext(state=False, state_msg="Operation interrupted")
                    mp_asset_query_create.logger.error("Failed to create query: {}".format(item.get("displayName")))
                    mp_asset_query_create.logger.error(result.message)
                    EVENTS.push(status="Fail", action="Create", instance="Query",
                                name=item.get("displayName"), instance_id=item.get("id"),
                                details=result.message)
                    continue
                else:
                    print("Asset query {} created".format(item.get("displayName")))
        console_clear_up()
    else:
        result = iface_query.create(command_context.context_data, disarm=disarm)
        if not result.state:
            mp_asset_query_create.logger.error("Failed to create asset "
                                               "query: {}".format(command_context.context_data.get("displayName")))
            mp_asset_query_create.logger.error(result.message)
        else:
            print("Asset query {} created".format(command_context.context_data.get("displayName")))
    EVENTS.checkout()
    mp_asset_query_create.logger.debug("Asset query creation complete")
    return CommandContext(state=True)


@Command.validate([validate_mp_connect, validate_enable])
@Command.with_options([
    {"key": "arg", "required": False, "help": "Query ID or name"},
    {"key": "quiet", "required": False, "help": "Delete without confirmation"}
])
@Command.with_help("Delete MaxPatrol Query")
@Command.with_name("delete")
@Command
def mp_asset_query_delete(command_context: CommandContext) -> CommandContext:
    """
    Delete asset query
    """
    mp_asset_query_delete.logger.debug("Run mp asset query delete")
    quiet = False
    confirm_all = False
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "displayName", "isFolder", "parentId", "type"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_asset_query_delete.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_query = iface_MP_AssetQuery()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_asset_query_delete.logger.error("MP asset query API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP asset query API init failed: {}".format(err))
    if command_context.get_kwarg():
        if "quiet" in command_context.get_kwarg():
            mp_asset_query_delete.logger.debug("Quiet mode")
            quiet = True
    disarm = "disarm" in command_context.get_kwarg()
    if disarm:
        mp_asset_query_delete.logger.debug("Disarm mode")
        quiet = True
    query_info = False
    if command_context.context_data:
        mp_asset_query_delete.logger.debug("Process context data")
        if isinstance(command_context.context_data, str):
            query_info = iface_query.info(pattern=command_context.context_data, user_only=False)
        if isinstance(command_context.context_data, list):
            query_info = iface_query.info(lst=command_context.context_data, user_only=False)
        if not query_info.state:
            mp_asset_query_delete.logger.debug("No query information found")
            return CommandContext(state=False, state_msg="No query information found")
        else:
            query_info = query_info.message
    if command_context.get_arg():
        query_info = iface_query.info(pattern=command_context.get_arg(), user_only=False)
        if not query_info.state:
            mp_asset_query_delete.logger.debug("No query information found")
            return CommandContext(state=False, state_msg="No query information found")
        else:
            query_info = query_info.message
    if not query_info:
        return CommandContext(state=False, state_msg="No query information found")
    query_info = iface_query.remove_childs(query_info) # noqa
    for item in query_info:
        # Deprecation block
        hierarchy_len = 0
        if "tree_hierarchy" in item:
            hierarchy_len = len(item.get("tree_hierarchy"))
        else:
            hierarchy_len = len(item["cli-mixin"]["hierarchy"])
        # End deprecation
        if item.get("type") == "standard" or hierarchy_len == 1:
            EVENTS.push(status="Fail", action="Delete", instance="Query",
                        name=item.get("displayName"), instance_id="N/A",
                        details="Query {} is built-in. Can`t delete".format(item.get("displayName")))
            mp_asset_query_delete.logger.debug("Query " + item["displayName"] + " is built-in. Can`t delete")
            continue
        if not quiet and not confirm_all:
            try:
                decision = Prompt.ask("Are you sure to delete query {}? ".format(item.get("displayName")),
                                      choices=["y", "n", "a"], default="n")
            except KeyboardInterrupt:
                return CommandContext(state=False, state_msg="Operation interrupted")
            match decision:
                case "n":
                    continue
                case "a":
                    confirm_all = True
        response = iface_query.delete(item.get("id"), is_folder=item.get("isFolder"), disarm=disarm)
        if response.state:
            print("MaxPatrol asset query {} deleted".format(item.get("displayName")))
            mp_asset_query_delete.logger.info("MaxPatrol asset query {} deleted".format(item.get("displayName")))
            continue
        else:
            return CommandContext(parent=command_context.parent, state=False,
                                  state_msg=response.message)
    return CommandContext(state=True)


mp_asset_query.add(mp_asset_query_list)
mp_asset_query.add(mp_asset_query_info)
mp_asset_query.add(mp_asset_query_create)
mp_asset_query.add(mp_asset_query_delete)
mp_asset.add(mp_asset_query)
