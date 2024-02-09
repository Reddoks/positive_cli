from rich import print as rich_print
from rich.prompt import Prompt

from app.app import validate_mp_connect, validate_enable, EVENTS
from app.core.command import Command, CommandContext
from app.core.func import validate_pipe
from app.mp.func import func_check_mixin
from app.mp.dashboard.iface_dashboard import iface_MP_Dashboard

from app.mp.cmd_mp import mp


@Command.with_help("MaxPatrol dashboard commands tree")
@Command.with_name("dashboard")
@Command
def mp_dashboard(_command_context: CommandContext) -> CommandContext:
    """
    Dashboard tree root
    """
    return CommandContext(state=False, state_msg="Wrong command")


@Command.validate(validate_mp_connect)
@Command.with_help("Get MaxPatrol dashboard list")
@Command.with_name("list")
@Command
def mp_dashboard_list(command_context: CommandContext) -> CommandContext:
    """
    Dashboard list
    """
    mp_dashboard_list.logger.debug("Run mp dashboard list")
    try:
        iface_dashboard = iface_MP_Dashboard()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_dashboard_list.logger.error("MP dashboard API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP dashboard API init failed: {}".format(err))
    return command_context.instead(context_data=iface_dashboard.list, data_fmt="table")


@Command.validate(validate_mp_connect)
@Command.with_options([
    {"key": "arg", "required": False, "help": "Dashboard ID or name"},
])
@Command.with_help("Get MaxPatrol dashboard information")
@Command.with_name("info")
@Command
def mp_dashboard_info(command_context: CommandContext) -> CommandContext:
    """
    Dashboard information
    """
    mp_dashboard_info.logger.debug("Run mp task dashboard info")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "name", "version", "canAddNewWidget"]
        },
        {
            "type": "dict",
            "fields": ["id", "name", "version", "canAddNewWidget"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_dashboard_info.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_dashboard = iface_MP_Dashboard()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_dashboard_info.logger.error("MP dashboard API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP dashboard API init failed: {}".format(err))
    dashboard_info = False
    if command_context.context_data:
        mp_dashboard_info.logger.debug("Processing context data")
        if isinstance(command_context.context_data, str):
            dashboard_info = iface_dashboard.info(pattern=command_context.context_data)
        elif isinstance(command_context.context_data, dict):
            dashboard_info = iface_dashboard.info(dct=command_context.context_data)
        else:
            dashboard_info = iface_dashboard.info(lst=command_context.context_data)
        if not dashboard_info.state:
            return CommandContext(state=False, state_msg=dashboard_info.message)
    if command_context.get_arg():
        mp_dashboard_info.logger.debug("Processing argument data")
        dashboard_info = iface_dashboard.info(pattern=command_context.get_arg())
        if not dashboard_info.state:
            return CommandContext(state=False, state_msg=dashboard_info.message)
    if dashboard_info:
        dashboard_info = dashboard_info.message
        EVENTS.checkout()
        return command_context.instead(context_data=dashboard_info, data_fmt="yaml",
                                       data_transform=iface_MP_Dashboard.reduce_info,
                                       data_islist_transform=True, force_transform=False,
                                       table_transform=True)
    else:
        EVENTS.checkout()
        return CommandContext(state=False, state_msg="No dashboard information found")


@Command.validate([validate_mp_connect, validate_enable, validate_pipe])
@Command.with_options([
    {"key": "disarm", "required": False, "help": "Run in test mode"},
])
@Command.with_help("Create MaxPatrol dashboard")
@Command.with_name("create")
@Command
def mp_dashboard_create(command_context: CommandContext) -> CommandContext:
    """
    Create MaxPatrol dashboard from specification
    """
    mp_dashboard_create.logger.debug("Run mp dashboard create")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["name", "version", "position", "widgets"]
        },
        {
            "type": "dict",
            "fields": ["name", "version", "position", "widgets"]
        }
    ])
    if not valid:
        mp_dashboard_create.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    # Check mixin
    mixin = func_check_mixin(data=command_context.context_data, kind="dashboard", params={})
    if not mixin:
        mp_dashboard_create.logger.error("Mixin validation failed - wrong specification?")
        return CommandContext(state=False, state_msg="Mixin validation failed - wrong specification?")
    disarm = "disarm" in command_context.get_kwarg()
    mp_dashboard_create.logger.debug("Disarm state: {}".format(disarm))
    try:
        iface_dashboard = iface_MP_Dashboard()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_dashboard_create.logger.error("MP dashboard API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP dashboard API init failed: {}".format(err))
    rich_print("[yellow]Please be aware, dashboard will be created in current user context")
    if isinstance(command_context.context_data, list):
        for item in command_context.context_data:
            response = iface_dashboard.create(source_spec=item, disarm=disarm)
            if not response.state:
                if response.message == "Operation interrupted":
                    return CommandContext(state=False, state_msg="Operation interrupted")
                mp_dashboard_create.logger.error("Failed to create dashboard: {}".format(response.message))
                rich_print("[red]Failed to create dashboard: {}".format(response.message))
                EVENTS.push(status="Fail", action="Create", instance="Dashboard",
                            name=item.get("name"), instance_id=item.get("id"), details=response.message)
                continue
            print(response.message)
    else:
        response = iface_dashboard.create(source_spec=command_context.context_data, disarm=disarm)
        if not response.state:
            mp_dashboard_create.logger.error("Failed to create dashboard: {}".format(response.message))
            rich_print("[red]Failed to create dashboard: {}".format(response.message))
        print(response.message)
    EVENTS.checkout()
    mp_dashboard_create.logger.debug("Dashboard creation completed")
    return CommandContext(state=True)


@Command.validate([validate_mp_connect, validate_enable])
@Command.with_options([
    {"key": "arg", "required": False, "help": "Template ID or name"},
    {"key": "quiet", "required": False, "help": "Delete without confirmation"},
    {"key": "disarm", "required": False, "help": "Run in test mode"},
])
@Command.with_help("Delete MaxPatrol template")
@Command.with_name("delete")
@Command
def mp_dashboard_delete(command_context: CommandContext) -> CommandContext:
    """
    Delete dashboard
    """
    mp_dashboard_delete.logger.debug("Run mp dashboard delete")
    quiet = False
    confirm_all = False
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "name", "version", "canAddNewWidget"]
        },
        {
            "type": "dict",
            "fields": ["id", "name", "version", "canAddNewWidget"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_dashboard_delete.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_dashboard = iface_MP_Dashboard()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_dashboard_delete.logger.error("MP dashboard API init failed: {}".format(err))
        return CommandContext(state=False)
    if command_context.get_kwarg():
        if "quiet" in command_context.get_kwarg():
            mp_dashboard_delete.logger.debug("Quiet mode")
            quiet = True
    disarm = "disarm" in command_context.get_kwarg()
    if disarm:
        mp_dashboard_delete.logger.debug("Disarm mode")
        quiet = True
    dashboard_info = False
    if command_context.context_data:
        if isinstance(command_context.context_data, str):
            dashboard_info = iface_dashboard.info(pattern=command_context.context_data)
        if isinstance(command_context.context_data, list):
            dashboard_info = iface_dashboard.info(lst=command_context.context_data)
        if not dashboard_info.state:
            mp_dashboard_delete.logger.debug("No dashboard information found")
            return CommandContext(state=False, state_msg="No dashboard information found")
    if command_context.get_arg():
        dashboard_info = iface_dashboard.info(pattern=command_context.get_arg())
        if not dashboard_info.state:
            mp_dashboard_delete.logger.debug("No dashboard information found")
            return CommandContext(state=False, state_msg="No dashboard information found")
    if not dashboard_info:
        mp_dashboard_delete.logger.debug("No dashboard information found")
        return CommandContext(state=False, state_msg="No dashboard information found")
    dashboard_info = dashboard_info.message
    for item in dashboard_info:
        if not quiet and not confirm_all:
            try:
                decision = Prompt.ask("Are you sure to delete dashboard {}? ".format(item.get("name")),
                                      choices=["y", "n", "a"], default="n")
            except KeyboardInterrupt:
                return CommandContext(state=False, state_msg="Operation interrupted")
            match decision:
                case "n":
                    continue
                case "a":
                    confirm_all = True
        response = iface_dashboard.delete(item.get("id"), disarm=disarm)
        if response.state:
            print("MaxPatrol dashboard {} deleted".format(item.get("name")))
            mp_dashboard_delete.logger.info("MaxPatrol dashboard {} deleted".format(item.get("name")))
            continue
        else:
            return CommandContext(parent=command_context.parent, state=False,
                                  state_msg=response.message)
    return CommandContext(state=True)


mp_dashboard.add(mp_dashboard_list)
mp_dashboard.add(mp_dashboard_info)
mp_dashboard.add(mp_dashboard_create)
mp_dashboard.add(mp_dashboard_delete)
mp.add(mp_dashboard)
