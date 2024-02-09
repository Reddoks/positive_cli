from rich import print as rich_print

from app.app import validate_mp_connect, validate_enable, EVENTS
from app.core.command import Command, CommandContext
from app.core.func import validate_pipe
from app.mp.func import func_check_mixin
from app.mp.user import iface_MP_User
from datetime import datetime

from app.mp.cmd_mp import mp


@Command.with_help("MaxPatrol user commands tree")
@Command.with_name("user")
@Command
def mp_user(_command_context: CommandContext) -> CommandContext:
    """
    User tree root
    """
    return CommandContext(state=False, state_msg="Wrong command")


@Command.validate(validate_mp_connect)
@Command.with_help("Get MaxPatrol user list")
@Command.with_name("list")
@Command
def mp_user_list(command_context: CommandContext) -> CommandContext:
    """
    User list
    """
    mp_user_list.logger.debug("Run mp user list")
    try:
        iface_user = iface_MP_User()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_user_list.logger.error("MP user API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP user API init failed: {}".format(err))
    return command_context.instead(context_data=iface_user.list, data_fmt="table",
                                   data_transform=iface_user.reduce_list,
                                   data_islist_transform=True)


@Command.validate(validate_mp_connect)
@Command.with_options([
    {"key": "arg", "required": False, "help": "User ID or name"},
])
@Command.with_help("Get MaxPatrol user information")
@Command.with_name("info")
@Command
def mp_user_info(command_context: CommandContext) -> CommandContext:
    """
    User information
    """
    mp_user_info.logger.debug("Run mp task user info")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "name", "login", "email"]
        },
        {
            "type": "dict",
            "fields": ["id", "name", "login", "email"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_user_info.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_user = iface_MP_User()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_user_info.logger.error("MP user API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP user API init failed: {}".format(err))
    user_info = False
    if command_context.context_data:
        mp_user_info.logger.debug("Processing context data")
        if isinstance(command_context.context_data, str):
            user_info = iface_user.info(pattern=command_context.context_data)
        elif isinstance(command_context.context_data, dict):
            user_info = iface_user.info(dct=command_context.context_data)
        else:
            user_info = iface_user.info(lst=command_context.context_data)
        if not user_info.state:
            return CommandContext(state=False, state_msg=user_info.message)
    if command_context.get_arg():
        mp_user_info.logger.debug("Processing argument data")
        user_info = iface_user.info(pattern=command_context.get_arg())
        if not user_info.state:
            return CommandContext(state=False, state_msg=user_info.message)
    if user_info:
        user_info = user_info.message
        EVENTS.checkout()
        return command_context.instead(context_data=user_info, data_fmt="yaml",
                                       data_transform=iface_MP_User.reduce_info,
                                       data_islist_transform=True, force_transform=False,
                                       table_transform=True)
    else:
        EVENTS.checkout()
        return CommandContext(state=False, state_msg="No user information found")


@Command.validate(validate_mp_connect)
@Command.with_options([
    {"key": "arg", "required": False, "help": "User ID or name"},
])
@Command.with_help("Get MaxPatrol user information")
@Command.with_name("info")
@Command
def mp_user_info(command_context: CommandContext) -> CommandContext:
    """
    User information
    """
    mp_user_info.logger.debug("Run mp user info")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "userName", "firstName", "status"]
        },
        {
            "type": "dict",
            "fields": ["id", "userName", "firstName", "status"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_user_info.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_user = iface_MP_User()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_user_info.logger.error("MP user API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP user API init failed: {}".format(err))
    user_info = False
    if command_context.context_data:
        mp_user_info.logger.debug("Processing context data")
        if isinstance(command_context.context_data, str):
            user_info = iface_user.info(pattern=command_context.context_data)
        elif isinstance(command_context.context_data, dict):
            user_info = iface_user.info(dct=command_context.context_data)
        else:
            user_info = iface_user.info(lst=command_context.context_data)
        if not user_info.state:
            return CommandContext(state=False, state_msg=user_info.message)
    if command_context.get_arg():
        mp_user_info.logger.debug("Processing argument data")
        user_info = iface_user.info(pattern=command_context.get_arg())
        if not user_info.state:
            return CommandContext(state=False, state_msg=user_info.message)
    if user_info:
        user_info = user_info.message
        EVENTS.checkout()
        return command_context.instead(context_data=user_info, data_fmt="yaml",
                                       data_transform=iface_MP_User.reduce_info,
                                       data_islist_transform=True, force_transform=False,
                                       table_transform=True)
    else:
        EVENTS.checkout()
        return CommandContext(state=False, state_msg="No user information found")


@Command.validate(validate_mp_connect)
@Command.with_options([
    {"key": "arg", "required": False, "help": "User ID or name"},
])
@Command.with_help("Get MaxPatrol user privileges")
@Command.with_name("privilege")
@Command
def mp_user_privilege(command_context: CommandContext) -> CommandContext:
    """
    User privilege information
    """
    mp_user_info.logger.debug("Run mp user privilege")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "userName", "firstName", "status"]
        },
        {
            "type": "dict",
            "fields": ["id", "userName", "firstName", "status"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_user_privilege.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_user = iface_MP_User()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_user_privilege.logger.error("MP user API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP user API init failed: {}".format(err))
    user_privilege = False
    if command_context.context_data:
        mp_user_privilege.logger.debug("Processing context data")
        if isinstance(command_context.context_data, str):
            user_privilege = iface_user.privilege(pattern=command_context.context_data)
        elif isinstance(command_context.context_data, dict):
            user_privilege = iface_user.privilege(dct=command_context.context_data)
        else:
            user_privilege = iface_user.privilege(lst=command_context.context_data)
        if not user_privilege.state:
            return CommandContext(state=False, state_msg=user_privilege.message)
    if command_context.get_arg():
        mp_user_privilege.logger.debug("Processing argument data")
        user_privilege = iface_user.privilege(pattern=command_context.get_arg())
        if not user_privilege.state:
            return CommandContext(state=False, state_msg=user_privilege.message)
    if user_privilege:
        user_privilege = user_privilege.message
        EVENTS.checkout()
        return command_context.instead(context_data=user_privilege, data_fmt="yaml", data_transform="reset")
    else:
        EVENTS.checkout()
        return CommandContext(state=False, state_msg="No user privilege information found")


@Command.validate([validate_mp_connect, validate_enable, validate_pipe])
@Command.with_options([
    {"key": "disarm", "required": False, "help": "Run in test mode"},
])
@Command.with_help("Create MaxPatrol user")
@Command.with_name("create")
@Command
def mp_user_create(command_context: CommandContext) -> CommandContext:
    """
    Create MaxPatrol user from specification
    """
    mp_user_create.logger.debug("Run mp user create")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["userName", "roles", "ldapAliases"]
        },
        {
            "type": "dict",
            "fields": ["userName", "roles", "ldapAliases"]
        }
    ])
    if not valid:
        mp_user_create.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    # Check mixin
    mixin = func_check_mixin(data=command_context.context_data, kind="user", params={})
    if not mixin:
        mp_user_create.logger.error("Mixin validation failed - wrong specification?")
        return CommandContext(state=False, state_msg="Mixin validation failed - wrong specification?")
    disarm = "disarm" in command_context.get_kwarg()
    mp_user_create.logger.debug("Disarm state: {}".format(disarm))
    try:
        iface_user = iface_MP_User()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_user_create.logger.error("MP user API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP user API init failed: {}".format(err))
    rich_print("[yellow]Please be aware, users will be created with dummy passwords and disabled state")
    if isinstance(command_context.context_data, list):
        for item in command_context.context_data:
            response = iface_user.create(source_spec=item, disarm=disarm)
            if not response.state:
                if response.message == "Operation interrupted":
                    return CommandContext(state=False, state_msg="Operation interrupted")
                mp_user_create.logger.error("Failed to create user: {}".format(response.message))
                rich_print("[red]Failed to create user: {}".format(response.message))
                EVENTS.push(status="Fail", action="Create", instance="User",
                            name=item.get("userName"), instance_id=item.get("id"), details=response.message)
                continue
            print(response.message)
    else:
        response = iface_user.create(source_spec=command_context.context_data, disarm=disarm)
        if not response.state:
            mp_user_create.logger.error("Failed to create user: {}".format(response.message))
            rich_print("[red]Failed to create user: {}".format(response.message))
        print(response.message)
    EVENTS.checkout()
    mp_user_create.logger.debug("User creation completed")
    return CommandContext(state=True)


@Command.validate(validate_mp_connect)
@Command.with_options([
    {"key": "arg", "required": False, "help": "User ID or name"},
    {"key": "time_from", "required": False, "help": "Get logs starting from"},
    {"key": "limit", "required": False, "help": "Log items limit"},
])
@Command.with_help("Get MaxPatrol users action log")
@Command.with_name("log")
@Command
def mp_user_log(command_context: CommandContext) -> CommandContext:
    """
    User action log
    """
    mp_user_info.logger.debug("Run mp user log")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "userName", "firstName", "status"]
        },
        {
            "type": "dict",
            "fields": ["id", "userName", "firstName", "status"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_user_info.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_user = iface_MP_User()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_user_info.logger.error("MP user API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP user API init failed: {}".format(err))
    actions_info = False
    time_from = None
    limit = 15
    got_context = False
    if command_context.get_kwarg("time_from"):
        try:
            time_from = datetime.fromisoformat(command_context.get_kwarg("time_from"))
            time_from = time_from.strftime('%Y-%m-%dT%H:%M:%SZ')
        except BaseException as err:
            return CommandContext(state=False, state_msg="Wrong `time_from` value: {}".format(err))
    if command_context.get_kwarg("limit"):
        lim = command_context.get_kwarg("limit")
        if not lim.isdigit():
            return CommandContext(state=False, state_msg="Wrong `limit`: not digit")
        limit = int(lim)
    if command_context.context_data:
        got_context = True
        mp_user_info.logger.debug("Processing context data")
        if isinstance(command_context.context_data, str):
            actions_info = iface_user.log(pattern=command_context.context_data, time_from=time_from, limit=limit)
        elif isinstance(command_context.context_data, dict):
            actions_info = iface_user.log(dct=command_context.context_data, time_from=time_from, limit=limit)
        else:
            actions_info = iface_user.log(lst=command_context.context_data, time_from=time_from, limit=limit)
        if not actions_info.state:
            return CommandContext(state=False, state_msg=actions_info.message)
    if command_context.get_arg():
        got_context = True
        mp_user_info.logger.debug("Processing argument data")
        actions_info = iface_user.log(pattern=command_context.get_arg(), time_from=time_from, limit=limit)
        if not actions_info.state:
            return CommandContext(state=False, state_msg=actions_info.message)
    if not got_context:
        actions_info = iface_user.log(time_from=time_from, limit=limit)
        if not actions_info.state:
            return CommandContext(state=False, state_msg=actions_info.message)
    if actions_info:
        actions_info = actions_info.message
        EVENTS.checkout()
        return command_context.instead(context_data=actions_info, data_fmt="table",
                                       data_transform=iface_MP_User.reduce_log,
                                       data_islist_transform=True, force_transform=False,
                                       table_transform=True)
    else:
        EVENTS.checkout()
        return CommandContext(state=False, state_msg="No log information found")


mp_user.add(mp_user_list)
mp_user.add(mp_user_info)
mp_user.add(mp_user_privilege)
mp_user.add(mp_user_create)
mp_user.add(mp_user_log)
mp.add(mp_user)
