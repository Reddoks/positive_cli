from app.app import validate_mp_connect, validate_enable, EVENTS
from app.core.command import Command, CommandContext
from app.mp.user.iface_user_roles import iface_MP_UserRole

from app.core.func import validate_pipe
from app.mp.func import func_check_mixin
from app.mp.user.cmd_user import mp_user
from rich import print as rich_print
from rich.prompt import Prompt


@Command.with_help("MaxPatrol user role commands tree")
@Command.with_name("role")
@Command
def mp_user_role(_command_context: CommandContext) -> CommandContext:
    """
    User role tree root
    """
    return CommandContext(state=False, state_msg="Wrong command")


@Command.validate(validate_mp_connect)
@Command.with_help("Get MaxPatrol user role list")
@Command.with_name("list")
@Command
def mp_user_role_list(command_context: CommandContext) -> CommandContext:
    """
    User role list
    """
    mp_user_role_list.logger.debug("Run mp user role list")
    try:
        iface_user_role = iface_MP_UserRole()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_user_role_list.logger.error("MP user role API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP user role API init failed: {}".format(err))
    if command_context.is_piped:
        return command_context.instead(context_data=iface_user_role.list, data_fmt="yaml",
                                       data_transform=iface_user_role.reduce_list, force_transform=False,
                                       data_islist_transform=True, table_transform=True)
    else:
        return command_context.instead(context_data=iface_user_role.list, data_fmt="table",
                                       data_transform=iface_user_role.reduce_list,
                                       data_islist_transform=True)


@Command.validate([validate_mp_connect, validate_enable, validate_pipe])
@Command.with_options([
    {"key": "disarm", "required": False, "help": "Run in test mode"},
])
@Command.with_help("Create MaxPatrol user role")
@Command.with_name("create")
@Command
def mp_user_role_create(command_context: CommandContext) -> CommandContext:
    """
    Create MaxPatrol user role from specification
    """
    mp_user_role_create.logger.debug("Run mp user role create")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "type", "privileges", "application"]
        },
        {
            "type": "dict",
            "fields": ["id", "type", "privileges", "application"]
        }
    ])
    if not valid:
        mp_user_role_create.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    # Check mixin
    mixin = func_check_mixin(data=command_context.context_data, kind="user_role", params={})
    if not mixin:
        mp_user_role_create.logger.error("Mixin validation failed - wrong specification?")
        return CommandContext(state=False, state_msg="Mixin validation failed - wrong specification?")
    disarm = "disarm" in command_context.get_kwarg()
    mp_user_role_create.logger.debug("Disarm state: {}".format(disarm))
    try:
        iface_user_role = iface_MP_UserRole(load=False)
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_user_role_create.logger.error("MP user role API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP user role API init failed: {}".format(err))
    if isinstance(command_context.context_data, list):
        for item in command_context.context_data:
            response = iface_user_role.create(source_spec=item, disarm=disarm)
            if not response.state:
                if response.message == "Operation interrupted":
                    return CommandContext(state=False, state_msg="Operation interrupted")
                mp_user_role_create.logger.error("Failed to create user role: {}".format(response.message))
                rich_print("[red]Failed to create user role: {}".format(response.message))
                EVENTS.push(status="Fail", action="Create", instance="User Role",
                            name=item.get("name"), instance_id=item.get("id"), details=response.message)
                continue
            print(response.message)
    else:
        response = iface_user_role.create(source_spec=command_context.context_data, disarm=disarm)
        if not response.state:
            mp_user_role_create.logger.error("Failed to create user role: {}".format(response.message))
            rich_print("[red]Failed to create user role: {}".format(response.message))
        print(response.message)
    EVENTS.checkout()
    mp_user_role_create.logger.debug("User role creation completed")
    return CommandContext(state=True)


@Command.validate(validate_mp_connect)
@Command.with_options([
    {"key": "arg", "required": False, "help": "Role ID or name"},
])
@Command.with_help("Get MaxPatrol role privilege")
@Command.with_name("privilege")
@Command
def mp_user_role_privilege(command_context: CommandContext) -> CommandContext:
    """
    Role privilege information
    """
    mp_user_role_privilege.logger.debug("Run mp user role privilege")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "name", "description", "privileges"]
        },
        {
            "type": "dict",
            "fields": ["id", "name", "description", "privileges"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_user_role_privilege.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_user_role = iface_MP_UserRole()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_user_role_privilege.logger.error("MP user role API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP user role API init failed: {}".format(err))
    privileges_info = False
    if command_context.context_data:
        mp_user_role_privilege.logger.debug("Processing context data")
        if isinstance(command_context.context_data, str):
            privileges_info = iface_user_role.privilege(pattern=command_context.context_data)
        elif isinstance(command_context.context_data, dict):
            privileges_info = iface_user_role.privilege(dct=command_context.context_data)
        else:
            privileges_info = iface_user_role.privilege(lst=command_context.context_data)
        if not privileges_info.state:
            return CommandContext(state=False, state_msg=privileges_info.message)
    if command_context.get_arg():
        mp_user_role_privilege.logger.debug("Processing argument data")
        privileges_info = iface_user_role.privilege(pattern=command_context.get_arg())
        if not privileges_info.state:
            return CommandContext(state=False, state_msg=privileges_info.message)
    if privileges_info:
        privileges_info = privileges_info.message
        EVENTS.checkout()
        return CommandContext(state=True, context_data=privileges_info, data_fmt="yaml",
                              is_piped=command_context.is_piped)
    else:
        EVENTS.checkout()
        return CommandContext(state=False, state_msg="No user role privilege found")


@Command.validate([validate_mp_connect, validate_enable])
@Command.with_options([
    {"key": "arg", "required": False, "help": "User role ID or name"},
    {"key": "quiet", "required": False, "help": "Delete without confirmation"},
    {"key": "disarm", "required": False, "help": "Run in test mode"},
])
@Command.with_help("Delete MaxPatrol user role")
@Command.with_name("delete")
@Command
def mp_user_role_delete(command_context: CommandContext) -> CommandContext:
    """
    Delete user role
    """
    mp_user_role_delete.logger.debug("Run mp template delete")
    quiet = False
    confirm_all = False
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "name", "description", "privileges"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_user_role_delete.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_user_role = iface_MP_UserRole()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_user_role_delete.logger.error("MP user role API init failed: {}".format(err))
        return CommandContext(state=False)
    if command_context.get_kwarg():
        if "quiet" in command_context.get_kwarg():
            mp_user_role_delete.logger.debug("Quiet mode")
            quiet = True
    disarm = "disarm" in command_context.get_kwarg()
    if disarm:
        mp_user_role_delete.logger.debug("Disarm mode")
        quiet = True
    role_info = False
    if command_context.context_data:
        if isinstance(command_context.context_data, str):
            role_info = iface_user_role.get_by_pattern(pattern=command_context.context_data)
        if isinstance(command_context.context_data, list):
            role_info = command_context.context_data
        if not role_info:
            mp_user_role_delete.logger.debug("No user role information found")
            return CommandContext(state=False, state_msg="No user role information found")
    if command_context.get_arg():
        role_info = iface_user_role.get_by_pattern(pattern=command_context.get_arg())
        if not role_info:
            mp_user_role_delete.logger.debug("No user role information found")
            return CommandContext(state=False, state_msg="No user role information found")
    if not role_info:
        mp_user_role_delete.logger.debug("No user role information found")
        return CommandContext(state=False, state_msg="No user role information found")
    for item in role_info:
        if item.get("type") == "System":
            rich_print("[yellow]User role {} is system. Skip.".format(item.get("name")))
            mp_user_role_delete.logger.debug("User role {} is system. Skip.".format(item.get("name")))
            continue
        if not quiet and not confirm_all:
            try:
                decision = Prompt.ask("Are you sure to delete user role {}? ".format(item.get("name")),
                                      choices=["y", "n", "a"], default="n")
            except KeyboardInterrupt:
                return CommandContext(state=False, state_msg="Operation interrupted")
            match decision:
                case "n":
                    continue
                case "a":
                    confirm_all = True
        response = iface_user_role.delete(item.get("id"), disarm=disarm)
        if response.state:
            print("MaxPatrol user role {} deleted".format(item.get("name")))
            mp_user_role_delete.logger.info("MaxPatrol user role {} deleted".format(item.get("name")))
            continue
        else:
            return CommandContext(parent=command_context.parent, state=False,
                                  state_msg=response.message)
    return CommandContext(state=True)


mp_user_role.add(mp_user_role_list)
mp_user_role.add(mp_user_role_privilege)
mp_user_role.add(mp_user_role_create)
mp_user_role.add(mp_user_role_delete)
mp_user.add(mp_user_role)
