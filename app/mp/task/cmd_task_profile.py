from rich import print as rich_print
from rich.prompt import Prompt

from app.app import validate_mp_connect, validate_enable, EVENTS
from app.core.command import Command, CommandContext
from app.core.func import validate_pipe
from app.mp.func import func_check_mixin
from app.mp.task.iface_task_profile import iface_MP_TaskProfile

from app.mp.task.cmd_task_root import mp_task


@Command.with_help("MaxPatrol Profile commands tree")
@Command.with_name("profile")
@Command
def mp_task_profile(_command_context: CommandContext) -> CommandContext:
    """
    Task profiles tree root
    """
    return CommandContext(state=False, state_msg="Wrong command")


@Command.validate(validate_mp_connect)
@Command.with_options([
    {"key": "user_only", "required": False, "help": "Get only custom profiles"}
])
@Command.with_help("Get MaxPatrol task profiles list")
@Command.with_name("list")
@Command
def mp_task_profile_list(command_context: CommandContext) -> CommandContext:
    """
    Task profiles list
    """
    mp_task_profile_list.logger.debug("Run mp task profile list")
    try:
        iface_profile = iface_MP_TaskProfile()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_task_profile_list.logger.error("MP task profile API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP task profile API init failed: {}".format(err))
    profiles_list = iface_profile.list
    if "user_only" in command_context.get_kwarg():
        profiles_list = iface_profile.remove_builtin(profiles_list)
    return command_context.instead(context_data=profiles_list, data_fmt="table",
                                   data_transform=iface_profile.reduce_list,
                                   data_islist_transform=True)


@Command.validate(validate_mp_connect)
@Command.with_options([
    {"key": "arg", "required": False, "help": "Profile ID or name"},
])
@Command.with_help("Get MaxPatrol task profile information")
@Command.with_name("info")
@Command
def mp_task_profile_info(command_context: CommandContext) -> CommandContext:
    """
    Task profile information
    """
    mp_task_profile_info.logger.debug("Run mp task profile info")
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
        mp_task_profile_info.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_profile = iface_MP_TaskProfile()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_task_profile_info.logger.error("MP task profile API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP task profile API init failed: {}".format(err))
    profile_info = False
    if command_context.context_data:
        mp_task_profile_info.logger.debug("Processing context data")
        if isinstance(command_context.context_data, str):
            profile_info = iface_profile.info(pattern=command_context.context_data)
        elif isinstance(command_context.context_data, dict):
            profile_info = iface_profile.info(dct=command_context.context_data)
        else:
            profile_info = iface_profile.info(lst=command_context.context_data)
        if not profile_info.state:
            mp_task_profile_info.logger.debug("No profile information found")
            return CommandContext(state=False, state_msg="No profile information found")
    if command_context.get_arg():
        mp_task_profile_info.logger.debug("Processing argument data")
        profile_info = iface_profile.info(pattern=command_context.get_arg())
        if not profile_info.state:
            mp_task_profile_info.logger.debug("No profile information found")
            return CommandContext(state=False, state_msg="No profile information found")
    if profile_info:
        profile_info = profile_info.message
        EVENTS.checkout()
        return command_context.instead(context_data=profile_info, data_fmt="yaml",
                                       data_transform=iface_profile.reduce_info,
                                       data_islist_transform=True, force_transform=False, table_transform=True)
    else:
        EVENTS.checkout()
        return CommandContext(state=False, state_msg="No profile information found")


@Command.validate([validate_mp_connect, validate_enable, validate_pipe])
@Command.with_options([
    {"key": "disarm", "required": False, "help": "Run in test mode"},
])
@Command.with_help("Create MaxPatrol scanning profile from specification")
@Command.with_name("create")
@Command
def mp_task_profile_create(command_context: CommandContext) -> CommandContext:
    """
    Create task profile from specification
    """
    mp_task_profile_create.logger.debug("Run mp task profile create")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "name", "isSystem", "overrides", "baseProfileName", "baseProfileId"]
        },
        {
            "type": "dict",
            "fields": ["id", "name", "isSystem", "overrides", "baseProfileName", "baseProfileId"]
        }
    ])
    if not valid:
        mp_task_profile_create.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    # Check mixin
    mixin = func_check_mixin(data=command_context.context_data, kind="profile")
    if not mixin:
        mp_task_profile_create.logger.error("Mixin validation failed")
        return CommandContext(state=False, state_msg="Mixin validation failed - wrong specification?")
    disarm = "disarm" in command_context.get_kwarg()
    mp_task_profile_create.logger.debug("Disarm state: {}".format(disarm))
    try:
        iface_profile = iface_MP_TaskProfile()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_task_profile_create.logger.error("MP task profile API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP task profile API init failed: {}".format(err))
    # Looking for list of profile specs
    if isinstance(command_context.context_data, list):
        for item in command_context.context_data:
            response = iface_profile.create(raw_spec=item, disarm=disarm)
            if not response.state:
                if response.message == "Operation interrupted":
                    return CommandContext(state=False, state_msg="Operation interrupted")
                mp_task_profile_create.logger.error("Failed to create profile: {}".format(response.message))
                rich_print("[red]Failed to create profile: {}".format(response.message))
                EVENTS.push(status="Fail", action="Create", instance="Profile",
                            name=item.get("name"), instance_id=item.get("id"),
                            details=str(response.message))
                continue
            print(response.message)
    else:
        response = iface_profile.create(raw_spec=command_context.context_data, disarm=disarm)
        if not response.state:
            mp_task_profile_create.logger.error("Failed to create profile: {}".format(response.message))
            rich_print("[red]Failed to create profile: {}".format(response.message))
            EVENTS.push(status="Fail", action="Create", instance="Profile",
                        name=command_context.context_data["name"], instance_id=command_context.context_data["id"],
                        details=str(response.message))
        print(response.message)
    EVENTS.checkout()
    mp_task_profile_create.logger.debug("Profile creation completed")
    return CommandContext(state=True)


@Command.validate([validate_mp_connect, validate_enable])
@Command.with_options([
    {"key": "arg", "required": False, "help": "Profile ID or name"},
    {"key": "quiet", "required": False, "help": "Delete without confirmation"},
    {"key": "disarm", "required": False, "help": "Run in test mode"},
])
@Command.with_help("Delete MaxPatrol task profile")
@Command.with_name("delete")
@Command
def mp_task_profile_delete(command_context: CommandContext) -> CommandContext:
    """
    Delete scan profile
    """
    mp_task_profile_delete.logger.debug("Run mp task profile delete")
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
        mp_task_profile_delete.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_profile = iface_MP_TaskProfile()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_task_profile_delete.logger.error("MP task profile API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP task profile API init failed: {}".format(err))
    if command_context.get_kwarg():
        if "quiet" in command_context.get_kwarg():
            mp_task_profile_delete.logger.debug("Quiet mode")
            quiet = True
    disarm = "disarm" in command_context.get_kwarg()
    if disarm:
        mp_task_profile_delete.logger.debug("Disarm mode")
        quiet = True
    profile_info = False
    if command_context.context_data:
        if isinstance(command_context.context_data, str):
            profile_info = iface_profile.info(pattern=command_context.context_data)
        if isinstance(command_context.context_data, list):
            profile_info = iface_profile.info(lst=command_context.context_data)
        if not profile_info.state:
            mp_task_profile_delete.logger.debug("No profile information found")
            return CommandContext(state=False, state_msg="No profile information found")
    if command_context.get_arg():
        profile_info = iface_profile.info(pattern=command_context.get_arg())
        if not profile_info.state:
            mp_task_profile_delete.logger.debug("No profile information found")
            return CommandContext(state=False, state_msg="No profile information found")
    if not profile_info:
        mp_task_profile_delete.logger.debug("No profile information found")
        return CommandContext(state=False, state_msg="No profile information found")
    profile_info = profile_info.message
    for item in profile_info:
        if item["isSystem"]:
            rich_print("[yellow]Profile {} is system profile. Skip.".format(item.get("name")))
            mp_task_profile_delete.logger.debug("Profile {} is system profile. Skip.".format(item.get("name")))
            continue
        if not quiet and not confirm_all:
            try:
                decision = Prompt.ask("Are you sure to delete profile {}? ".format(item.get("name")),
                                      choices=["y", "n", "a"], default="n")
            except KeyboardInterrupt:
                return CommandContext(state=False, state_msg="Operation interrupted")
            match decision:
                case "n":
                    continue
                case "a":
                    confirm_all = True
        response = iface_profile.delete(item.get("id"), disarm=disarm)
        if response.state:
            print("MaxPatrol profile {} deleted".format(item.get("name")))
            mp_task_profile_delete.logger.info("MaxPatrol profile {} deleted".format(item.get("name")))
            continue
        else:
            return CommandContext(parent=command_context.parent, state=False,
                                  state_msg=response.message)
    return CommandContext(state=True)


mp_task_profile.add(mp_task_profile_list)
mp_task_profile.add(mp_task_profile_info)
mp_task_profile.add(mp_task_profile_create)
mp_task_profile.add(mp_task_profile_delete)
mp_task.add(mp_task_profile)
