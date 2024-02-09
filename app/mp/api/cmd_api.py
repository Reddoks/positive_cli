import app
from app.app import validate_mp_connect
from app.core.command import Command, CommandContext
from app.mp.func import func_select_list_item
from app.mp.cmd_mp import mp
from app.mp.api.iface_api import iface_MP_APIProfiles
from app.mp.iface_api import iface_MP_API
from rich.prompt import Prompt


@Command.with_help("MaxPatrol API commands tree")
@Command.with_name("api")
@Command
def mp_api(_command_context: CommandContext) -> CommandContext:
    """
    API connection profiles tree root
    """
    return CommandContext(state=False, state_msg="Wrong command")


@Command.with_help("List API connection profiles")
@Command.with_name("list")
@Command
def mp_api_list(command_context: CommandContext) -> CommandContext:
    """
    List API connection profiles
    """
    try:
        api_profiles_api = iface_MP_APIProfiles()
    except BaseException as err:
        mp_api_list.logger.error("Failed to init connection API: {}".format(err))
        return CommandContext(state=False, state_msg="Failed to init connection API: {}".format(err))
    return command_context.instead(context_data=api_profiles_api.list, data_fmt="table",
                                   data_transform=api_profiles_api.reduce_list)


@Command.with_help("API connection profiles information")
@Command.with_name("info")
@Command
def mp_api_info(command_context: CommandContext) -> CommandContext:
    """
    Get API connection profiles information
    """
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["name", "host", "secret"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_api_info.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_api_profile = iface_MP_APIProfiles()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_api_info.logger.error("Failed to init connection API: {}".format(err))
        return CommandContext(state=False, state_msg="Failed to init connection API: {}".format(err))
    profile_info = False
    if command_context.context_data:
        if isinstance(command_context.context_data, str):
            profile_info = []
            profile = iface_api_profile.find_by_name(command_context.context_data)
            if profile:
                for item in profile:
                    profile_info.append(item)
            else:
                mp_api_info.logger.error("API profile {} not found".format(command_context.context_data))
                return CommandContext(state=False,
                                      state_msg="API profile {} not found".format(command_context.context_data))
        if isinstance(command_context.context_data, list):
            profile_info = []
            for item in command_context.context_data:
                profile = iface_api_profile.find_by_name(item.get("name"))
                if profile:
                    for itm in profile:
                        profile_info.append(itm)
                else:
                    mp_api_info.logger.error("API profile {} not found".format(item.get("name")))
                    print("API profile {} not found".format(item.get("name")))
    if command_context.get_arg():
        profile_info = []
        profile = iface_api_profile.find_by_name(command_context.get_arg())
        if profile:
            for item in profile:
                profile_info.append(item)
        else:
            mp_api_info.logger.error("API profile {} not found".format(command_context.get_arg()))
            return CommandContext(state=False,
                                  state_msg="API profile {} not found".format(command_context.get_arg()))
    if profile_info:
        return command_context.instead(context_data=profile_info, data_fmt="yaml", data_transform="reset")
    else:
        return CommandContext(state=True)


@Command.with_help("Set default API profile")
@Command.with_options([
    {"key": "arg", "required": True, "help": "API profile name"}
])
@Command.with_name("default")
@Command
def mp_api_default(command_context: CommandContext) -> CommandContext:
    """
    Set default API connection profile
    """
    try:
        iface_api_profile = iface_MP_APIProfiles()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_api_list.logger.error("Failed to init connection API: {}".format(err))
        return CommandContext(state=False, state_msg="Failed to init connection API: {}".format(err))
    response = iface_api_profile.set_default(command_context.get_arg())
    if not response.state:
        return CommandContext(state=False, state_msg=response.message)
    return CommandContext(state=True, state_msg=response.message)


# MaxPatrol create API profile
@Command.with_help("Create API connection profiles")
@Command.with_options([
    {"key": "name", "required": False, "help": "Profile name"},
    {"key": "host", "required": False, "help": "Host FQDN or IP address"},
    {"key": "secret", "required": False, "help": "Client secret string"},
    {"key": "api_port", "required": False, "help": "API port. Default:3334"},
    {"key": "front_port", "required": False, "help": "Frontend port. Default:443"},
    {"key": "default", "required": False, "help": "Make profile default. Default:False"},
    {"key": "disarm", "required": False, "help": "Run in test mode"},
])
@Command.with_name("create")
@Command
def mp_api_create(command_context: CommandContext) -> CommandContext:
    """
    Create API connection profile from specification
    """
    mp_api_create.logger.debug("Run mp api profile create")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["name", "host", "secret"]
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_api_create.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    disarm = "disarm" in command_context.get_kwarg()
    mp_api_create.logger.debug("Disarm state: {}".format(disarm))
    try:
        iface_api_profile = iface_MP_APIProfiles()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_api_create.logger.error("Failed to init connection API: {}".format(err))
        return CommandContext(state=False, state_msg="Failed to init connection API: {}".format(err))
    if isinstance(command_context.context_data, list):
        for item in command_context.context_data:
            response = iface_api_profile.create(item, disarm=disarm)
            if not response.state:
                return CommandContext(state=False, state_msg=response.message)
            return CommandContext(state=True, state_msg=response.message)
    # If no piped data
    if not command_context.is_piped:
        spec = iface_api_profile.get_spec_from_params(
            name=command_context.get_kwarg("name"),
            host=command_context.get_kwarg("host"),
            secret=command_context.get_kwarg("secret"),
            api_port=command_context.get_kwarg("api_port"),
            front_port=command_context.get_kwarg("front_port"),
            default=bool(command_context.get_kwarg("default"))
        )
        if not spec:
            return CommandContext(state=False, state_msg="Operation interrupted")
        response = iface_api_profile.create(spec, disarm=disarm)
        if not response.state:
            return CommandContext(state=False, state_msg=response.message)
        return CommandContext(state=True, state_msg=response.message)
    return CommandContext(state=False, state_msg="Failed to create - something went wrong")


# MaxPatrol delete API profile
@Command.with_help("Delete API connection profiles")
@Command.with_options([
    {"key": "arg", "required": False, "help": "API profile name"},
    {"key": "quiet", "required": False, "help": "Delete without confirmation"},
    {"key": "disarm", "required": False, "help": "Run in test mode"}
])
@Command.with_name("delete")
@Command
def mp_api_delete(command_context: CommandContext) -> CommandContext:
    """
    Delete API connection profile
    """
    mp_api_delete.logger.debug("Run mp api profile delete")
    quiet = False
    confirm_all = False
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["name", "host", "secret"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_api_delete.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_api_profile = iface_MP_APIProfiles()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_api_delete.logger.error("Failed to init connection API: {}".format(err))
        return CommandContext(state=False, state_msg="Failed to init connection API: {}".format(err))
    if command_context.get_kwarg():
        if "quiet" in command_context.get_kwarg():
            mp_api_delete.logger.debug("Quiet mode")
            quiet = True
    disarm = "disarm" in command_context.get_kwarg()
    if disarm:
        mp_api_delete.logger.debug("Disarm mode")
        quiet = True
    profile_info = False
    if command_context.context_data:
        if isinstance(command_context.context_data, str):
            profile_info = []
            profile = iface_api_profile.find_by_name(command_context.context_data)
            if profile:
                for item in profile:
                    profile_info.append(item.get("name"))
            else:
                mp_api_delete.logger.error("API profile {} not found".format(command_context.context_data))
                return CommandContext(state=False,
                                      state_msg="API profile {} not found".format(command_context.context_data))
        if isinstance(command_context.context_data, list):
            profile_info = []
            for item in command_context.context_data:
                profile = iface_api_profile.find_by_name(item.get("name"))
                if profile:
                    for itm in profile:
                        profile_info.append(itm.get("name"))
                else:
                    mp_api_delete.logger.error("API profile {} not found".format(item.get("name")))
                    print("API profile {} not found".format(item.get("name")))
    if command_context.get_arg():
        profile_info = []
        profile = iface_api_profile.find_by_name(command_context.get_arg())
        if profile:
            for item in profile:
                profile_info.append(item["name"])
        else:
            mp_api_delete.logger.error("API profile {} not found".format(command_context.get_arg()))
            return CommandContext(state=False,
                                  state_msg="API profile {} not found".format(command_context.get_arg()))
    if profile_info:
        disarm = "disarm" in command_context.get_kwarg()
        for item in profile_info:
            if not quiet and not confirm_all:
                try:
                    decision = Prompt.ask("[yellow]Are you sure to delete API profile {}? ".format(item),
                                          choices=["y", "n", "a"], default="n")
                except KeyboardInterrupt:
                    return CommandContext(state=False, state_msg="Operation interrupted")
                match decision:
                    case "a":
                        confirm_all = True
                        continue
                    case "n":
                        return CommandContext(state=False, state_msg="User canceled")
            response = iface_api_profile.delete(item, disarm=disarm)
            if response.state:
                print("API profile {} deleted".format(item))
                mp_api_delete.logger.info("API profile {} deleted".format(item))
                continue
            else:
                return CommandContext(state=False, state_msg=response.message)
    return CommandContext(state=True)


# MaxPatrol API connect
@Command.with_help("Connect MaxPatrol API with default or named profile")
@Command.with_options([
    {"key": "arg", "required": False, "help": "Name of profile or regex expression"},
    {"key": "login", "required": False, "help": "Login name."},
    {"key": "password", "required": False, "help": "Password string."},
    {"key": "session", "required": False, "help": "Connect using session."},
    {"key": "host", "required": False, "help": "Host for session connect."},
    {"key": "secret", "required": False, "help": "API secret for session connect."},
])
@Command.with_name("connect")
@Command
def mp_api_connect(command_context: CommandContext) -> CommandContext:
    """
    Connect MaxPatrol API
    """
    mp_api_connect.logger.debug("Run mp api profile connect")
    # Look for credentials
    if not command_context.get_kwarg("login"):
        try:
            login = Prompt.ask("Login name ")
        except KeyboardInterrupt:
            return CommandContext(state=False, state_msg="Operation interrupted")
    else:
        login = command_context.get_kwarg("login")
    if not command_context.get_kwarg("password"):
        try:
            password = Prompt.ask("Password ", password=True)
        except KeyboardInterrupt:
            return CommandContext(state=False, state_msg="Operation interrupted")
    else:
        password = command_context.get_kwarg("password")
    try:
        iface_api_profile = iface_MP_APIProfiles()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_api_create.logger.error("Failed to init connection API: {}".format(err))
        return CommandContext(state=False, state_msg="Failed to init connection API: {}".format(err))
    # Look for profile
    if not command_context.get_kwarg("host"):
        db_profiles = app.DB.table('profiles')
        if not (command_context.get_arg()):
            default_profile = db_profiles.search(app.DBQUERY.default == True) # noqa
            if len(default_profile) > 0:
                profile = default_profile[0]
            else:
                mp_api_connect.logger.info("Connect API profile: No default profile found")
                return CommandContext(state=False,
                                      state_msg="Connect API profile: No default profile found")
        else:
            profile = iface_api_profile.find_by_name(command_context.get_arg())
            if profile:
                if len(profile) > 1:
                    profile = func_select_list_item(profile, woids=True)
                else:
                    profile = profile[0]
            else:
                return CommandContext(state=False,
                                      state_msg="No connection profile found")
    else:
        if not command_context.get_kwarg("host"):
            try:
                host = Prompt.ask("Host ")
            except KeyboardInterrupt:
                return CommandContext(state=False, state_msg="Operation interrupted")
        else:
            host = command_context.get_kwarg("host")
        if not command_context.get_kwarg("secret") and "session" not in command_context.get_kwarg():
            try:
                secret = Prompt.ask("Secret ")
            except KeyboardInterrupt:
                return CommandContext(state=False, state_msg="Operation interrupted")
        else:
            if command_context.get_kwarg("secret"):
                secret = command_context.get_kwarg("secret")
            else:
                secret = ""
        profile = {
            "host": host,
            "secret": secret,
            "api_port": "3334",
            "front_port": "443"
        }
    # Session connect
    if "session" in command_context.get_kwarg():
        app.API_MP = iface_MP_API(
            host=profile.get("host"),
            client_secret="",
            login=login,
            password=password,
            api_port="3334",
            front_port="443"
        )
        result = app.API_MP.session_connect()
        if not result.state:
            mp_api_connect.logger.error("Failed to connect MaxPatrol API session: {}".format(result.message))
            return CommandContext(state=False,
                                  state_msg="Failed to connect MaxPatrol API session: {}".format(result.message))
        mp_api_connect.logger.info("MaxPatrol host {} now connected".format(profile.get("host")))
        app.PROFILE_MP = profile.get("host")
        return CommandContext(state=True, state_msg="MaxPatrol host {} now connected".format(profile.get("host")))
    else:
        app.API_MP = iface_MP_API(
            host=profile.get("host"),
            client_secret=profile.get("secret"),
            login=login,
            password=password,
            api_port=profile.get("api_port"),
            front_port=profile.get("front_port")
        )
        result = app.API_MP.connect()
        if not result.state:
            mp_api_connect.logger.error("Failed to connect MaxPatrol API profile '" + profile["name"] + "'")
            return CommandContext(state=False,
                                  state_msg="Failed to connect MaxPatrol API profile '" + profile["name"] + "': " +
                                  result.message)
        mp_api_connect.logger.info("MaxPatrol host {} now connected".format(profile.get("name")))
        app.PROFILE_MP = profile.get("name")
        return CommandContext(state=True, state_msg="MaxPatrol host {} now connected".format(profile.get("name")))


# MaxPatrol API disconnect
@Command.validate(validate_mp_connect)
@Command.with_help("Disconnect current MaxPatrol API profile")
@Command.with_name("disconnect")
@Command
def mp_api_disconnect(_command_context: CommandContext) -> CommandContext:
    """
    Disconnect MaxPatrol API
    """
    mp_api_disconnect.logger.debug("Run mp api profile disconnect")
    disconnected_profile = app.PROFILE_MP
    app.PROFILE_MP = None
    app.API_MP = None
    mp_api_disconnect.logger.info("MaxPatrol API profile {} disconnected".format(disconnected_profile))
    return CommandContext(state=True, state_msg="MaxPatrol API profile {} disconnected".format(disconnected_profile))


mp_api.add(mp_api_list)
mp_api.add(mp_api_info)
mp_api.add(mp_api_default)
mp_api.add(mp_api_create)
mp_api.add(mp_api_delete)
mp_api.add(mp_api_connect)
mp_api.add(mp_api_disconnect)
mp.add(mp_api)
