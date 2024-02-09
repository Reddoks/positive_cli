from app.app import validate_mp_connect
from app.core.command import Command, CommandContext
from app.mp.cmd_mp import mp
from app.mp.aec.iface_aec import iface_MP_AEC


@Command.with_help("MaxPatrol AEC commands tree")
@Command.with_name("aec")
@Command
def mp_aec(_command_context: CommandContext) -> CommandContext:
    """
    AEC command tree root
    """
    return CommandContext(state=False, state_msg="Wrong command")


@Command.validate(validate_mp_connect)
@Command.with_help("Get MaxPatrol AECs list")
@Command.with_name("list")
@Command
def mp_aec_list(command_context: CommandContext) -> CommandContext:
    """
    AEC list
    """
    mp_aec_list.logger.debug("Run mp AECs list")
    try:
        iface_aec = iface_MP_AEC()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_aec_list.logger.error("MP AEC API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP AEC API init failed: {}".format(err))
    if isinstance(iface_aec.list, list):
        return command_context.instead(context_data=iface_aec.list, data_fmt="table",
                                       data_transform=iface_aec.reduce_list,
                                       data_islist_transform=True)
    else:
        return command_context.instead(context_data=iface_aec.list, data_fmt="table",
                                       data_transform=iface_aec.reduce_list)


@Command.validate(validate_mp_connect)
@Command.with_options([
    {"key": "arg", "required": False, "help": "AEC ID or name"},
])
@Command.with_help("Get MaxPatrol AEC information")
@Command.with_name("info")
@Command
def mp_aec_info(command_context: CommandContext) -> CommandContext:
    """
    AEC information
    """
    mp_aec_info.logger.debug("Run mp AEC info")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "name", "siemId"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_aec_info.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_aec = iface_MP_AEC()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_aec_info.logger.error("MP AEC API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP AEC API init failed: {}".format(err))
    aec_info = False
    if command_context.context_data:
        mp_aec_info.logger.debug("Processing context data")
        if isinstance(command_context.context_data, str):
            aec_info = iface_aec.info(pattern=command_context.context_data)
        else:
            aec_info = iface_aec.info(lst=command_context.context_data)
        if not aec_info.state:
            mp_aec_info.logger.debug("No AEC information found")
            return CommandContext(state=False, state_msg="No AEC information found")
    if command_context.get_arg():
        mp_aec_info.logger.debug("Processing argument data")
        aec_info = iface_aec.info(pattern=command_context.get_arg())
        if not aec_info.state:
            mp_aec_info.logger.debug("No AEC information found")
            return CommandContext(state=False, state_msg="No AEC information found")
    if aec_info:
        aec_info = aec_info.message
        return command_context.instead(context_data=aec_info, data_fmt="yaml", data_transform="reset",
                                       data_islist_transform=False, force_transform=False)
    else:
        return CommandContext(state=False, state_msg="No AEC information found")


mp_aec.add(mp_aec_list)
mp_aec.add(mp_aec_info)
mp.add(mp_aec)
