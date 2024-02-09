from app.app import validate_mp_connect, validate_enable, EVENTS
from app.core.command import Command, CommandContext
from app.mp.cmd_mp import mp
from app.core.func import validate_pipe
from app.mp.func import func_check_mixin
from app.mp.policy.iface_policy import iface_MP_Policy
from rich import print as rich_print


@Command.with_help("MaxPatrol policy commands tree")
@Command.with_name("policy")
@Command
def mp_policy(_command_context: CommandContext) -> CommandContext:
    """
    Policy command tree root
    """
    return CommandContext(state=False, state_msg="Wrong command")


@Command.validate(validate_mp_connect)
@Command.with_help("Get MaxPatrol policy list")
@Command.with_name("list")
@Command
def mp_policy_list(command_context: CommandContext) -> CommandContext:
    """
    Policy list
    """
    mp_policy_list.logger.debug("Run mp policy list")
    try:
        iface_policy = iface_MP_Policy()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_policy_list.logger.error("MP policy API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP policy API init failed: {}".format(err))
    return command_context.instead(context_data=iface_policy.list, data_fmt="table",
                                   data_transform=iface_policy.reduce_policy_list,
                                   data_islist_transform=True)


@Command.validate(validate_mp_connect)
@Command.with_options([
    {"key": "arg", "required": False, "help": "Policy ID"},
])
@Command.with_help("MaxPatrol policy information")
@Command.with_name("info")
@Command
def mp_policy_info(command_context: CommandContext) -> CommandContext:
    """
    Policy information
    """
    mp_policy.logger.debug("Run mp policy information")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["policyId"]
        },
        {
            "type": "dict",
            "fields": ["policyId"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_policy.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_policy = iface_MP_Policy()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_policy.logger.error("MP policy API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP policy API init failed: {}".format(err))
    rules_info = False
    if command_context.context_data:
        mp_policy.logger.debug("Processing context data")
        if isinstance(command_context.context_data, list):
            rules_info = iface_policy.info(policy_lst=command_context.context_data)
        elif isinstance(command_context.context_data, dict):
            rules_info = iface_policy.info(policy_dct=command_context.context_data)
        else:
            rules_info = iface_policy.info(policy_id_pattern=command_context.context_data)
        if not rules_info.state:
            mp_policy.logger.debug(rules_info.message)
            return CommandContext(state=False, state_msg=rules_info.message)
    if command_context.get_arg():
        mp_policy.logger.debug("Processing argument data")
        rules_info = iface_policy.info(policy_id_pattern=command_context.get_arg())
        if not rules_info.state:
            mp_policy.logger.debug(rules_info.message)
            return CommandContext(state=False, state_msg=rules_info.message)
    if rules_info:
        rules_info = rules_info.message
        EVENTS.checkout()
        return command_context.instead(context_data=rules_info, data_fmt="yaml",
                                       data_transform=iface_policy.reduce_policy_information,
                                       data_islist_transform=True, table_transform=True)
    else:
        EVENTS.checkout()
        return CommandContext(state=False, state_msg="No policy information found")


mp_policy.add(mp_policy_list)
mp_policy.add(mp_policy_info)
mp.add(mp_policy)
