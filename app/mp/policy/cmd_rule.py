from app.app import validate_mp_connect, validate_enable, EVENTS
from app.core.command import Command, CommandContext
from app.mp.policy.iface_policy import iface_MP_Policy
from app.mp.policy.cmd_policy import mp_policy
from app.core.func import validate_pipe
from app.mp.func import func_check_mixin
from rich import print as rich_print
from rich.prompt import Prompt


@Command.validate(validate_mp_connect)
@Command.with_options([
    {"key": "arg", "required": False, "help": "Rule ID or name"},
])
@Command.with_help("MaxPatrol policy rule information")
@Command.with_name("rule")
@Command
def mp_policy_rule(command_context: CommandContext) -> CommandContext:
    """
    Policy rule information
    """
    mp_policy_rule.logger.debug("Run mp policy rule information")
    try:
        iface_policy = iface_MP_Policy()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_policy_rule.logger.error("MP policy API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP policy API init failed: {}".format(err))
    rule_info = None
    if command_context.get_arg():
        mp_policy_rule.logger.debug("Processing argument data")
        rule_info = iface_policy.rule(pattern=command_context.get_arg())
        if not rule_info.state:
            mp_policy.logger.debug(rule_info.message)
            return CommandContext(state=False, state_msg=rule_info.message)
    if rule_info:
        rules_info = rule_info.message
        EVENTS.checkout()
        return command_context.instead(context_data=rules_info, data_fmt="yaml",
                                       data_transform=iface_policy.reduce_policy_information,
                                       data_islist_transform=True, table_transform=True)
    else:
        EVENTS.checkout()
        return CommandContext(state=False, state_msg="No policy rule information found")


@Command.validate([validate_mp_connect, validate_enable])
@Command.with_options([
    {"key": "arg", "required": False, "help": "Rule ID or name"},
    {"key": "disarm", "required": False, "help": "Run in test mode"},
    {"key": "quiet", "required": False, "help": "Delete without confirmation"}
])
@Command.with_help("Delete MaxPatrol policy rule")
@Command.with_name("delete")
@Command
def mp_policy_rule_delete(command_context: CommandContext) -> CommandContext:
    """
    Delete policy rule
    """
    mp_policy_rule_delete.logger.debug("Run mp delete policy rule")
    quiet = False
    confirm_all = False
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "name", "condition", "actionResult"]
        },
        {
            "type": "dict",
            "fields": ["id", "name", "condition", "actionResult"]
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_policy_rule_delete.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_policy = iface_MP_Policy()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_policy_rule_delete.logger.error("MP policy API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP policy API init failed: {}".format(err))
    if command_context.get_kwarg():
        if "quiet" in command_context.get_kwarg():
            mp_policy_rule_delete.logger.debug("Quiet mode")
            quiet = True
    disarm = "disarm" in command_context.get_kwarg()
    if disarm:
        disarm = True
        mp_policy_rule_delete.logger.debug("Disarm mode")
        quiet = True
    rule_info = None
    if command_context.get_arg():
        mp_policy.logger.debug("Processing argument data")
        rule_info = iface_policy.rule(pattern=command_context.get_arg())
        if not rule_info.state:
            mp_policy.logger.error(rule_info.message)
            return CommandContext(state=False, state_msg=rule_info.message)
        rule_info = rule_info.message
    if command_context.context_data:
        if isinstance(command_context.context_data, list):
            rule_info = command_context.context_data
        else:
            rule_info = [command_context.context_data]
    if rule_info:
        for item in rule_info:
            if not quiet and not confirm_all:
                try:
                    decision = Prompt.ask("Are you sure to delete policy rule {}? ".format(item.get("name")),
                                          choices=["y", "n", "a"], default="n")
                except KeyboardInterrupt:
                    return CommandContext(state=False, state_msg="Operation interrupted")
                match decision:
                    case "n":
                        continue
                    case "a":
                        confirm_all = True
            response = iface_policy.delete(item.get("type"), item.get("id"), disarm)
            if response.state:
                print(response.message)
                mp_policy_rule_delete.logger.info("Policy rule {} deleted".format(item.get("name")))
                continue
            else:
                return CommandContext(state=False, state_msg=response.message)
        EVENTS.checkout()
        return CommandContext(state=True)
    else:
        EVENTS.checkout()
        return CommandContext(state=False, state_msg="No policy rule information found")


@Command.validate([validate_mp_connect, validate_enable, validate_pipe])
@Command.with_options([
    {"key": "disarm", "required": False, "help": "Run in test mode"},
])
@Command.with_help("Create MaxPatrol policy rule")
@Command.with_name("create")
@Command
def mp_policy_rule_create(command_context: CommandContext) -> CommandContext:
    """
    Create MaxPatrol policy rule from specification
    """
    mp_policy_rule_create.logger.debug("Run mp policy create")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "name", "condition", "actionResult"]
        },
        {
            "type": "dict",
            "fields": ["id", "name", "condition", "actionResult"]
        }
    ])
    if not valid:
        mp_policy_rule_create.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    # Check mixin
    mixin = func_check_mixin(data=command_context.context_data, kind="policy_rule", params={})
    if not mixin:
        mp_policy_rule_create.logger.error("Mixin validation failed - wrong specification?")
        return CommandContext(state=False, state_msg="Mixin validation failed - wrong specification?")
    disarm = "disarm" in command_context.get_kwarg()
    mp_policy_rule_create.logger.debug("Disarm state: {}".format(disarm))
    try:
        iface_policy = iface_MP_Policy()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_policy_rule_create.logger.error("MP policy API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP policy API init failed: {}".format(err))
    # Looking for list of policy rule specs
    if isinstance(command_context.context_data, list):
        for item in command_context.context_data:
            response = iface_policy.create(source_spec=item, disarm=disarm)
            if not response.state:
                if response.message == "Operation interrupted":
                    return CommandContext(state=False, state_msg="Operation interrupted")
                mp_policy_rule_create.logger.error("Failed to create policy rule: {}".format(response.message))
                rich_print("[red]Failed to create policy rule: {}".format(response.message))
                EVENTS.push(status="Fail", action="Create", instance="Rule",
                            name=item.get("name"), instance_id=item.get("id"), details=response.message)
                continue
            print(response.message)
    else:
        response = iface_policy.create(source_spec=command_context.context_data, disarm=disarm)
        if not response.state:
            mp_policy_rule_create.logger.error("Failed to create policy rule: {}".format(response.message))
            rich_print("[red]Failed to create policy rule: {}".format(response.message))
        print(response.message)
    EVENTS.checkout()
    mp_policy_rule_create.logger.debug("Policy creation completed")
    return CommandContext(state=True)


@Command.validate([validate_mp_connect, validate_enable])
@Command.with_options([
    {"key": "arg", "required": True, "help": "Rule ID or name"},
    {"key": "disarm", "required": False, "help": "Run in test mode"}
])
@Command.with_help("Move policy rule up in list")
@Command.with_name("up")
@Command
def mp_policy_rule_up(command_context: CommandContext) -> CommandContext:
    """
    Move policy rule up in list
    """
    mp_policy_rule_up.logger.debug("Run mp policy rule up")
    try:
        iface_policy = iface_MP_Policy()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_policy_rule_up.logger.error("MP policy API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP policy API init failed: {}".format(err))
    rule_info = None
    disarm = "disarm" in command_context.get_kwarg()
    if disarm:
        disarm = True
        mp_policy_rule_up.logger.debug("Disarm mode")
    if command_context.get_arg():
        mp_policy_rule_up.logger.debug("Processing argument data")
        rule_info = iface_policy.rule(pattern=command_context.get_arg())
        if not rule_info.state:
            mp_policy_rule_up.logger.debug(rule_info.message)
            return CommandContext(state=False, state_msg=rule_info.message)
    if rule_info:
        rule_info = rule_info.message[0]
        # Getting all policy rules
        policy_rules = iface_policy.info(policy_id_pattern=rule_info.get("type"))
        if not policy_rules.state:
            return CommandContext(state=False, state_msg=policy_rules.message)
        # Get rule neighbors
        previous, subsequent = iface_policy.get_rule_neighbors(policy_rules.message, rule_info.get("id"))
        if not previous:
            return CommandContext(state=True, state_msg="Rule {} already on top".format(rule_info.get("name")))
        # Get previous rule neighbors
        previous, subsequent = iface_policy.get_rule_neighbors(policy_rules.message, previous)
        response = iface_policy.set_preceding(rule_info.get("type"), rule_info.get("id"), previous, disarm=disarm)
        if not response.state:
            return CommandContext(state=False, state_msg=response.message)
        return CommandContext(state=True, state_msg=response.message)
    else:
        EVENTS.checkout()
        return CommandContext(state=False, state_msg="No policy rule information found")


@Command.validate([validate_mp_connect, validate_enable])
@Command.with_options([
    {"key": "arg", "required": True, "help": "Rule ID or name"},
    {"key": "disarm", "required": False, "help": "Run in test mode"}
])
@Command.with_help("Move policy rule down in list")
@Command.with_name("down")
@Command
def mp_policy_rule_down(command_context: CommandContext) -> CommandContext:
    """
    Move policy rule down in list
    """
    mp_policy_rule_down.logger.debug("Run mp policy rule down")
    try:
        iface_policy = iface_MP_Policy()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_policy_rule_down.logger.error("MP policy API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP policy API init failed: {}".format(err))
    rule_info = None
    disarm = "disarm" in command_context.get_kwarg()
    if disarm:
        disarm = True
        mp_policy_rule_down.logger.debug("Disarm mode")
    if command_context.get_arg():
        mp_policy.logger.debug("Processing argument data")
        rule_info = iface_policy.rule(pattern=command_context.get_arg())
        if not rule_info.state:
            mp_policy_rule_down.logger.debug(rule_info.message)
            return CommandContext(state=False, state_msg=rule_info.message)
    if rule_info:
        rule_info = rule_info.message[0]
        # Getting all policy rules
        policy_rules = iface_policy.info(policy_id_pattern=rule_info.get("type"))
        if not policy_rules.state:
            return CommandContext(state=False, state_msg=policy_rules.message)
        # Get rule neighbors
        previous, subsequent = iface_policy.get_rule_neighbors(policy_rules.message, rule_info.get("id"))
        if not subsequent:
            return CommandContext(state=True, state_msg="Rule {} already on bottom".format(rule_info.get("name")))
        response = iface_policy.set_preceding(rule_info.get("type"), rule_info.get("id"), subsequent, disarm=disarm)
        if not response.state:
            return CommandContext(state=False, state_msg=response.message)
        return CommandContext(state=True, state_msg=response.message)
    else:
        EVENTS.checkout()
        return CommandContext(state=False, state_msg="No policy rule information found")


@Command.validate([validate_mp_connect, validate_enable])
@Command.with_options([
    {"key": "arg", "required": True, "help": "Rule ID or name"},
    {"key": "disarm", "required": False, "help": "Run in test mode"}
])
@Command.with_help("Move policy rule in top of list")
@Command.with_name("top")
@Command
def mp_policy_rule_top(command_context: CommandContext) -> CommandContext:
    """
    Move policy rule in top of list
    """
    mp_policy_rule_top.logger.debug("Run mp policy rule top")
    try:
        iface_policy = iface_MP_Policy()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_policy_rule_top.logger.error("MP policy API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP policy API init failed: {}".format(err))
    rule_info = None
    disarm = "disarm" in command_context.get_kwarg()
    if disarm:
        disarm = True
        mp_policy_rule_top.logger.debug("Disarm mode")
    if command_context.get_arg():
        mp_policy_rule_top.logger.debug("Processing argument data")
        rule_info = iface_policy.rule(pattern=command_context.get_arg())
        if not rule_info.state:
            mp_policy.logger.debug(rule_info.message)
            return CommandContext(state=False, state_msg=rule_info.message)
    if rule_info:
        rule_info = rule_info.message[0]
        # Getting all policy rules
        policy_rules = iface_policy.info(policy_id_pattern=rule_info.get("type"))
        if not policy_rules.state:
            return CommandContext(state=False, state_msg=policy_rules.message)
        # Get rule neighbors
        previous, subsequent = iface_policy.get_rule_neighbors(policy_rules.message, rule_info.get("id"))
        if not previous:
            return CommandContext(state=True, state_msg="Rule {} already on top".format(rule_info.get("name")))
        response = iface_policy.set_preceding(rule_info.get("type"), rule_info.get("id"), preceding_id=None,
                                              disarm=disarm)
        if not response.state:
            return CommandContext(state=False, state_msg=response.message)
        return CommandContext(state=True, state_msg=response.message)
    else:
        EVENTS.checkout()
        return CommandContext(state=False, state_msg="No policy rule information found")


@Command.validate([validate_mp_connect, validate_enable])
@Command.with_options([
    {"key": "arg", "required": True, "help": "Rule ID or name"},
    {"key": "disarm", "required": False, "help": "Run in test mode"}
])
@Command.with_help("Move policy rule in bottom of list")
@Command.with_name("bottom")
@Command
def mp_policy_rule_bottom(command_context: CommandContext) -> CommandContext:
    """
    Move policy rule in bottom of list
    """
    mp_policy_rule_bottom.logger.debug("Run mp policy rule bottom")
    try:
        iface_policy = iface_MP_Policy()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_policy_rule_bottom.logger.error("MP policy API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP policy API init failed: {}".format(err))
    rule_info = None
    disarm = "disarm" in command_context.get_kwarg()
    if disarm:
        disarm = True
        mp_policy_rule_bottom.logger.debug("Disarm mode")
    if command_context.get_arg():
        mp_policy_rule_bottom.logger.debug("Processing argument data")
        rule_info = iface_policy.rule(pattern=command_context.get_arg())
        if not rule_info.state:
            mp_policy.logger.debug(rule_info.message)
            return CommandContext(state=False, state_msg=rule_info.message)
    if rule_info:
        rule_info = rule_info.message[0]
        # Getting all policy rules
        policy_rules = iface_policy.info(policy_id_pattern=rule_info.get("type"))
        if not policy_rules.state:
            return CommandContext(state=False, state_msg=policy_rules.message)
        # Get rule neighbors
        previous, subsequent = iface_policy.get_rule_neighbors(policy_rules.message, rule_info.get("id"))
        if not subsequent:
            return CommandContext(state=True, state_msg="Rule {} already on bottom".format(rule_info.get("name")))
        # Look bottom policy
        bottom = None
        for item in policy_rules.message:
            _, subsequent = iface_policy.get_rule_neighbors(policy_rules.message, item.get("id"))
            if not subsequent:
                bottom = item.get("id")
        response = iface_policy.set_preceding(rule_info.get("type"), rule_info.get("id"), preceding_id=bottom,
                                              disarm=disarm)
        if not response.state:
            return CommandContext(state=False, state_msg=response.message)
        return CommandContext(state=True, state_msg=response.message)
    else:
        EVENTS.checkout()
        return CommandContext(state=False, state_msg="No policy rule information found")


mp_policy_rule.add(mp_policy_rule_up)
mp_policy_rule.add(mp_policy_rule_down)
mp_policy_rule.add(mp_policy_rule_top)
mp_policy_rule.add(mp_policy_rule_bottom)
mp_policy_rule.add(mp_policy_rule_delete)
mp_policy_rule.add(mp_policy_rule_create)
mp_policy.add(mp_policy_rule)
