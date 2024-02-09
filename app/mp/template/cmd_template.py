from rich import print as rich_print
from rich.prompt import Prompt

from app.app import validate_mp_connect, validate_enable, EVENTS
from app.core.command import Command, CommandContext
from app.core.func import validate_pipe
from app.mp.func import func_check_mixin
from app.mp.template import iface_MP_Template

from app.mp.cmd_mp import mp


@Command.with_help("MaxPatrol template commands tree")
@Command.with_name("template")
@Command
def mp_template(_command_context: CommandContext) -> CommandContext:
    """
    Template tree root
    """
    return CommandContext(state=False, state_msg="Wrong command")


@Command.validate(validate_mp_connect)
@Command.with_options([
    {"key": "user_only", "required": False, "help": "Get only custom templates"}
])
@Command.with_help("Get MaxPatrol templates list")
@Command.with_name("list")
@Command
def mp_template_list(command_context: CommandContext) -> CommandContext:
    """
    Templates list
    """

    def rebuild_user_only(temp_list: list) -> list | None:
        out_list = []
        for item in temp_list:
            if not item.get("system"):
                out_list.append(item)
        if len(out_list) == 0:
            return
        return out_list
    mp_template_list.logger.debug("Run mp template list")
    try:
        iface_template = iface_MP_Template()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_template_list.logger.error("MP template API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP template API init failed: {}".format(err))
    if "user_only" in command_context.get_kwarg():
        template_list = rebuild_user_only(iface_template.list)
    else:
        template_list = iface_template.list
    return command_context.instead(context_data=template_list, data_fmt="table",
                                   data_transform=iface_template.reduce_list,
                                   data_islist_transform=True)


@Command.validate(validate_mp_connect)
@Command.with_options([
    {"key": "arg", "required": False, "help": "Template ID or name"},
])
@Command.with_help("Get MaxPatrol template information")
@Command.with_name("info")
@Command
def mp_template_info(command_context: CommandContext) -> CommandContext:
    """
    Template information
    """
    mp_template_info.logger.debug("Run mp task template info")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "name", "type", "source"]
        },
        {
            "type": "dict",
            "fields": ["id", "name", "type", "source"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_template_info.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_template = iface_MP_Template()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_template_info.logger.error("MP template API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP template API init failed: {}".format(err))
    template_info = False
    if command_context.context_data:
        mp_template_info.logger.debug("Processing context data")
        if isinstance(command_context.context_data, str):
            template_info = iface_template.info(pattern=command_context.context_data,
                                                user_only="user_only" in command_context.get_kwarg())
        elif isinstance(command_context.context_data, dict):
            template_info = iface_template.info(dct=command_context.context_data,
                                                user_only="user_only" in command_context.get_kwarg())
        else:
            template_info = iface_template.info(lst=command_context.context_data,
                                                user_only="user_only" in command_context.get_kwarg())
        if not template_info.state:
            return CommandContext(state=False, state_msg=template_info.message)
    if command_context.get_arg():
        mp_template_info.logger.debug("Processing argument data")
        template_info = iface_template.info(pattern=command_context.get_arg())
        if not template_info.state:
            return CommandContext(state=False, state_msg=template_info.message)
    if template_info:
        template_info = template_info.message
        EVENTS.checkout()
        return command_context.instead(context_data=template_info, data_fmt="yaml",
                                       data_transform=iface_MP_Template.reduce_info,
                                       data_islist_transform=True, force_transform=False,
                                       table_transform=True)
    else:
        EVENTS.checkout()
        return CommandContext(state=False, state_msg="No template information found")


@Command.validate([validate_mp_connect, validate_enable, validate_pipe])
@Command.with_options([
    {"key": "disarm", "required": False, "help": "Run in test mode"},
])
@Command.with_help("Create MaxPatrol template")
@Command.with_name("create")
@Command
def mp_template_create(command_context: CommandContext) -> CommandContext:
    """
    Create MaxPatrol template from specification
    """
    mp_template_create.logger.debug("Run mp template create")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["name", "type", "filter", "settings"]
        },
        {
            "type": "dict",
            "fields": ["name", "type", "filter", "settings"]
        }
    ])
    if not valid:
        mp_template_create.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    # Check mixin
    mixin = func_check_mixin(data=command_context.context_data, kind="template", params={})
    if not mixin:
        mp_template_create.logger.error("Mixin validation failed - wrong specification?")
        return CommandContext(state=False, state_msg="Mixin validation failed - wrong specification?")
    disarm = "disarm" in command_context.get_kwarg()
    mp_template_create.logger.debug("Disarm state: {}".format(disarm))
    try:
        iface_template = iface_MP_Template()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_template_create.logger.error("MP template API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP template API init failed: {}".format(err))
    rich_print("[yellow]Please be aware, templates will be created in current user context")
    if isinstance(command_context.context_data, list):
        for item in command_context.context_data:
            response = iface_template.create(source_spec=item, disarm=disarm)
            if not response.state:
                if response.message == "Operation interrupted":
                    return CommandContext(state=False, state_msg="Operation interrupted")
                mp_template_create.logger.error("Failed to create template: {}".format(response.message))
                rich_print("[red]Failed to create template: {}".format(response.message))
                EVENTS.push(status="Fail", action="Create", instance="Template",
                            name=item.get("name"), instance_id=item.get("id"), details=response.message)
                continue
            print(response.message)
    else:
        response = iface_template.create(source_spec=command_context.context_data, disarm=disarm)
        if not response.state:
            mp_template_create.logger.error("Failed to create template: {}".format(response.message))
            rich_print("[red]Failed to create template: {}".format(response.message))
        print(response.message)
    EVENTS.checkout()
    mp_template_create.logger.debug("Template creation completed")
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
def mp_template_delete(command_context: CommandContext) -> CommandContext:
    """
    Delete template
    """
    mp_template_delete.logger.debug("Run mp template delete")
    quiet = False
    confirm_all = False
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "name", "type", "source"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_template_delete.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_template = iface_MP_Template()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_template_delete.logger.error("MP template API init failed: {}".format(err))
        return CommandContext(state=False)
    if command_context.get_kwarg():
        if "quiet" in command_context.get_kwarg():
            mp_template_delete.logger.debug("Quiet mode")
            quiet = True
    disarm = "disarm" in command_context.get_kwarg()
    if disarm:
        mp_template_delete.logger.debug("Disarm mode")
        quiet = True
    template_info = False
    if command_context.context_data:
        if isinstance(command_context.context_data, str):
            template_info = iface_template.info(pattern=command_context.context_data)
        if isinstance(command_context.context_data, list):
            template_info = iface_template.info(lst=command_context.context_data)
        if not template_info.state:
            mp_template_delete.logger.debug("No template information found")
            return CommandContext(state=False, state_msg="No template information found")
    if command_context.get_arg():
        template_info = iface_template.info(pattern=command_context.get_arg())
        if not template_info.state:
            mp_template_delete.logger.debug("No template information found")
            return CommandContext(state=False, state_msg="No template information found")
    if not template_info:
        mp_template_delete.logger.debug("No template information found")
        return CommandContext(state=False, state_msg="No template information found")
    template_info = template_info.message
    for item in template_info:
        if item.get("system"):
            rich_print("[yellow]Template {} is system template. Skip.".format(item.get("name")))
            mp_template_delete.logger.debug("Template {} is system template. Skip.".format(item.get("name")))
            continue
        if not quiet and not confirm_all:
            try:
                decision = Prompt.ask("Are you sure to delete template {}? ".format(item.get("name")),
                                      choices=["y", "n", "a"], default="n")
            except KeyboardInterrupt:
                return CommandContext(state=False, state_msg="Operation interrupted")
            match decision:
                case "n":
                    continue
                case "a":
                    confirm_all = True
        response = iface_template.delete(item.get("id"), disarm=disarm)
        if response.state:
            print("MaxPatrol template {} deleted".format(item.get("name")))
            mp_template_delete.logger.info("MaxPatrol template {} deleted".format(item.get("name")))
            continue
        else:
            return CommandContext(parent=command_context.parent, state=False,
                                  state_msg=response.message)
    return CommandContext(state=True)


mp_template.add(mp_template_list)
mp_template.add(mp_template_info)
mp_template.add(mp_template_create)
mp_template.add(mp_template_delete)
mp.add(mp_template)
