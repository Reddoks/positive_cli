from rich import print as rich_print
from rich.prompt import Prompt

from app.app import validate_mp_connect, validate_enable, EVENTS
from app.core.command import Command, CommandContext
from app.core.func import validate_pipe
from app.mp.func import func_check_mixin
from app.mp.report.iface_report_template import iface_MP_Report_Template

from app.mp.report.cmd_report import mp_report


@Command.with_help("MaxPatrol report template commands tree")
@Command.with_name("template")
@Command
def mp_report_template(_command_context: CommandContext) -> CommandContext:
    """
    Report templates tree root
    """
    return CommandContext(state=False, state_msg="Wrong command")


@Command.validate(validate_mp_connect)
@Command.with_options([
    {"key": "user_only", "required": False, "help": "Get only custom report templates"}
])
@Command.with_help("Get MaxPatrol report templates list")
@Command.with_name("list")
@Command
def mp_report_template_list(command_context: CommandContext) -> CommandContext:
    """
    Report templates list
    """
    mp_report_template_list.logger.debug("Run mp report template list")
    try:
        iface_report_template = iface_MP_Report_Template()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_report_template_list.logger.error("MP report template API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP report template API init failed: {}".format(err))
    template_list = iface_report_template.list
    if "user_only" in command_context.get_kwarg():
        template_list = iface_report_template.remove_builtin(template_list)
    return command_context.instead(context_data=template_list, data_fmt="table")


@Command.validate(validate_mp_connect)
@Command.with_options([
    {"key": "arg", "required": False, "help": "Report ID or name"},
])
@Command.with_help("Get MaxPatrol report template information")
@Command.with_name("info")
@Command
def mp_report_template_info(command_context: CommandContext) -> CommandContext:
    """
    Report template information
    """
    mp_report_template_info.logger.debug("Run mp report template info")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "folderId", "name", "isSystem"]
        },
        {
            "type": "dict",
            "fields": ["id", "folderId", "name", "isSystem"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_report_template_info.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_report_template = iface_MP_Report_Template()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_report_template_info.logger.error("MP report template API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP report template API init failed: {}".format(err))
    template_info = False
    if command_context.context_data:
        mp_report_template_info.logger.debug("Processing context data")
        if isinstance(command_context.context_data, str):
            template_info = iface_report_template.info(pattern=command_context.context_data)
        elif isinstance(command_context.context_data, dict):
            template_info = iface_report_template.info(dct=command_context.context_data)
        else:
            template_info = iface_report_template.info(lst=command_context.context_data)
        if not template_info.state:
            return CommandContext(state=False, state_msg=template_info.message)
    if command_context.get_arg():
        mp_report_template_info.logger.debug("Processing argument data")
        template_info = iface_report_template.info(pattern=command_context.get_arg())
        if not template_info.state:
            return CommandContext(state=False, state_msg=template_info.message)
    if template_info:
        template_info = template_info.message
        EVENTS.checkout()
        return command_context.instead(context_data=template_info, data_fmt="yaml")
        # return command_context.instead(context_data=report_info, data_fmt="yaml",
        #                               data_transform=iface_MP_Report.reduce_info,
        #                               data_islist_transform=True, force_transform=False,
        #                               table_transform=True)
    else:
        EVENTS.checkout()
        return CommandContext(state=False, state_msg="No report template information found")


@Command.validate([validate_mp_connect, validate_enable, validate_pipe])
@Command.with_options([
    {"key": "disarm", "required": False, "help": "Run in test mode"},
])
@Command.with_help("Create MaxPatrol report template from specification")
@Command.with_name("create")
@Command
def mp_report_template_create(command_context: CommandContext) -> CommandContext:
    """
    Create report template from specification
    """
    mp_report_template_create.logger.debug("Run mp report template create")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "name", "type", "layout", "schedule"]
        },
        {
            "type": "dict",
            "fields": ["id", "name", "type", "layout", "schedule"]
        }
    ])
    if not valid:
        mp_report_template_create.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    # Check mixin
    mixin = func_check_mixin(data=command_context.context_data, kind="report_template")
    if not mixin:
        mp_report_template_create.logger.error("Mixin validation failed")
        return CommandContext(state=False, state_msg="Mixin validation failed - wrong specification?")
    disarm = "disarm" in command_context.get_kwarg()
    mp_report_template_create.logger.debug("Disarm state: {}".format(disarm))
    try:
        iface_report_template = iface_MP_Report_Template()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_report_template_create.logger.error("MP report template API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP report template API init failed: {}".format(err))
    if isinstance(command_context.context_data, list):
        for item in command_context.context_data:
            response = iface_report_template.create(source_spec=item, disarm=disarm)
            if not response.state:
                if response.message == "Operation interrupted":
                    return CommandContext(state=False, state_msg="Operation interrupted")
                mp_report_template_create.logger.error("Failed to create report template: {}".format(response.message))
                rich_print("[red]Failed to create report template: {}".format(response.message))
                EVENTS.push(status="Fail", action="Create", instance="Report Template",
                            name=item.get("name"), instance_id=item.get("id"),
                            details=str(response.message))
                continue
            print(response.message)
    else:
        response = iface_report_template.create(source_spec=command_context.context_data, disarm=disarm)
        if not response.state:
            mp_report_template_create.logger.error("Failed to create report template: {}".format(response.message))
            rich_print("[red]Failed to create report template: {}".format(response.message))
            EVENTS.push(status="Fail", action="Create", instance="Report Template",
                        name=command_context.context_data["name"], instance_id=command_context.context_data["id"],
                        details=str(response.message))
        print(response.message)
    EVENTS.checkout()
    mp_report_template_create.logger.debug("Report template creation completed")
    return CommandContext(state=True)


@Command.validate([validate_mp_connect, validate_enable])
@Command.with_options([
    {"key": "arg", "required": False, "help": "Report template ID or name"},
    {"key": "quiet", "required": False, "help": "Delete without confirmation"},
    {"key": "disarm", "required": False, "help": "Run in test mode"},
])
@Command.with_help("Delete MaxPatrol report template")
@Command.with_name("delete")
@Command
def mp_report_template_delete(command_context: CommandContext) -> CommandContext:
    """
    Delete report template
    """
    mp_report_template_delete.logger.debug("Run mp report template delete")
    quiet = False
    confirm_all = False
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "folderId", "name", "isSystem"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_report_template_delete.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_report_template = iface_MP_Report_Template()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_report_template_delete.logger.error("MP report template API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP report template API init failed: {}".format(err))
    if command_context.get_kwarg():
        if "quiet" in command_context.get_kwarg():
            mp_report_template_delete.logger.debug("Quiet mode")
            quiet = True
    disarm = "disarm" in command_context.get_kwarg()
    if disarm:
        mp_report_template_delete.logger.debug("Disarm mode")
        quiet = True
    template_info = False
    if command_context.context_data:
        if isinstance(command_context.context_data, str):
            template_info = iface_report_template.info(pattern=command_context.context_data)
        if isinstance(command_context.context_data, list):
            template_info = iface_report_template.info(lst=command_context.context_data)
        if not template_info.state:
            mp_report_template_delete.logger.debug("No report template information found")
            return CommandContext(state=False, state_msg="No report template information found")
    if command_context.get_arg():
        template_info = iface_report_template.info(pattern=command_context.get_arg())
        if not template_info.state:
            mp_report_template_delete.logger.debug("No report template information found")
            return CommandContext(state=False, state_msg="No report template information found")
    if not template_info:
        mp_report_template_delete.logger.debug("No report template information found")
        return CommandContext(state=False, state_msg="No report template information found")
    template_info = template_info.message
    for item in template_info:
        if item["isSystem"]:
            rich_print("[yellow]Report template {} is system template. Skip.".format(item.get("name")))
            mp_report_template_delete.logger.debug("Report template {} is system profile. "
                                                   "Skip.".format(item.get("name")))
            continue
        if not quiet and not confirm_all:
            try:
                decision = Prompt.ask("Are you sure to delete report template {}? ".format(item.get("name")),
                                      choices=["y", "n", "a"], default="n")
            except KeyboardInterrupt:
                return CommandContext(state=False, state_msg="Operation interrupted")
            match decision:
                case "n":
                    continue
                case "a":
                    confirm_all = True
        response = iface_report_template.delete(item.get("id"), disarm=disarm)
        if response.state:
            print("MaxPatrol report template {} deleted".format(item.get("name")))
            mp_report_template_delete.logger.info("MaxPatrol report template {} deleted".format(item.get("name")))
            continue
        else:
            return CommandContext(parent=command_context.parent, state=False,
                                  state_msg=response.message)
    return CommandContext(state=True)


mp_report_template.add(mp_report_template_delete)
mp_report_template.add(mp_report_template_create)
mp_report_template.add(mp_report_template_info)
mp_report_template.add(mp_report_template_list)
mp_report.add(mp_report_template)
