from rich import print as rich_print
from rich.prompt import Prompt

from app.app import validate_mp_connect, validate_enable, EVENTS
from app.core.command import Command, CommandContext
from app.core.func import validate_pipe
from app.mp.func import func_check_mixin
from app.mp.report import iface_MP_Report_Task

from app.mp.report.cmd_report import mp_report


@Command.with_help("MaxPatrol report task commands tree")
@Command.with_name("task")
@Command
def mp_report_task(_command_context: CommandContext) -> CommandContext:
    """
    Report task tree root
    """
    return CommandContext(state=False, state_msg="Wrong command")


@Command.validate(validate_mp_connect)
@Command.with_help("Get MaxPatrol report list")
@Command.with_name("list")
@Command
def mp_report_task_list(command_context: CommandContext) -> CommandContext:
    """
    Reports list
    """
    mp_report_task_list.logger.debug("Run mp report task list")
    try:
        iface_report_task = iface_MP_Report_Task()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_report_task_list.logger.error("MP report task API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP report task API init failed: {}".format(err))
    return command_context.instead(context_data=iface_report_task.list, data_fmt="table",
                                   data_transform=iface_report_task.reduce_list,
                                   data_islist_transform=True)


@Command.validate(validate_mp_connect)
@Command.with_options([
    {"key": "arg", "required": False, "help": "Report ID or name"},
])
@Command.with_help("Get MaxPatrol report task information")
@Command.with_name("info")
@Command
def mp_report_task_info(command_context: CommandContext) -> CommandContext:
    """
    Report information
    """
    mp_report_task_info.logger.debug("Run mp report task info")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "name", "type", "author", "scheduleState"]
        },
        {
            "type": "dict",
            "fields": ["id", "name", "type", "author", "scheduleState"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_report_task_info.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_report_task = iface_MP_Report_Task()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_report_task_info.logger.error("MP report task API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP report task API init failed: {}".format(err))
    task_info = False
    if command_context.context_data:
        mp_report_task_info.logger.debug("Processing context data")
        if isinstance(command_context.context_data, str):
            task_info = iface_report_task.info(pattern=command_context.context_data)
        elif isinstance(command_context.context_data, dict):
            task_info = iface_report_task.info(dct=command_context.context_data)
        else:
            task_info = iface_report_task.info(lst=command_context.context_data)
        if not task_info.state:
            return CommandContext(state=False, state_msg=task_info.message)
    if command_context.get_arg():
        mp_report_task_info.logger.debug("Processing argument data")
        task_info = iface_report_task.info(pattern=command_context.get_arg())
        if not task_info.state:
            return CommandContext(state=False, state_msg=task_info.message)
    if task_info:
        task_info = task_info.message
        EVENTS.checkout()
        return command_context.instead(context_data=task_info, data_fmt="yaml",
                                       data_transform=iface_MP_Report_Task.reduce_info,
                                       data_islist_transform=True, force_transform=False,
                                       table_transform=True)
    else:
        EVENTS.checkout()
        return CommandContext(state=False, state_msg="No report task information found")


@Command.validate([validate_mp_connect, validate_enable, validate_pipe])
@Command.with_options([
    {"key": "disarm", "required": False, "help": "Run in test mode"},
])
@Command.with_help("Create MaxPatrol report task from specification")
@Command.with_name("create")
@Command
def mp_report_task_create(command_context: CommandContext) -> CommandContext:
    """
    Create report task from specification
    """
    mp_report_task_create.logger.debug("Run mp report task create")
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
        mp_report_task_create.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    # Check mixin
    mixin = func_check_mixin(data=command_context.context_data, kind="report_task")
    if not mixin:
        mp_report_task_create.logger.error("Mixin validation failed")
        return CommandContext(state=False, state_msg="Mixin validation failed - wrong specification?")
    disarm = "disarm" in command_context.get_kwarg()
    mp_report_task_create.logger.debug("Disarm state: {}".format(disarm))
    try:
        iface_report_task = iface_MP_Report_Task()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_report_task_create.logger.error("MP report task API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP report task API init failed: {}".format(err))
    if isinstance(command_context.context_data, list):
        for item in command_context.context_data:
            response = iface_report_task.create(source_spec=item, disarm=disarm)
            if not response.state:
                if response.message == "Operation interrupted":
                    return CommandContext(state=False, state_msg="Operation interrupted")
                mp_report_task_create.logger.error("Failed to create report task: {}".format(response.message))
                rich_print("[red]Failed to create report task: {}".format(response.message))
                EVENTS.push(status="Fail", action="Create", instance="Report Task",
                            name=item.get("name"), instance_id=item.get("id"),
                            details=str(response.message))
                continue
            print(response.message)
    else:
        response = iface_report_task.create(source_spec=command_context.context_data, disarm=disarm)
        if not response.state:
            mp_report_task_create.logger.error("Failed to create report task: {}".format(response.message))
            rich_print("[red]Failed to create report task: {}".format(response.message))
            EVENTS.push(status="Fail", action="Create", instance="Report Task",
                        name=command_context.context_data["name"], instance_id=command_context.context_data["id"],
                        details=str(response.message))
        print(response.message)
    EVENTS.checkout()
    mp_report_task_create.logger.debug("Report template creation completed")
    return CommandContext(state=True)


@Command.validate([validate_mp_connect, validate_enable])
@Command.with_options([
    {"key": "arg", "required": False, "help": "Report template ID or name"},
    {"key": "quiet", "required": False, "help": "Delete without confirmation"},
    {"key": "disarm", "required": False, "help": "Run in test mode"},
])
@Command.with_help("Delete MaxPatrol report task")
@Command.with_name("delete")
@Command
def mp_report_task_delete(command_context: CommandContext) -> CommandContext:
    """
    Delete report task
    """
    mp_report_task_delete.logger.debug("Run mp report task delete")
    quiet = False
    confirm_all = False
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "type", "name", "format"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_report_task_delete.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_report_task = iface_MP_Report_Task()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_report_task_delete.logger.error("MP report task API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP report task API init failed: {}".format(err))
    if command_context.get_kwarg():
        if "quiet" in command_context.get_kwarg():
            mp_report_task_delete.logger.debug("Quiet mode")
            quiet = True
    disarm = "disarm" in command_context.get_kwarg()
    if disarm:
        mp_report_task_delete.logger.debug("Disarm mode")
        quiet = True
    task_info = False
    if command_context.context_data:
        if isinstance(command_context.context_data, str):
            task_info = iface_report_task.info(pattern=command_context.context_data)
        if isinstance(command_context.context_data, list):
            task_info = iface_report_task.info(lst=command_context.context_data)
        if not task_info.state:
            mp_report_task_delete.logger.debug("No report task information found")
            return CommandContext(state=False, state_msg="No report task information found")
    if command_context.get_arg():
        task_info = iface_report_task.info(pattern=command_context.get_arg())
        if not task_info.state:
            mp_report_task_delete.logger.debug("No report task information found")
            return CommandContext(state=False, state_msg="No report task information found")
    if not task_info:
        mp_report_task_delete.logger.debug("No report task information found")
        return CommandContext(state=False, state_msg="No report task information found")
    task_info = task_info.message
    for item in task_info:
        if not quiet and not confirm_all:
            try:
                decision = Prompt.ask("Are you sure to delete report task {}? ".format(item.get("name")),
                                      choices=["y", "n", "a"], default="n")
            except KeyboardInterrupt:
                return CommandContext(state=False, state_msg="Operation interrupted")
            match decision:
                case "n":
                    continue
                case "a":
                    confirm_all = True
        response = iface_report_task.delete(item.get("id"), disarm=disarm)
        if response.state:
            print("MaxPatrol report task {} deleted".format(item.get("name")))
            mp_report_task_delete.logger.info("MaxPatrol report task {} deleted".format(item.get("name")))
            continue
        else:
            return CommandContext(parent=command_context.parent, state=False,
                                  state_msg=response.message)
    return CommandContext(state=True)


mp_report_task.add(mp_report_task_list)
mp_report_task.add(mp_report_task_info)
mp_report_task.add(mp_report_task_create)
mp_report_task.add(mp_report_task_delete)
mp_report.add(mp_report_task)
