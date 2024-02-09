from time import sleep

from app.app import validate_mp_connect, validate_enable, EVENTS
from app.core.command import Command, CommandContext
from app.core.func import validate_pipe
from app.mp.func import func_check_mixin
from app.mp.task.iface_task import iface_MP_Task

from app.mp.task.cmd_task_root import mp_task
from rich.prompt import Prompt
from rich import print as rich_print


@Command.validate(validate_mp_connect)
@Command.with_help("Get MaxPatrol task list")
@Command.with_name("list")
@Command
def mp_task_list(command_context: CommandContext) -> CommandContext:
    """
    Scan task list
    """
    mp_task_list.logger.debug("Run mp task list")
    try:
        iface_task = iface_MP_Task()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_task_list.logger.error("MP task API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP task API init failed: {}".format(err))

    if isinstance(iface_task.list, list):
        return command_context.instead(context_data=iface_task.list, data_fmt="table",
                                       data_transform=iface_task.reduce_list,
                                       data_islist_transform=True)
    else:
        return command_context.instead(context_data=iface_task.list,
                                       data_fmt="table", data_transform=iface_task.reduce_list)


@Command.validate(validate_mp_connect)
@Command.with_options([
    {"key": "arg", "required": False, "help": "Task ID or name"},
    {"key": "resolve_assets", "required": False, "help": "Resolve asset targets to IP/FQDN targets"},
    {"key": "ignore_resolve", "required": False, "help": "Ignore ID resolve failures"}
])
@Command.with_help("Get MaxPatrol task information")
@Command.with_name("info")
@Command
def mp_task_info(command_context: CommandContext) -> CommandContext:
    """
    Get scan task information
    """
    mp_task_info.logger.debug("Run mp task info")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "name", "scope"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_task_info.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_task = iface_MP_Task()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_task_info.logger.error("MP task API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP task API init failed: {}".format(err))
    task_info = False
    if command_context.context_data:
        mp_task_info.logger.debug("Processing context data")
        if isinstance(command_context.context_data, str):
            task_info = iface_task.info(pattern=command_context.context_data,
                                        not_resolve="ignore_resolve" in command_context.get_kwarg(),
                                        resolve_assets="resolve_assets" in command_context.get_kwarg())
        else:
            task_info = iface_task.info(lst=command_context.context_data,
                                        not_resolve="ignore_resolve" in command_context.get_kwarg(),
                                        resolve_assets="resolve_assets" in command_context.get_kwarg())
        if not task_info.state:
            mp_task_info.logger.debug("No task information found")
            return CommandContext(state=False, state_msg=task_info.message)
        else:
            task_info = task_info.message
    if command_context.get_arg():
        mp_task_info.logger.debug("Processing argument data")
        task_info = iface_task.info(pattern=command_context.get_arg(),
                                    not_resolve="ignore_resolve" in command_context.get_kwarg(),
                                    resolve_assets="resolve_assets" in command_context.get_kwarg())
        if not task_info.state:
            mp_task_info.logger.debug("No task information found")
            return CommandContext(state=False, state_msg=task_info.message)
        else:
            task_info = task_info.message
    if task_info:
        EVENTS.checkout()
        return command_context.instead(context_data=task_info, data_fmt="yaml",
                                       data_transform=iface_MP_Task.reduce_info,
                                       data_islist_transform=True, force_transform=False, table_transform=True)
    else:
        return CommandContext(state=False)


@Command.validate(validate_mp_connect)
@Command.with_options([
    {"key": "arg", "required": False, "help": "Task ID or name"},
])
@Command.with_help("Get MaxPatrol task history")
@Command.with_name("history")
@Command
def mp_task_history(command_context: CommandContext) -> CommandContext:
    """
    Get scan task history
    """
    mp_task_history.logger.debug("Run mp task history")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "name", "scope"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_task_history.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_task = iface_MP_Task()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_task_history.logger.error("MP task API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP task API init failed: {}".format(err))
    history_lst = False
    if command_context.context_data:
        mp_task_history.logger.debug("Processing context data")
        if isinstance(command_context.context_data, list):
            history_lst = iface_task.history(lst=command_context.context_data)
        else:
            history_lst = iface_task.history(pattern=command_context.context_data)
        if not history_lst.state:
            mp_task_history.logger.debug(history_lst.message)
            return CommandContext(state=False, state_msg=history_lst.message)
        else:
            history_lst = history_lst.message
    if command_context.get_arg():
        mp_task_history.logger.debug("Processing argument data")
        history_lst = iface_task.history(pattern=command_context.get_arg())
        if not history_lst.state:
            mp_task_history.logger.debug("No task history information found")
            return CommandContext()
        else:
            history_lst = history_lst.message
    if not history_lst:
        return CommandContext(state=False, state_msg="No task history information found")
    return command_context.instead(context_data=history_lst, data_fmt="table",
                                   data_transform=iface_task.reduce_history, data_islist_transform=True)


@Command.validate([validate_mp_connect, validate_enable, validate_pipe])
@Command.with_help("Create MaxPatrol Task from specification")
@Command.with_options([
    {"key": "disarm", "required": False, "help": "Run in test mode"},
    {"key": "drop_aec", "required": False, "help": "Remove aec from task"}
])
@Command.with_name("create")
@Command
def mp_task_create(command_context: CommandContext) -> CommandContext:
    """
    Create scan task from specification
    """
    mp_task_create.logger.debug("Run mp task create")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "name", "scope", "profile", "include", "exclude"]
        },
        {
            "type": "dict",
            "fields": ["id", "name", "scope", "profile", "include", "exclude"]
        }
    ])
    if not valid:
        mp_task_create.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    # Check mixin
    mixin = func_check_mixin(data=command_context.context_data, kind="task", params={})
    if not mixin:
        mp_task_create.logger.error("Mixin validation failed - wrong specification?")
        return CommandContext(state=False, state_msg="Mixin validation failed - wrong specification?")
    disarm = "disarm" in command_context.get_kwarg()
    mp_task_create.logger.debug("Disarm state: {}".format(disarm))
    try:
        iface_task = iface_MP_Task()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_task_create.logger.error("MP task API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP task API init failed: {}".format(err))
    # Looking for list of task specs
    if isinstance(command_context.context_data, list):
        for item in command_context.context_data:
            response = iface_task.create(source_spec=item,
                                         drop_aec="drop_aec" in command_context.get_kwarg(), disarm=disarm)
            if not response.state:
                if response.message == "Operation interrupted":
                    return CommandContext(state=False, state_msg="Operation interrupted")
                mp_task_create.logger.error("Failed to create task: {}".format(response.message))
                rich_print("[red]Failed to create task: {}".format(response.message))
                EVENTS.push(status="Fail", action="Create", instance="Task",
                            name=item.get("name"), instance_id=item.get("id"), details=response.message)
                continue
            print(response.message)
    else:
        response = iface_task.create(source_spec=command_context.context_data,
                                     drop_aec="drop_aec" in command_context.get_kwarg(), disarm=disarm)
        if not response.state:
            mp_task_create.logger.error("Failed to create task: {}".format(response.message))
            rich_print("[red]Failed to create task: {}".format(response.message))
        print(response.message)
    EVENTS.checkout()
    mp_task_create.logger.debug("Task creation completed")
    return CommandContext(state=True)


@Command.validate([validate_mp_connect, validate_enable, validate_pipe])
@Command.with_help("Update MaxPatrol Task from specification")
@Command.with_options([
    {"key": "disarm", "required": False, "help": "Run in test mode"},
    {"key": "drop_aec", "required": False, "help": "Remove aec from task"}
])
@Command.with_name("update")
@Command
def mp_task_update(command_context: CommandContext) -> CommandContext:
    """
    Update task from specification
    """
    mp_task_create.logger.debug("Run mp task update")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "name", "scope", "profile", "include", "exclude"]
        },
        {
            "type": "dict",
            "fields": ["id", "name", "scope", "profile", "include", "exclude"]
        }
    ])
    if not valid:
        mp_task_update.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    # Check mixin
    mixin = func_check_mixin(data=command_context.context_data, kind="task", params={"resolved": True})
    if not mixin:
        mp_task_update.logger.error("Mixin validation failed")
        return CommandContext(state=False, state_msg="Mixin validation failed - wrong specification?")
    disarm = "disarm" in command_context.get_kwarg()
    mp_task_update.logger.debug("Disarm state: {}".format(disarm))
    try:
        iface_task = iface_MP_Task()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_task_create.logger.error("MP task API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP task API init failed: {}".format(err))
    # Looking for list of task specs
    if isinstance(command_context.context_data, list):
        for item in command_context.context_data:
            response = iface_task.update(source_spec=item,
                                         drop_aec="drop_aec" in command_context.get_kwarg(), disarm=disarm)
            if not response.state:
                if response.message == "Operation interrupted":
                    return CommandContext(state=False, state_msg="Operation interrupted")
                mp_task_update.logger.error("Failed to update task {}: "
                                            "{}".format(item.get("name"), response.message))
                rich_print("[red]Failed to update task {}: "
                           "{}".format(item.get("name"), response.message))
                EVENTS.push(status="Fail", action="Update", instance="Task",
                            name=item.get("name"), instance_id=item.get("id"), details=response.message)
                continue
            print(response.message)
    else:
        result = iface_task.update(source_spec=command_context.context_data,
                                   drop_aec="drop_aec" in command_context.get_kwarg(),
                                   disarm=disarm)
        if not result.state:
            mp_task_update.logger.error(
                "Failed to update task {}: {}".format(command_context.context_data.get("name"), result.message))
            rich_print("[red]Failed to update task {}: "
                       "{}".format(command_context.context_data.get("name"), result.message))
    EVENTS.checkout()
    mp_task_update.logger.debug("Task update completed")
    return CommandContext()


@Command.validate([validate_mp_connect, validate_enable])
@Command.with_options([
    {"key": "arg", "required": False, "help": "Task ID or name"},
    {"key": "disarm", "required": False, "help": "Run in test mode"},
    {"key": "quiet", "required": False, "help": "Delete without confirmation"}
])
@Command.with_help("Delete MaxPatrol Task")
@Command.with_name("delete")
@Command
def mp_task_delete(command_context: CommandContext) -> CommandContext:
    """
    Delete scan task
    """
    mp_task_delete.logger.debug("Run mp task delete")
    quiet = False
    confirm_all = False
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "name", "scope"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_task_delete.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_task = iface_MP_Task()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_task_delete.logger.error("MP task API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP task API init failed: {}".format(err))
    if command_context.get_kwarg():
        if "quiet" in command_context.get_kwarg():
            mp_task_delete.logger.debug("Quiet mode")
            quiet = True
    disarm = "disarm" in command_context.get_kwarg()
    if disarm:
        disarm = True
        mp_task_delete.logger.debug("Disarm mode")
        quiet = True
    task_info = False
    if command_context.context_data:
        mp_task_delete.logger.debug("Processing context data")
        if isinstance(command_context.context_data, str):
            task_info = iface_task.info(pattern=command_context.context_data, not_resolve=True)
        else:
            task_info = iface_task.info(lst=command_context.context_data, not_resolve=True)
        if not task_info.state:
            mp_task_delete.logger.debug("No task information found")
            return CommandContext(state=False, state_msg=task_info.message)
    if command_context.get_arg():
        mp_task_delete.logger.debug("Processing argument data")
        task_info = iface_task.info(pattern=command_context.get_arg(), not_resolve=True)
        if not task_info.state:
            mp_task_delete.logger.debug("No task information found")
            return CommandContext(state=False, state_msg=task_info.message)
    if not task_info:
        return CommandContext(state=False, state_msg="No task information found")
    task_info = task_info.message
    for item in task_info:
        if not quiet and not confirm_all:
            try:
                decision = Prompt.ask("Are you sure to delete task {}? ".format(item.get("name")),
                                      choices=["y", "n", "a"], default="n")
            except KeyboardInterrupt:
                return CommandContext(state=False, state_msg="Operation interrupted")
            match decision:
                case "n":
                    continue
                case "a":
                    confirm_all = True
        if item.get("status") == "waiting" or item.get("status") == "running":
            rich_print("[yellow]Trying to stop task {}".format(item.get("name")))
            success = False
            for i in range(0, 5):
                iface_task.stop(item["id"])
                task_control = iface_task.info(pattern=item["id"])
                if task_control.state:
                    if task_control.message[0]["status"] == "finished":
                        success = True
                        break
                sleep(10)
            if not success:
                EVENTS.push(status="Fail", action="Delete", instance="Task",
                            name=item.get("name"), instance_id=item.get("id"),
                            details="Unable to stop task {}".format(item.get("name")))
                rich_print("[red]Unable to stop task {}".format(item.get("name")))
                continue
        response = iface_task.delete(item.get("id"), disarm=disarm)
        if response.state:
            print("MaxPatrol task {} deleted".format(item.get("name")))
            mp_task_delete.logger.info("MaxPatrol task {} deleted".format(item.get("name")))
            continue
        else:
            return CommandContext(parent=command_context.parent, state=False,
                                  state_msg=response.message)
    return CommandContext(state=True)


@Command.validate([validate_mp_connect, validate_enable])
@Command.with_options([
    {"key": "arg", "required": False, "help": "Task ID or name"},
    {"key": "disarm", "required": False, "help": "Run in test mode"}
])
@Command.with_help("Start MaxPatrol Task")
@Command.with_name("start")
@Command
def mp_task_start(command_context: CommandContext) -> CommandContext:
    """
    Start scan task
    """
    mp_task_start.logger.debug("Run mp task start")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "name", "scope"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_task_start.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_task = iface_MP_Task()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_task_start.logger.error("MP task API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP task API init failed: {}".format(err))
    disarm = "disarm" in command_context.get_kwarg()
    if disarm:
        mp_task_start.logger.debug("Disarm mode")
    task_info = False
    if command_context.context_data:
        mp_task_start.logger.debug("Processing context data")
        if isinstance(command_context.context_data, str):
            task_info = iface_task.info(pattern=command_context.context_data, not_resolve=True)
        else:
            task_info = iface_task.info(lst=command_context.context_data, not_resolve=True)
        if not task_info.state:
            mp_task_start.logger.debug("No task information found")
            return CommandContext(state=False, state_msg=task_info.message)
    if command_context.get_arg():
        mp_task_start.logger.debug("Processing argument data")
        task_info = iface_task.info(pattern=command_context.get_arg(), not_resolve=True)
        if not task_info.state:
            mp_task_start.logger.debug("No task information found")
            return CommandContext(state=False, state_msg=task_info.message)
    if not task_info:
        return CommandContext(state=False, state_msg="No task information found")
    task_info = task_info.message
    for item in task_info:
        response = iface_task.start(item.get("id"), disarm=disarm)
        if response.state:
            print("MaxPatrol task {} sent to start".format(item.get("name")))
            mp_task_start.logger.info("MaxPatrol task {} sent to start".format(item.get("name")))
            continue
        else:
            return CommandContext(parent=command_context.parent, state=False,
                                  state_msg="Failed response from API: {}".format(response.message))
    return CommandContext(state=True)


@Command.validate([validate_mp_connect, validate_enable])
@Command.with_options([
    {"key": "arg", "required": False, "help": "Task ID or name"},
    {"key": "disarm", "required": False, "help": "Run in test mode"}
])
@Command.with_help("Stop MaxPatrol Task")
@Command.with_name("stop")
@Command
def mp_task_stop(command_context: CommandContext) -> CommandContext:
    """
    Stop scan task
    """
    mp_task_stop.logger.debug("Stop mp task start")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "name", "scope"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_task_stop.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_task = iface_MP_Task()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_task_stop.logger.error("MP task API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP task API init failed: {}".format(err))
    disarm = "disarm" in command_context.get_kwarg()
    if disarm:
        mp_task_stop.logger.debug("Disarm mode")
    task_info = False
    if command_context.context_data:
        mp_task_stop.logger.debug("Processing context data")
        if isinstance(command_context.context_data, str):
            task_info = iface_task.info(pattern=command_context.context_data, not_resolve=True)
        else:
            task_info = iface_task.info(lst=command_context.context_data, not_resolve=True)
        if not task_info.state:
            mp_task_stop.logger.debug("No task information found")
            return CommandContext(state=False, state_msg=task_info.message)
    if command_context.get_arg():
        mp_task_stop.logger.debug("Processing argument data")
        task_info = iface_task.info(pattern=command_context.get_arg(), not_resolve=True)
        if not task_info.state:
            mp_task_stop.logger.debug("No task information found")
            return CommandContext(state=False, state_msg=task_info.message)
    if not task_info:
        mp_task_stop.logger.debug("No task information found")
        return CommandContext(state=False, state_msg="No task information found")
    if not task_info:
        return CommandContext(state=False, state_msg="No task information found")
    task_info = task_info.message
    for item in task_info:
        response = iface_task.stop(item.get("id"), disarm=disarm)
        if response.state:
            print("MaxPatrol task {} sent to stop state".format(item.get("name")))
            mp_task_stop.logger.info("MaxPatrol task {} sent to stop state".format(item.get("name")))
            continue
        else:
            return CommandContext(parent=command_context.parent, state=False,
                                  state_msg="Failed response from API: {}".format(response.message))
    return CommandContext(state=True)


@Command.validate([validate_mp_connect, validate_enable])
@Command.with_options([
    {"key": "arg", "required": False, "help": "Task ID or name"},
    {"key": "disarm", "required": False, "help": "Run in test mode"}
])
@Command.with_help("Suspend MaxPatrol Task")
@Command.with_name("suspend")
@Command
def mp_task_suspend(command_context: CommandContext) -> CommandContext:
    """
    Suspend scan task
    """
    mp_task_suspend.logger.debug("Suspend mp task start")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "name", "scope"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_task_suspend.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_task = iface_MP_Task()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_task_suspend.logger.error("MP task API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP task API init failed: {}".format(err))
    disarm = "disarm" in command_context.get_kwarg()
    if disarm:
        mp_task_suspend.logger.debug("Disarm mode")
    task_info = False
    if command_context.context_data:
        mp_task_suspend.logger.debug("Processing context data")
        if isinstance(command_context.context_data, str):
            task_info = iface_task.info(pattern=command_context.context_data, not_resolve=True)
        else:
            task_info = iface_task.info(lst=command_context.context_data, not_resolve=True)
        if not task_info.state:
            mp_task_suspend.logger.debug("No task information found")
            return CommandContext(state=False, state_msg=task_info.message)
    if command_context.get_arg():
        mp_task_suspend.logger.debug("Processing argument data")
        task_info = iface_task.info(pattern=command_context.get_arg(), not_resolve=True)
        if not task_info.state:
            mp_task_suspend.logger.debug("No task information found")
            return CommandContext(state=False, state_msg=task_info.message)
    if not task_info:
        mp_task_suspend.logger.debug("No task information found")
        return CommandContext(state=False, state_msg="No task information found")
    if not task_info:
        return CommandContext(state=False, state_msg="No task information found")
    task_info = task_info.message
    for item in task_info:
        if item.get("status") == "running":
            response = iface_task.suspend(item.get("id"), disarm=disarm)
        else:
            rich_print("[yellow]Task {} not in running state".format(item.get("name")))
            continue
        if response.state:
            print("MaxPatrol task {} suspended".format(item.get("name")))
            mp_task_suspend.logger.info("MaxPatrol task {} suspended".format(item.get("name")))
            continue
        else:
            return CommandContext(parent=command_context.parent, state=False,
                                  state_msg="Failed response from API: {}".format(response.message))
    return CommandContext(state=True)


mp_task.add(mp_task_list)
mp_task.add(mp_task_info)
mp_task.add(mp_task_history)
mp_task.add(mp_task_create)
mp_task.add(mp_task_update)
mp_task.add(mp_task_delete)
mp_task.add(mp_task_start)
mp_task.add(mp_task_stop)
mp_task.add(mp_task_suspend)
