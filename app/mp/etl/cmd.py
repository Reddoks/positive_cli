from app.app import validate_mp_connect
from app.core.command import Command, CommandContext
from app.mp.cmd_mp import mp
from app.mp.etl.api import MPAPIETL
from app.mp.func import func_confirm_prompt
from app.core.func import deep_get

from rich import print as rich_print
from rich.prompt import Prompt

from app.app import EVENTS


# MaxPatrol ETL Tree instance
@Command.with_help("MaxPatrol ETL commands tree")
@Command.with_name("etl")
@Command
def mp_etl() -> CommandContext:
    return CommandContext(state=False, state_msg="Wrong command")


# MaxPatrol API pipeline list
@Command.with_help("List ETL pipelines")
@Command.with_name("list")
@Command
def mp_etl_list(command_context: CommandContext) -> CommandContext:
    try:
        etls = MPAPIETL()
    except BaseException as err:
        mp_etl_list.logger.error("Failed to init ETL API: {}".format(err))
        return CommandContext(state=False, state_msg="Failed to init ETL API: {}".format(err))
    return command_context.instead(context_data=etls.list, data_fmt="table", data_transform=etls.reduce_list)


# MaxPatrol API pipeline info
@Command.with_help("ETL pipelines information")
@Command.with_name("info")
@Command
def mp_etl_info(command_context: CommandContext) -> CommandContext:
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["name", "source", "destination"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_etl_info.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        etls = MPAPIETL()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_etl_info.logger.error("Failed to init connection API: {}".format(err))
        return CommandContext(state=False, state_msg="Failed to init connection API: {}".format(err))
    etl_info = False
    if command_context.context_data:
        if type(command_context.context_data) == str:
            etl_info = []
            etl = etls.find_by_name(command_context.context_data)
            if etl:
                for item in etl:
                    etl_info.append(item)
            else:
                return CommandContext(state=False,
                                      state_msg="ETL pipeline {} not found".format(command_context.context_data))
        if type(command_context.context_data) == list:
            etl_info = []
            for item in command_context.context_data:
                etl = etls.find_by_name(item.get("name"))
                if etl:
                    for itm in etl:
                        etl_info.append(itm)
                else:
                    EVENTS.push(status="Fail", action="Find", instance="ETL",
                                name=item.get("name"), instance_id="N/A",
                                details="Pipeline not found")
    if command_context.get_arg():
        etl_info = []
        etl = etls.find_by_name(command_context.get_arg())
        if etl:
            for item in etl:
                etl_info.append(item)
        else:
            return CommandContext(state=False, state_msg="ETL pipeline {} not found".format(command_context.get_arg()))
    EVENTS.checkout()
    if etl_info:
        return command_context.instead(context_data=etl_info, data_fmt="yaml", data_transform="reset")
    else:
        return CommandContext(state=True)


# MaxPatrol create API pipeline
@Command.validate(validate_mp_connect)
@Command.with_help("Create ETL connection pipeline")
@Command.with_options([
    {"key": "disarm", "required": False, "help": "Run in test mode"}
])
@Command.with_name("create")
@Command
def mp_etl_create(command_context: CommandContext) -> CommandContext:
    mp_etl_create.logger.debug("Run mp ETL pipeline create")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["name", "source", "destination"]
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_etl_create.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    disarm = "disarm" in command_context.get_kwarg()
    mp_etl_create.logger.debug("Disarm state: {}".format(disarm))
    try:
        etls = MPAPIETL()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_etl_create.logger.error("Failed to init ETL API: {}".format(err))
        return CommandContext(state=False, state_msg="Failed to init ETL API: {}".format(err))
    if type(command_context.context_data) == list:
        for item in command_context.context_data:
            if disarm:
                print("Disarmed api pipeline creation: {}".format(item.get("name")))
                continue
            response = etls.create(item)
            if not response.state:
                return CommandContext(state=False, state_msg=response.message)
    # If no piped data
    if not command_context.is_piped:
        spec = {}
        try:
            rich_print("[yellow]Creating ETL pipeline")
            rich_print("[bright_black]ETL pipelines can be used to Extract, Transform and Load data from MaxPatrol")
            while True:
                spec["name"] = Prompt.ask("ETL pipeline name ")
                if not spec.get("name"):
                    rich_print("[red]ETL pipeline name can`t be empty")
                    continue
                exist = etls.get_by_name(spec.get("name"))
                if exist:
                    rich_print("[red]ETL pipeline with name {} exist".format(spec.get("name")))
                    continue
                break
            rich_print("[bright_black]First, you should choose data source")
            source = Prompt.ask("Source ", choices=etls.sources_list, default=etls.sources_list[0])
            response = etls.get_source(source).create()
            if not response.state:
                return CommandContext(state=False, state_msg=response.message)
            spec["source"] = response.message
            # Transform
            rich_print("[bright_black]Data retrieved from source can be transformed before output")
            rich_print("[bright_black]You may use embedded script to do transform or just ENTER to skip")
            rich_print("JS transform script (optional):")
            lines = []
            while True:
                line = input()
                if line:
                    lines.append(line)
                else:
                    break
            spec["transform"] = {"aggregated": False}
            spec["transform"]["code"] = '\n'.join(lines)
            # Aggregated results
            if deep_get(spec, "transform.code"):
                rich_print("[bright_black]Transform function may return aggregated value")
                aggregated = Prompt.ask("Get aggregated value from transform?", choices=["y", "n"], default="n")
                if aggregated == "y":
                    spec["transform"]["aggregated"] = True
            rich_print("[bright_black]Finally, you should decide how to data out of ETL pipeline")
            destination = Prompt.ask("Destination ", choices=etls.destinations_list, default=etls.destinations_list[0])
            response = etls.get_destination(destination).create()
            if not response.state:
                return CommandContext(state=False, state_msg=response.message)
            spec["destination"] = response.message
        except KeyboardInterrupt:
            return CommandContext(state=False, state_msg="\nOperation interrupted")
        except BaseException as err:
            return CommandContext(state=False, state_msg="\nOperation failed: {}".format(err))
        if disarm:
            print("Disarmed api pipeline creation: {}".format(spec.get("name")))
            return CommandContext(state=True)
        else:
            response = etls.create(spec)
        if not response.state:
            return CommandContext(state=False, state_msg=response.message)
        print(response.message)
    return CommandContext(state=True)


# MaxPatrol update ETL pipeline
@Command.with_help("Update ETL connection pipelines")
@Command.with_options([
    {"key": "disarm", "required": False, "help": "Run in test mode"}
])
@Command.with_name("update")
@Command
def mp_etl_update(command_context: CommandContext) -> CommandContext:
    mp_etl_update.logger.debug("Run mp ETL pipeline update")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["name", "source", "destination"]
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_etl_update.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    disarm = "disarm" in command_context.get_kwarg()
    mp_etl_update.logger.debug("Disarm state: {}".format(disarm))
    try:
        etls = MPAPIETL()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_etl_update.logger.error("Failed to init ETL API: {}".format(err))
        return CommandContext(state=False, state_msg="Failed to init ETL API: {}".format(err))
    if type(command_context.context_data) == list:
        for item in command_context.context_data:
            if disarm:
                print("Disarmed api pipeline update: {}".format(item.get("name")))
                continue
            response = etls.update(item)
            if not response.state:
                return CommandContext(state=False, state_msg=response.message)
            print(response.message)
    return CommandContext(state=True)


# MaxPatrol delete API pipeline
@Command.with_help("Delete ETL pipelines")
@Command.with_options([
    {"key": "arg", "required": False, "help": "ETL pipeline name"},
    {"key": "quiet", "required": False, "help": "Delete without confirmation"},
    {"key": "disarm", "required": False, "help": "Run in test mode"}
])
@Command.with_name("delete")
@Command
def mp_etl_delete(command_context: CommandContext) -> CommandContext:
    mp_etl_delete.logger.debug("Run mp ETL pipeline delete")
    quiet = False
    confirm_all = False
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["name", "source", "destination"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_etl_delete.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        etls = MPAPIETL()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_etl_delete.logger.error("Failed to init connection API: {}".format(err))
        return CommandContext(state=False, state_msg="Failed to init connection API: {}".format(err))
    if command_context.get_kwarg():
        if "quiet" in command_context.get_kwarg():
            mp_etl_delete.logger.debug("Quiet mode")
            quiet = True
    if "disarm" in command_context.get_kwarg():
        mp_etl_delete.logger.debug("Disarm mode")
        quiet = True
    etl_info = False
    if command_context.context_data:
        if type(command_context.context_data) == str:
            etl_info = []
            etl = etls.find_by_name(command_context.context_data)
            if etl:
                for item in etl:
                    etl_info.append(item.get("name"))
            else:
                print("ETL pipeline {} not found".format(command_context.context_data))
        if type(command_context.context_data) == list:
            etl_info = []
            for item in command_context.context_data:
                etl = etls.find_by_name(item.get("name"))
                if etl:
                    for itm in etl:
                        etl_info.append(itm.get("name"))
                else:
                    print("ETL pipeline {} not found".format(item.get("name")))
    if command_context.get_arg():
        etl_info = []
        etl = etls.find_by_name(command_context.get_arg())
        if etl:
            for item in etl:
                etl_info.append(item.get("name"))
        else:
            print("ETL pipeline {} not found".format(command_context.get_arg()))
    if etl_info:
        for item in etl_info:
            if "disarm" in command_context.get_kwarg():
                print("Disarmed ETL pipeline deletion: {}".format(item))
                mp_etl_delete.logger.debug("Disarmed ETL pipeline deletion: {}".format(item))
                continue
            if not quiet and not command_context.get_kwarg().get("disarm") and not confirm_all:
                confirm, confirm_all, cancel = (
                    func_confirm_prompt("Are you sure to delete ETL pipeline {} "
                                        "(yes/y/all/a to confirm, c to cancel)?: ".format(item)))
                if cancel:
                    return CommandContext(state=False)
                if not confirm and not confirm_all:
                    continue
            response = etls.delete(item)
            if response.state:
                print("ETL pipeline {} deleted".format(item))
                mp_etl_delete.logger.info("ETL pipeline {} deleted".format(item))
                continue
            else:
                return CommandContext(state=False, state_msg=response.message)
    return CommandContext(state=True)


# MaxPatrol ETL exec
@Command.validate(validate_mp_connect)
@Command.with_help("Execute ETL pipeline")
@Command.with_options([
    {"key": "arg", "required": False, "help": "Name of ETL pipeline"},
])
@Command.with_name("exec")
@Command
def mp_etl_exec(command_context: CommandContext) -> CommandContext:
    mp_etl_exec.logger.debug("Run mp etl exec")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["name", "source", "destination"]
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_etl_exec.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        etls = MPAPIETL()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_etl_exec.logger.error("Failed to init ETL API: {}".format(err))
        return CommandContext(state=False, state_msg="Failed to init ETL API: {}".format(err))
    # Look for pipeline
    etl_info = None
    if command_context.is_piped:
        etl_info = command_context.context_data
    if not command_context.is_piped and command_context.get_arg():
        etl_info = []
        etl = etls.find_by_name(command_context.get_arg())
        if etl:
            for item in etl:
                etl_info.append(item)
        else:
            return CommandContext(state=False, state_msg="ETL pipeline {} not found".format(command_context.get_arg()))
    if etl_info:
        for item in etl_info:
            if "disarm" in command_context.get_kwarg():
                print("Disarmed ETL pipeline execution: {}".format(item.get("name")))
                mp_etl_delete.logger.debug("Disarmed ETL pipeline execution: {}".format(item.get("name")))
                continue
            mp_etl_exec.logger.debug("ETL pipeline execution: {}".format(item.get("name")))
            # Extraction
            response = etls.get_source(item.get("source", {}).get("type")).extract(source=item.get("source"),
                                                                                   params=command_context.get_kwarg())
            if not response.state:
                mp_etl_exec.logger.error("ETL {} extraction failed: {}".format(item.get("name"), response.message))
                EVENTS.push(status="Fail", action="Extraction", instance="ETL",
                            name=item.get("name"), instance_id="N/A",
                            details="Extraction failed: " + response.message)
                continue
            # Transform and output
            destination_type = item.get("destination", {}).get("type")
            response = etls.get_destination(destination_type).load(obj_block=response.message,
                                                                   transform=item.get("transform"),
                                                                   params=command_context.get_kwarg(),
                                                                   destination=item.get("destination"))
            if not response.state:
                mp_etl_exec.logger.error("ETL {} load failed: {}".format(item.get("name"), response.message))
                EVENTS.push(status="Fail", action="Load", instance="ETL",
                            name=item.get("name"), instance_id="N/A",
                            details="Load failed: " + response.message)
                continue
            else:
                mp_etl_exec.logger.info("ETL {} load completed: {}".format(item.get("name"), response.message))
                print("ETL {} load completed: {}".format(item.get("name"), response.message))
        EVENTS.checkout()
        return CommandContext(state=True, state_msg=response.message)


mp_etl.add(mp_etl_list)
mp_etl.add(mp_etl_info)
mp_etl.add(mp_etl_exec)
mp_etl.add(mp_etl_delete)
mp_etl.add(mp_etl_create)
mp_etl.add(mp_etl_update)
mp.add(mp_etl)
