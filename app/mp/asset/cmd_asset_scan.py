import copy
import xmltodict
from datetime import datetime
import os
import yaml
import base64
from app.mp.api import MPAPIResponse
from cryptography.fernet import Fernet

from rich.progress import Progress
from rich.prompt import Prompt
from rich import print as rich_print

from app.app import EVENTS
from app.app import validate_mp_connect, validate_enable
from app.core.command import Command, CommandContext
from app.core.func import validate_pipe, console_clear_up, get_string_from_fmt, get_file_list_by_pattern
from app.mp.asset.iface_asset_scan import iface_MP_Scan
from app.mp.asset.cmd_asset_root import mp_asset


@Command.with_help("MaxPatrol Asset Scan commands tree")
@Command.with_name("scan")
@Command
def mp_asset_scan(_command_context: CommandContext) -> CommandContext:
    """
    Asset scan tree root
    """
    return CommandContext(state=False, state_msg="Wrong command")


@Command.validate(validate_mp_connect)
@Command.with_help("Get asset scans statistic")
@Command.with_options([
    {"key": "for_last_days", "required": False, "help": "Get processed scans for last N days"},
    {"key": "from_date", "required": False, "help": "Get processed scans from date YY-mm-dd"},
    {"key": "limit", "required": False, "help": "Get processed scans with limit N"},
    {"key": "raw", "required": False, "help": "For raw scans"}
])
@Command.with_name("stat")
@Command
def mp_asset_scan_stat(command_context: CommandContext) -> CommandContext:
    """
    Asset scans statistic
    """
    try:
        iface_scan = iface_MP_Scan()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_asset_scan_stat.logger.error("MP asset scan API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP asset scan API init failed: {}".format(err))
    from_date = None
    limit = 100000
    last_days = 28
    # If date provided, validate
    if command_context.get_kwarg("from_date"):
        try:
            from_date = datetime.fromisoformat(command_context.get_kwarg("from_date"))
        except BaseException as err:
            return CommandContext(state=False, state_msg="Wrong `from_date` value: {}".format(err))
    # If last days provided, validate
    if command_context.get_kwarg("for_last_days"):
        ld = command_context.get_kwarg("for_last_days")
        if not ld.isdigit():
            return CommandContext(state=False, state_msg="Wrong `last_days`: not digit")
        last_days = int(ld)
    # If limit provided, validate
    if command_context.get_kwarg("limit"):
        lim = command_context.get_kwarg("limit")
        if not lim.isdigit():
            return CommandContext(state=False, state_msg="Wrong `limit`: not digit")
        limit = int(lim)
    if not from_date:
        from_date = iface_scan.get_isodata_subtract_days(days=last_days)
    raw = "raw" in command_context.get_kwarg()
    if raw:
        rich_print("[bright_black]Getting raw scans from date {} with limit {}".format(from_date, limit))
        scan_stat = iface_scan.get_raw_scans(from_date=from_date, limit=limit)
    else:
        rich_print("[bright_black]Getting processed scans from date {} with limit {}".format(from_date, limit))
        scan_stat = iface_scan.get_processed_scans(from_date=from_date, limit=limit)
    if not scan_stat.state:
        return CommandContext(state=False, state_msg="Failed to get processed scan stats: {}".format(scan_stat.message))
    if scan_stat.message.get("count") == limit:
        rich_print("[yellow]Limit {} fulfilled. Probably number of scans exceeds limit".format(from_date, limit))
    return command_context.instead(context_data=scan_stat.message, data_fmt="yaml")


@Command.validate(validate_mp_connect)
@Command.with_help("Get asset scans list")
@Command.with_options([
    {"key": "arg", "required": False, "help": "Scan type"},
    {"key": "raw", "required": False, "help": "For raw scans"},
    {"key": "items", "required": False, "help": "Items per page"},
    {"key": "for_last_days", "required": False, "help": "Get processed scans for last N days"},
    {"key": "from_date", "required": False, "help": "Get processed scans from date YY-mm-dd"},
    {"key": "limit", "required": False, "help": "Get processed scans with limit N"},
    {"key": "unprocessed", "required": False, "help": "Get unprocessed scans"}
])
@Command.with_name("list")
@Command
def mp_asset_scan_list(command_context: CommandContext) -> CommandContext:
    """
    Asset scans list
    """
    try:
        iface_scan = iface_MP_Scan()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_asset_scan_list.logger.error("MP asset scan API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP asset scan API init failed: {}".format(err))
    from_date = None
    limit = 100000
    last_days = 28
    items = 15
    offset = 0
    # If date provided, validate
    if command_context.get_kwarg("from_date"):
        try:
            from_date = datetime.fromisoformat(command_context.get_kwarg("from_date"))
        except BaseException as err:
            return CommandContext(state=False, state_msg="Wrong `from_date` value: {}".format(err))
    # If last days provided, validate
    if command_context.get_kwarg("for_last_days"):
        ld = command_context.get_kwarg("for_last_days")
        if not ld.isdigit():
            return CommandContext(state=False, state_msg="Wrong `last_days`: not digit")
        last_days = int(ld)
    # If limit provided, validate
    if command_context.get_kwarg("limit"):
        lim = command_context.get_kwarg("limit")
        if not lim.isdigit():
            return CommandContext(state=False, state_msg="Wrong `limit`: not digit")
        limit = int(lim)
    if not from_date:
        from_date = iface_scan.get_isodata_subtract_days(days=last_days)
    # If items provided, validate
    if "items" in command_context.get_kwarg():
        items = command_context.get_kwarg("items")
        if not items.isdigit():
            return CommandContext(state=False, state_msg="Wrong `items`: not digit")
        items = int(items)
    raw = "raw" in command_context.get_kwarg()
    if not raw:
        scan_stat = iface_scan.get_processed_scans(from_date=from_date,
                                                   limit=limit,
                                                   offset=0,
                                                   return_scans=True,
                                                   unprocessed="unprocessed" in command_context.get_kwarg())
    else:
        scan_stat = iface_scan.get_raw_scans(from_date=from_date, limit=items, offset=offset,
                                             return_scans=True)
    if not scan_stat.state:
        return CommandContext(state=False,
                              state_msg="Failed to get scan stats: {}".format(scan_stat.message))
    if len(scan_stat.message.get("scans")) > 200:
        rich_print("[yellow]Result contains {} items".format(len(scan_stat.message.get("scans"))))
        try:
            result = Prompt.ask("Would you like to continue?", choices=["y", "n"], default="y")
        except KeyboardInterrupt:
            return CommandContext(state=False, state_msg="Operation interrupted")
        if result == "n":
            return CommandContext(state=False, state_msg="Operation interrupted")
    return command_context.instead(context_data=scan_stat.message.get("scans"), data_fmt="table")


@Command.validate(validate_mp_connect)
@Command.with_help("Get asset scan content")
@Command.with_options([
    {"key": "arg", "required": False, "help": "Scan ID"},
    {"key": "raw", "required": False, "help": "For raw scans"},
])
@Command.with_name("content")
@Command
def mp_asset_scan_content(command_context: CommandContext) -> CommandContext:
    """
    Asset scan content
    """
    try:
        iface_scan = iface_MP_Scan()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_asset_scan_content.logger.error("MP asset scan API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP asset scan API init failed: {}".format(err))
    mp_asset_scan_content.logger.debug("Run mp asset scan content")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "source", "type", "jobId"]
        },
        {
            "type": "dict",
            "fields": ["id", "source", "type", "jobId"]
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_asset_scan_dump.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    raw = "raw" in command_context.get_kwarg()
    scan_id_list = None
    if command_context.get_arg():
        scan_id_list = [{"id": command_context.get_arg()}]
    if command_context.context_data:
        scan_id_list = command_context.context_data
    output = []
    rich_print("[yellow]Depending on scan content size it may take some time.")
    with Progress() as progress:
        count = len(scan_id_list)
        task = progress.add_task("Get scan content...", total=count)
        for item in scan_id_list:
            progress.update(task, advance=1)
            if raw:
                response = iface_scan.get_raw_scan_content(scan_id=item.get("id"))
            else:
                response = iface_scan.get_scan_content(scan_id=item.get("id"))
            if not response.state:
                return CommandContext(state=False, state_msg=response.message)
            output.append({
                "id": item.get("id"),
                "content": xmltodict.parse(response.message)
            })
    console_clear_up(skip_line=True)
    return command_context.instead(context_data=output, data_fmt="yaml")


@Command.validate([validate_pipe, validate_mp_connect])
@Command.with_options([
    {"key": "arg", "required": True, "help": "Target filename"},
    {"key": "encryption", "required": False, "help": "Export encrypted specification(s)"}
])
@Command.with_name("dump")
@Command
def mp_asset_scan_dump(command_context: CommandContext) -> CommandContext:
    """
    Works only in pipe, dump raw scans
    Export context to file. Can export to encrypted file.
    """

    def get_raw_scan_block(scan: dict) -> MPAPIResponse:
        block = copy.deepcopy(scan)
        content = iface_scan.get_raw_scan_content(scan_id=scan.get("id"))
        if not content.state:
            return content
        block["content"] = content.message
        return MPAPIResponse(state=True, message=block)

    mp_asset_scan_dump.logger.debug("Run mp asset scan dump")
    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["id", "source", "type", "jobId"]
        },
        {
            "type": "dict",
            "fields": ["id", "source", "type", "jobId"]
        }
    ])
    if not valid:
        mp_asset_scan_dump.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_scan = iface_MP_Scan()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_asset_scan_dump.logger.error("MP asset scan API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP asset scan API init failed: {}".format(err))
    # Reset file if exist
    with open(command_context.get_arg(), "w", encoding="utf-8") as _:
        pass
    mode = "a"
    encoding = "utf-8"
    cipher_suite = None
    if "encryption" in command_context.get_kwarg():
        try:
            source_key = Prompt.ask("Secret key", password=True)
        except KeyboardInterrupt:
            return CommandContext(state=False, state_msg="Operation interrupted")
        code_bytes = source_key.encode("utf-8")
        secret_key = base64.urlsafe_b64encode(code_bytes.ljust(32)[:32])
        cipher_suite = Fernet(secret_key)
        mode = "ab"
        encoding = None
    # Process raw scans
    rich_print("[yellow]Depending on scan content size it may take some time.")
    with Progress() as progress:
        task = progress.add_task("Dumping scans...", total=len(command_context.context_data))
        for item in command_context.context_data:
            progress.update(task, advance=1)
            out_block = get_raw_scan_block(item)
            if not out_block.state:
                EVENTS.push(status="Fail", action="Dump", instance="Scan",
                            name="N/A", instance_id=item.get("id"),
                            details=out_block.message)
                rich_print("[red]Failed to dump scan {}".format(item.get("id")))
                continue
            else:
                out_block = out_block.message
                block_id = out_block.get("id")
                out_block = get_string_from_fmt(out_block, fmt="yaml")
            start_string = "# Raw scan {}\n".format(block_id)
            end_string = "# End scan\n"
            if "encryption" in command_context.get_kwarg():
                out_block = cipher_suite.encrypt(out_block.encode("utf-8"))
                start_string = start_string.encode("utf-8")
                end_string = "\n# End scan\n".encode("utf-8")
            try:
                with open(command_context.get_arg(), mode, encoding=encoding) as file:
                    file.write(start_string)
                    file.write(out_block)
                    file.write(end_string)
            except BaseException as err:
                mp_asset_scan_dump.logger.error(
                    "Export: Failed output to file {}".format(command_context.get_arg()), exc_info=False)
                mp_asset_scan_dump.logger.debug("Error info: ", exc_info=True)
                return CommandContext(state=False,
                                      state_msg="Failed to write file {}: {}".format(command_context.get_arg(), err))
    console_clear_up(skip_line=True)
    mp_asset_scan_dump.logger.debug("Scans dump completed")
    return CommandContext(state=True)


@Command.validate([validate_mp_connect, validate_enable])
@Command.with_options([
    {"key": "arg", "required": True, "help": "Source filename"},
    {"key": "encryption", "required": False, "help": "Load encrypted specification(s)"},
    {"key": "disarm", "required": False, "help": "Run in test mode"}
])
@Command.with_name("load")
@Command
def mp_asset_scan_load(command_context: CommandContext) -> CommandContext:
    """
    Load scans
    Load scan data from file.
    """

    def read_file(path: str, encrypt: bool) -> list | None:
        mode = "r"
        encoding = "utf-8"
        cipher_suite = None
        if encrypt:
            try:
                source_key = Prompt.ask("Secret key", password=True)
            except KeyboardInterrupt:
                print("Operation interrupted")
                return None
            code_bytes = source_key.encode("utf-8")
            secret_key = base64.urlsafe_b64encode(code_bytes.ljust(32)[:32])
            cipher_suite = Fernet(secret_key)
            mode = "rb"
            encoding = None
        try:
            out_data = []
            scan_block = ""
            with open(path, mode, encoding=encoding) as file:
                while True:
                    line = file.readline()
                    if not line:
                        break
                    if not encrypt:
                        if "# Raw scan" in line:
                            scan_block = ""
                            continue
                        if "# End scan" in line:
                            try:
                                yaml_data = yaml.safe_load(scan_block)
                                out_data.append(yaml_data)
                                continue
                            except BaseException as erro:
                                mp_asset_scan_load.logger.debug(
                                    "File does not contains valid YAML: {}".format(erro),
                                    exc_info=False)
                                mp_asset_scan_load.logger.debug("Error info: ", exc_info=True)
                                path, name = os.path.split(path)
                                print("File {} does not contains valid YAML data".format(name))
                                return
                        scan_block += line
                    else:
                        if b"# Raw scan" in line or b"# End scan" in line: # noqa
                            continue
                        try:
                            scan_block = cipher_suite.decrypt(line[:-1])
                            scan_block = scan_block.decode("utf-8")
                            try:
                                yaml_data = yaml.safe_load(scan_block)
                                out_data.append(yaml_data)
                            except BaseException as error:
                                mp_asset_scan_load.logger.debug(
                                    "File does not contains valid YAML: {}".format(error),
                                    exc_info=False)
                                mp_asset_scan_load.logger.debug("Error info: ", exc_info=True)
                                path, name = os.path.split(path)
                                print("File {} does not contains valid YAML data".format(name))
                                return
                            continue
                        except BaseException as errr:
                            print("Something went wrong. Probably secret key is invalid. Error: {}".format(errr))
                            return

                return out_data
        except BaseException as errr:
            path, name = os.path.split(path)
            print("Unable to read file {}. Error: {}".format(name, errr))
            return None

    mp_asset_scan_load.logger.debug("Run mp asset scan load")
    try:
        iface_scan = iface_MP_Scan()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_asset_scan_load.logger.error("MP asset scan API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP asset scan API init failed: {}".format(err))
    targets = get_file_list_by_pattern(command_context.get_arg())
    if not targets:
        return CommandContext(state=False, state_msg="No files found")
    output = []
    disarm = "disarm" in command_context.get_kwarg()
    mp_asset_scan_load.logger.debug("Disarm state: " + str(disarm))
    if len(targets) > 0:
        for target in targets:
            encryption = False
            if "encryption" in command_context.get_kwarg():
                encryption = True
            scan_data = read_file(target, encryption)
            if not scan_data:
                continue
            output += scan_data
    # Iterate scans
    with Progress() as progress:
        task = progress.add_task("Loading scans...", total=len(output))
        for item in output:
            progress.update(task, advance=1)
            # Getting timestamp
            time = datetime.utcnow()
            time = time.strftime('%Y-%m-%dT%H:%M:%SZ')
            item["timeStamp"] = time
            response = iface_scan.load_scan(source_scan=item, overwrite=False, disarm=disarm)
            if not response.state:
                if response.message == "Operation interrupted":
                    return CommandContext(state=False, state_msg="Operation interrupted")
                rich_print("[red]Scan load error: {}".format(response.message))
                continue
            print("Scan {} loaded successfully".format(item.get("id")))
    console_clear_up(skip_line=True)
    EVENTS.checkout()
    mp_asset_scan_load.logger.debug("Scans load complete")
    return CommandContext(state=True)


mp_asset_scan.add(mp_asset_scan_list)
mp_asset_scan.add(mp_asset_scan_stat)
mp_asset_scan.add(mp_asset_scan_dump)
mp_asset_scan.add(mp_asset_scan_load)
mp_asset_scan.add(mp_asset_scan_content)
mp_asset.add(mp_asset_scan)
