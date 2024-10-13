import copy
import re
import uuid

from datetime import datetime
import os
import yaml
import base64

from cryptography.fernet import Fernet
from rich.prompt import Prompt

from app.core.command import Command, CommandContext
from app.mp.cmd_mp import mp
from app.app import validate_mp_connect, get_string_from_fmt, validate_enable, EVENTS
from app.core.func import console_clear_up, validate_pipe, get_file_list_by_pattern
from app.mp.asset.iface_asset import iface_MP_Asset
from app.mp.asset.iface_asset_group import iface_MP_Group
from app.mp.asset.iface_asset_scan import iface_MP_Scan
from app.mp.asset.iface_asset_scope import iface_MP_Scope

from rich import print as rich_print
from rich.progress import Progress


# MaxPatrol Asset Tree instance
@Command.with_help("MaxPatrol Asset commands tree")
@Command.with_name("asset")
@Command
def mp_asset(_command_context: CommandContext) -> CommandContext:
    """
    Asset tree root
    """
    return CommandContext(state=False, state_msg="Wrong command")


@Command.validate(validate_mp_connect)
@Command.with_help("Get assets list")
@Command.with_options([
    {"key": "limit", "required": False, "help": "PDQL result list items limit"},
    {"key": "offset", "required": False, "help": "PDQL result list offset"},
    {"key": "group", "required": False, "help": "Pick asset group to filter"},
])
@Command.with_name("list")
@Command
def mp_asset_list(command_context: CommandContext) -> CommandContext:
    """
    Get assets
    """
    mp_asset_list.logger.debug("Run mp asset list")
    try:
        iface_asset = iface_MP_Asset()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_asset_list.logger.error("MP asset API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP asset API init failed: {}".format(err))
    # Parameters
    limit = 50
    work_offset = 0
    if command_context.get_kwarg("limit"):
        lim = command_context.get_kwarg("limit")
        if not lim.isdigit():
            return CommandContext(state=False, state_msg="Wrong `limit`: not digit")
        limit = int(lim)
    if command_context.get_kwarg("offset"):
        off = command_context.get_kwarg("offset")
        if not off.isdigit():
            return CommandContext(state=False, state_msg="Wrong `offset`: not digit")
        work_offset = int(off)
    asset_group = None
    if "group" in command_context.get_kwarg():
        try:
            iface_group = iface_MP_Group()
        except KeyboardInterrupt:
            return CommandContext(state=False, state_msg="Operation interrupted")
        except BaseException as err:
            mp_asset_list.logger.error("MP asset group API init failed: {}".format(err))
            return CommandContext(state=False, state_msg="MP asset group API init failed: {}".format(err))
        asset_group = iface_group.get_group_picker("Asset group to filter (? or * acceptable): ")
        if not asset_group.state:
            return CommandContext(state=False, state_msg="Failed to get filter group")
        asset_group = asset_group.message.get("id")
    response = iface_asset.list(group_filter=[asset_group])
    if not response.state:
        return CommandContext(state=False, state_msg="Failed PDQL list request: {}".format(response.message))
    search_object = response.message
    result = search_object.get_offset_list(offset=work_offset, limit=limit)
    if not result.state:
        return CommandContext(state=False, state_msg="Failed to get PDQL result: {}".format(result.message))
    if len(result.message) == 0:
        return CommandContext(state=False, state_msg="No assets found")
    return command_context.instead(state_msg=True, context_data=result.message, data_fmt="table",
                                   data_transform=iface_asset.reduce_assets, data_islist_transform=True)


@Command.validate(validate_mp_connect)
@Command.with_help("Quick search asset")
@Command.with_options([
    {"key": "arg", "required": True, "help": "Search string"},
    {"key": "limit", "required": False, "help": "Result list items limit"},
    {"key": "offset", "required": False, "help": "Result list offset"},
    {"key": "group", "required": False, "help": "Pick asset group to filter"},
])
@Command.with_name("search")
@Command
def mp_asset_search(command_context: CommandContext) -> CommandContext:
    """
    Get assets quick search
    """
    mp_asset_search.logger.debug("Run mp asset search")
    try:
        iface_asset = iface_MP_Asset()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_asset_search.logger.error("MP asset API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP asset API init failed: {}".format(err))
    # Parameters
    limit = 50
    work_offset = 0
    if command_context.get_kwarg("limit"):
        lim = command_context.get_kwarg("limit")
        if not lim.isdigit():
            return CommandContext(state=False, state_msg="Wrong `limit`: not digit")
        limit = int(lim)
    if command_context.get_kwarg("offset"):
        off = command_context.get_kwarg("offset")
        if not off.isdigit():
            return CommandContext(state=False, state_msg="Wrong `offset`: not digit")
        work_offset = int(off)
    asset_group = None
    if "group" in command_context.get_kwarg():
        try:
            iface_group = iface_MP_Group()
        except KeyboardInterrupt:
            return CommandContext(state=False, state_msg="Operation interrupted")
        except BaseException as err:
            mp_asset_search.logger.error("MP asset group API init failed: {}".format(err))
            return CommandContext(state=False, state_msg="MP asset group API init failed: {}".format(err))
        asset_group = iface_group.get_group_picker("Asset group to filter (? or * acceptable): ")
        if not asset_group.state:
            return CommandContext(state=False, state_msg="Failed to get filter group")
        asset_group = asset_group.message.get("id")
    response = iface_asset.qsearch(search_str=command_context.get_arg(), group_filter=[asset_group])
    if not response.state:
        return CommandContext(state=False, state_msg="Failed PDQL qsearch request: {}".format(response.message))
    search_object = response.message
    result = search_object.get_offset_list(offset=work_offset, limit=limit)
    if not result.state:
        return CommandContext(state=False, state_msg="Failed to get PDQL qsearch result: {}".format(result.message))
    if len(result.message) == 0:
        return CommandContext(state=False, state_msg="No assets found")
    return command_context.instead(state_msg=True, context_data=result.message, data_fmt="table",
                                   data_transform=iface_asset.reduce_assets, data_islist_transform=True)


@Command.validate(validate_mp_connect)
@Command.with_help("Search asset grid with PDQL")
@Command.with_options([
    {"key": "arg", "required": True, "help": "PDQL query"},
    {"key": "limit", "required": False, "help": "Result list items limit"},
    {"key": "offset", "required": False, "help": "Result list offset"}
])
@Command.with_name("pdql")
@Command
def mp_asset_pdql(command_context: CommandContext) -> CommandContext:
    """
    Search asset grid with PDQL
    """
    mp_asset_pdql.logger.debug("Run mp asset pdql")
    try:
        iface_asset = iface_MP_Asset()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_asset_pdql.logger.error("MP asset API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP asset API init failed: {}".format(err))
    # Parameters
    query = None
    work_offset = 0
    limit = 50
    if command_context.get_kwarg("limit"):
        lim = command_context.get_kwarg("limit")
        if not lim.isdigit():
            return CommandContext(state=False, state_msg="Wrong `limit`: not digit")
        limit = int(lim)
    if command_context.get_kwarg("offset"):
        off = command_context.get_kwarg("offset")
        if not off.isdigit():
            return CommandContext(state=False, state_msg="Wrong `offset`: not digit")
        work_offset = int(off)
    if command_context.get_arg():
        query = command_context.get_arg()
    response = iface_asset.query(query=query)
    if not response.state:
        return CommandContext(state=False, state_msg="Failed PDQL list request: {}".format(response.message))
    search_object = response.message
    result = search_object.get_offset_list(offset=work_offset, limit=limit)
    if not result.state:
        return CommandContext(state=False, state_msg="Failed to get PDQL result: {}".format(result.message))
    if len(result.message) == 0:
        return CommandContext(state=False, state_msg="No assets found")
    # Check grouping results
    pdql_result = result.message
    if len(pdql_result) > 0:
        if "$assetGridGroupKey" in pdql_result[0]:
            out_pdql_result = []
            for item in pdql_result:
                group_data = copy.deepcopy(item)
                del group_data["$assetGridGroupKey"]
                group_selection_result = search_object.get_offset_group_list(group_id=item.get("$assetGridGroupKey"),
                                                                             offset=work_offset, limit=limit)
                if not group_selection_result.state:
                    return CommandContext(state=False, state_msg="Failed to get PDQL result: "
                                                                 "{}".format(group_selection_result.message))
                group_data["records"] = group_selection_result.message
                out_pdql_result.append(group_data)
            pdql_result = out_pdql_result
    return command_context.instead(state_msg=True, context_data=pdql_result, data_fmt="yaml")


@Command.validate(validate_mp_connect)
@Command.with_help("Get asset passport")
@Command.with_options([
    {"key": "arg", "required": False, "help": "Asset ID or search string"},
])
@Command.with_name("passport")
@Command
def mp_asset_passport(command_context: CommandContext) -> CommandContext:
    """
    Get asset passport information
    """
    valid = command_context.validate([
        {
            "type": "list",
            "fields": [],
            "some_fields": ["@Host", "id"]
        },
        {
            "type": "dict",
            "fields": [],
            "some_fields": ["@Host", "id"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_asset_passport.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    mp_asset_passport.logger.debug("Run mp asset passport")
    try:
        iface_asset = iface_MP_Asset()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_asset_passport.logger.error("MP asset API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP asset API init failed: {}".format(err))
    asset_ids = []
    # If argument
    if command_context.get_arg():
        id_pattern = re.compile("[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+")
        if re.match(id_pattern, command_context.get_arg()):
            asset_ids.append(command_context.get_arg())
        else:
            assets_obj = iface_asset.qsearch(search_str=command_context.get_arg())
            if not assets_obj.state:
                return CommandContext(state=False, state_msg="Failed to get assets: {}".format(assets_obj.message))
            assets = assets_obj.message.get_offset_list(offset=0, limit=50000)
            if not assets.state:
                return CommandContext(state=False, state_msg="Failed to get assets: {}".format(assets.message))
            for asst in assets.message:
                asset_ids.append(asst.get("@Host", {}).get("id"))

    # If context - getting IDs from context
    if isinstance(command_context.context_data, list):
        for item in command_context.context_data:
            if item.get("@Host"):
                if item.get("@Host", {}).get("id"):
                    asset_ids.append(item.get("@Host", {}).get("id"))
            elif item.get("id"):
                asset_ids.append(item.get("id"))
    if isinstance(command_context.context_data, dict):
        if command_context.context_data.get("@Host"):
            if command_context.context_data.get("@Host", {}).get("id"):
                asset_ids.append(command_context.context_data.get("@Host", {}).get("id"))
            elif command_context.context_data.get("id"):
                asset_ids.append(command_context.context_data.get("id"))
    if isinstance(command_context.context_data, str):
        asset_ids.append(command_context.context_data)
    # Getting passports
    if len(asset_ids) == 0:
        return CommandContext(state=False, state_msg="No assets found")
    passports = []
    with Progress() as progress:
        task = progress.add_task("Getting asset passports...", total=len(asset_ids))
        for item in asset_ids:
            progress.update(task, advance=1)
            passport = iface_asset.get_asset_passport(asset_id=item)
            if not passport.state:
                if "core.assetsInfo.assetsNotExists.error" in passport.message:
                    EVENTS.push(action="Resolve", status="Fail",
                                instance="Asset",
                                name="N/A", instance_id=item,
                                details="Unable to get passport for asset with ID {}. Asset not found.".format(item))
                    continue
                return CommandContext(state=False,
                                      state_msg="Failed to get asset passport: {}".format(passport.message))
            else:
                passports.append(passport.message)
    EVENTS.checkout()
    console_clear_up(skip_line=True)
    if len(passports) > 0:
        return command_context.instead(state_msg=True, context_data=passports, data_fmt="table",
                                       data_transform=iface_asset.reduce_passport, data_islist_transform=True)
    else:
        return CommandContext(state=False,
                              state_msg="No assets found")


@Command.validate([validate_mp_connect, validate_pipe])
@Command.with_help("Get asset snapshot")
@Command.with_options([
    {"key": "arg", "required": True, "help": "Target filename"},
    {"key": "encryption", "required": False, "help": "Export encrypted specification(s)"},
    {"key": "disarm", "required": False, "help": "Run in test mode"}
])
@Command.with_name("dump")
@Command
def mp_asset_dump(command_context: CommandContext) -> CommandContext:
    """
    Get asset snapshot
    Works only in pipe
    """
    valid = command_context.validate([
        {
            "type": "list",
            "fields": [],
            "some_fields": ["@Host", "id"]
        },
        {
            "type": "dict",
            "fields": [],
            "some_fields": ["@Host", "id"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_asset_dump.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    mp_asset_dump.logger.debug("Run mp asset dump")
    try:
        iface_asset = iface_MP_Asset()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_asset_dump.logger.error("MP asset API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP asset API init failed: {}".format(err))
    asset_ids = []
    disarm = "disarm" in command_context.get_kwarg()
    # If context - getting IDs from context
    if isinstance(command_context.context_data, list):
        for item in command_context.context_data:
            if item.get("@Host"):
                if item.get("@Host", {}).get("id"):
                    asset_ids.append(item.get("@Host", {}).get("id"))
            elif item.get("id"):
                asset_ids.append(item.get("id"))
    if isinstance(command_context.context_data, dict):
        if command_context.context_data.get("@Host"):
            if command_context.context_data.get("@Host", {}).get("id"):
                asset_ids.append(command_context.context_data.get("@Host", {}).get("id"))
            elif command_context.context_data.get("id"):
                asset_ids.append(command_context.context_data.get("id"))
    if isinstance(command_context.context_data, str):
        asset_ids.append(command_context.context_data)
    # Getting passports
    if len(asset_ids) == 0:
        return CommandContext(state=False, state_msg="No assets found")
    snapshots = []
    with Progress() as progress:
        task = progress.add_task("Building asset snapshots...", total=len(asset_ids))
        for item in asset_ids:
            progress.update(task, advance=1)
            snapshot = iface_asset.get_asset_snapshot(asset_id=item)
            if not snapshot.state:
                if "Asset not found or snapshot is empty for" in snapshot.message:
                    EVENTS.push(action="Get", status="Fail",
                                instance="Snapshot",
                                name="N/A", instance_id=item,
                                details=snapshot.message)
                    continue
                return CommandContext(state=False,
                                      state_msg="Failed to get asset snapshot: {}".format(snapshot.message))
            else:
                snapshots.append({
                    "id": item,
                    "content": snapshot.message
                })
    EVENTS.checkout()
    console_clear_up(skip_line=True)
    if len(snapshots) > 0:
        # Got snapshots, save
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
        if disarm:
            return CommandContext(state=True, state_msg="Success - disarmed")
        for item in snapshots:
            start_string = "# Asset {}\n".format(item.get("id"))
            end_string = "# End\n"
            content = {"content": item.get("content")}
            content = get_string_from_fmt(content, fmt="yaml")
            if "encryption" in command_context.get_kwarg():
                content = cipher_suite.encrypt(content.encode("utf-8"))
                start_string = start_string.encode("utf-8")
                end_string = "\n# End\n".encode("utf-8")
            try:
                with open(command_context.get_arg(), mode, encoding=encoding) as file:
                    file.write(start_string)
                    file.write(content)
                    file.write(end_string)
            except BaseException as err:
                mp_asset_dump.logger.error(
                    "Export: Failed output to file {}".format(command_context.get_arg()), exc_info=False)
                mp_asset_dump.logger.debug("Error info: ", exc_info=True)
                return CommandContext(state=False,
                                      state_msg="Failed to write file {}: {}".format(command_context.get_arg(), err))
        mp_asset_dump.logger.debug("Assets dump completed")
        return CommandContext(state=True)
    else:
        return CommandContext(state=False,
                              state_msg="No assets found")


@Command.validate(validate_mp_connect)
@Command.with_help("Get asset membership")
@Command.with_options([
    {"key": "arg", "required": False, "help": "Asset ID or search string"},
])
@Command.with_name("member")
@Command
def mp_asset_member(command_context: CommandContext) -> CommandContext:
    """
    Get asset membership information
    """
    valid = command_context.validate([
        {
            "type": "list",
            "fields": [],
            "some_fields": ["@Host", "id"]
        },
        {
            "type": "dict",
            "fields": [],
            "some_fields": ["@Host", "id"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_asset_member.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    mp_asset_member.logger.debug("Run mp asset member")
    try:
        iface_asset = iface_MP_Asset()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_asset_passport.logger.error("MP asset API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP asset API init failed: {}".format(err))
    asset_ids = []
    # If argument
    if command_context.get_arg():
        id_pattern = re.compile("[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+")
        if re.match(id_pattern, command_context.get_arg()):
            asset_ids.append(command_context.get_arg())
        else:
            assets_obj = iface_asset.qsearch(search_str=command_context.get_arg())
            if not assets_obj.state:
                return CommandContext(state=False, state_msg="Failed to get assets: {}".format(assets_obj.message))
            assets = assets_obj.message.get_offset_list(offset=0, limit=50000)
            if not assets.state:
                return CommandContext(state=False, state_msg="Failed to get assets: {}".format(assets.message))
            for asst in assets.message:
                asset_ids.append(asst.get("@Host", {}).get("id"))

    # If context - getting IDs from context
    if isinstance(command_context.context_data, list):
        for item in command_context.context_data:
            if item.get("@Host"):
                if item.get("@Host", {}).get("id"):
                    asset_ids.append(item.get("@Host", {}).get("id"))
            elif item.get("id"):
                asset_ids.append(item.get("id"))
    if isinstance(command_context.context_data, dict):
        if command_context.context_data.get("@Host"):
            if command_context.context_data.get("@Host", {}).get("id"):
                asset_ids.append(command_context.context_data.get("@Host", {}).get("id"))
            elif command_context.context_data.get("id"):
                asset_ids.append(command_context.context_data.get("id"))
    if isinstance(command_context.context_data, str):
        asset_ids.append(command_context.context_data)
    # Getting membership
    if len(asset_ids) == 0:
        return CommandContext(state=False, state_msg="No assets found")
    groups = []
    with Progress() as progress:
        task = progress.add_task("Getting asset membership...", total=len(asset_ids))
        for item in asset_ids:
            progress.update(task, advance=1)
            groups_obj = iface_asset.member(asset_id=item)
            if not groups_obj.state:
                EVENTS.push(action="Resolve", status="Fail",
                            instance="Group Membership",
                            name="N/A", instance_id=item,
                            details="Unable to get group membership for asset with ID {}.".format(item))
                continue
            else:
                groups.append({
                    "id": item,
                    "groups": groups_obj.message
                })
    EVENTS.checkout()
    console_clear_up(skip_line=True)
    if len(groups) > 0:
        return command_context.instead(state_msg=True, context_data=groups, data_fmt="yaml",
                                       data_transform=iface_asset.reduce_member, force_transform=True)
    else:
        return CommandContext(state=False,
                              state_msg="No assets found")


@Command.validate([validate_mp_connect, validate_enable])
@Command.with_options([
    {"key": "arg", "required": True, "help": "Source filename"},
    {"key": "encryption", "required": False, "help": "Load encrypted specification(s)"},
    {"key": "disarm", "required": False, "help": "Run in test mode"}
])
@Command.with_name("load")
@Command
def mp_asset_load(command_context: CommandContext) -> CommandContext:
    """
    Load assets
    Load assets data from file.
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
                        if "# Asset" in line:
                            old_asset_id = line.replace("# Asset ", "")
                            scan_block = ""
                            continue
                        if "# End" in line:
                            try:
                                yaml_data = yaml.safe_load(scan_block)
                                yaml_data["old_asset_id"] = old_asset_id
                                out_data.append(yaml_data)
                                continue
                            except BaseException as erro:
                                mp_asset_load.logger.debug(
                                    "File does not contains valid YAML: {}".format(erro),
                                    exc_info=False)
                                mp_asset_load.logger.debug("Error info: ", exc_info=True)
                                path, name = os.path.split(path)
                                print("File {} does not contains valid YAML data".format(name))
                                return
                        scan_block += line
                    else:
                        if b"# Asset" in line:
                            normalized_line = line.decode("utf-8")
                            old_asset_id = normalized_line.replace("# Asset ", "")
                        if b"# Asset" in line or b"# End" in line:  # noqa
                            continue
                        try:
                            scan_block = cipher_suite.decrypt(line[:-1])
                            scan_block = scan_block.decode("utf-8")
                            try:
                                yaml_data = yaml.safe_load(scan_block)
                                yaml_data["old_asset_id"] = old_asset_id
                                out_data.append(yaml_data)
                            except BaseException as error:
                                mp_asset_load.logger.debug(
                                    "File does not contains valid YAML: {}".format(error),
                                    exc_info=False)
                                mp_asset_load.logger.debug("Error info: ", exc_info=True)
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

    mp_asset_load.logger.debug("Run mp asset load")
    try:
        iface_scan = iface_MP_Scan()
        iface_scope = iface_MP_Scope()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_asset_load.logger.error("MP asset APIs init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP asset APIs init failed: {}".format(err))
    targets = get_file_list_by_pattern(command_context.get_arg())
    if not targets:
        return CommandContext(state=False, state_msg="No files found")
    output = []
    disarm = "disarm" in command_context.get_kwarg()
    overwrite = "overwrite" in command_context.get_kwarg()
    mp_asset_load.logger.debug("Disarm state: " + str(disarm))
    if len(targets) > 0:
        for target in targets:
            encryption = False
            if "encryption" in command_context.get_kwarg():
                encryption = True
            scan_data = read_file(target, encryption)
            if not scan_data:
                continue
            output += scan_data
    # Check scope
    if len(iface_scope.list) > 1:
        scope_id = iface_scope.get_scope_picker("Target scope (? and * allowed): ")
        if not scope_id.state:
            return CommandContext(state=False, state_msg="Load failed - missing infrastructure scope")
    else:
        scope_id = iface_scope.list[0].get("id")
    # Iterate assets
    with Progress() as progress:
        task = progress.add_task("Loading assets...", total=len(output))
        for item in output:
            progress.update(task, advance=1)
            # Build synthetic scan
            # Generate scan ID based on current time
            scan_exist = True
            while scan_exist:
                scan_uuid = str(uuid.uuid1())
                # Make sure that scans with this UUID not exist
                raw_scan = iface_scan.get_raw_scan_by_id(scan_uuid)
                prc_scan = iface_scan.get_scan_by_id(scan_uuid)
                if not raw_scan.state and not prc_scan.state:
                    scan_exist = False
            # Overwrite setting
            replace_entities = False
            if "overwrite" in command_context.get_kwarg():
                replace_entities = True
            # Getting timestamp
            time = datetime.utcnow()
            time = time.strftime('%Y-%m-%dT%H:%M:%SZ')
            # Structure
            scan = {
                "id": scan_uuid,
                "source": "audit",
                "scopeId": scope_id,
                "timeStamp": time,
                "jobId": None,
                "orderedId": None,
                "noTtl": False,
                "replaceEntities": replace_entities,
                "createOnly": False,
                "content": item.get("content")
            }
            response = iface_scan.load_scan(source_scan=scan, overwrite=overwrite, disarm=disarm)
            if not response.state:
                if response.message == "Operation interrupted":
                    return CommandContext(state=False, state_msg="Operation interrupted")
                rich_print("[red]Asset (OLD ID:{}) load error: {}".format(item.get("old_asset_id"), response.message))
                continue
    console_clear_up(skip_line=True)
    EVENTS.checkout()
    mp_asset_load.logger.debug("Assets load complete")
    return CommandContext(state=True)


@Command.validate([validate_mp_connect, validate_enable])
@Command.with_help("Delete asset")
@Command.with_options([
    {"key": "arg", "required": False, "help": "Asset ID or search string"},
    {"key": "disarm", "required": False, "help": "Run in test mode"},
    {"key": "quiet", "required": False, "help": "Delete without confirmation"}
])
@Command.with_name("delete")
@Command
def mp_asset_delete(command_context: CommandContext) -> CommandContext:
    """
    Delete assets
    """
    valid = command_context.validate([
        {
            "type": "list",
            "fields": [],
            "some_fields": ["@Host", "id"]
        },
        {
            "type": "dict",
            "fields": [],
            "some_fields": ["@Host", "id"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_asset_delete.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    mp_asset_delete.logger.debug("Run mp asset delete")
    quiet = False
    confirm_all = False
    try:
        iface_asset = iface_MP_Asset()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_asset_delete.logger.error("MP asset API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP asset API init failed: {}".format(err))
    asset_ids = []
    # If argument
    if command_context.get_arg():
        id_pattern = re.compile("[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+")
        if re.match(id_pattern, command_context.get_arg()):
            asset_ids.append(command_context.get_arg())
        else:
            assets_obj = iface_asset.qsearch(search_str=command_context.get_arg())
            if not assets_obj.state:
                return CommandContext(state=False, state_msg="Failed to get assets: {}".format(assets_obj.message))
            assets = assets_obj.message.get_offset_list(offset=0, limit=50000)
            if not assets.state:
                return CommandContext(state=False, state_msg="Failed to get assets: {}".format(assets.message))
            for asst in assets.message:
                asset_ids.append(asst.get("@Host", {}).get("id"))
    # If context - getting IDs from context
    if isinstance(command_context.context_data, list):
        for item in command_context.context_data:
            if item.get("@Host"):
                if item.get("@Host", {}).get("id"):
                    asset_ids.append(item.get("@Host", {}).get("id"))
            elif item.get("id"):
                asset_ids.append(item.get("id"))
    if isinstance(command_context.context_data, dict):
        if command_context.context_data.get("@Host"):
            if command_context.context_data.get("@Host", {}).get("id"):
                asset_ids.append(command_context.context_data.get("@Host", {}).get("id"))
        elif command_context.context_data.get("id"):
            asset_ids.append(command_context.context_data)
    if isinstance(command_context.context_data, str):
        asset_ids.append(command_context.context_data)
    if command_context.get_kwarg():
        if "quiet" in command_context.get_kwarg():
            mp_asset_delete.logger.debug("Quiet mode")
            quiet = True
    disarm = "disarm" in command_context.get_kwarg()
    if disarm:
        mp_asset_delete.logger.debug("Disarm mode")
        quiet = True
    # Delete assets
    if len(asset_ids) == 0:
        return CommandContext(state=False, state_msg="No assets found")
    for item in asset_ids:
        # Check IDs
        id_pattern = re.compile("[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+")
        if not re.match(id_pattern, str(item)):
            EVENTS.push(action="Check", status="Fail",
                        instance="Asset",
                        name="N/A", instance_id=item,
                        details="Wrong asset ID: {}".format(item))
            continue
        if len(item) != 36:
            EVENTS.push(action="Check", status="Fail",
                        instance="Asset",
                        name="N/A", instance_id=item,
                        details="Wrong asset ID: {}".format(item))
            continue
        if not quiet and not confirm_all:
            try:
                decision = Prompt.ask("Are you sure to delete asset {}? ".format(item),
                                      choices=["y", "n", "a"], default="n")
            except KeyboardInterrupt:
                return CommandContext(state=False, state_msg="Operation interrupted")
            match decision:
                case "n":
                    continue
                case "a":
                    confirm_all = True
        response = iface_asset.delete(asset_id=item, disarm=disarm)
        if response.state:
            print("MaxPatrol asset {} deleted".format(item))
            mp_asset_delete.logger.info("MaxPatrol asset {} deleted".format(item))
            continue
        else:
            return CommandContext(parent=command_context.parent, state=False,
                                  state_msg=response.message)
    EVENTS.checkout()
    return CommandContext(state=True)


mp_asset.add(mp_asset_pdql)
mp_asset.add(mp_asset_search)
mp_asset.add(mp_asset_passport)
mp_asset.add(mp_asset_dump)
mp_asset.add(mp_asset_load)
mp_asset.add(mp_asset_member)
mp_asset.add(mp_asset_delete)
mp_asset.add(mp_asset_list)
mp.add(mp_asset)
