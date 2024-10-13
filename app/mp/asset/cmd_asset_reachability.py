import re

from app.app import validate_mp_connect
from app.core.command import Command, CommandContext
from app.mp.asset.iface_asset_reachability import iface_MP_Reachability
from app.mp.asset.iface_asset import iface_MP_Asset
from app.mp.asset.iface_asset_group import iface_MP_Group
from app.mp.asset.cmd_asset_root import mp_asset


@Command.validate(validate_mp_connect)
@Command.with_help("Get network reachability from specific asset to specific asset")
@Command.with_options([
    {"key": "arg", "required": False, "help": "Asset ID or search string"},
    {"key": "from", "required": False, "help": "Asset name, ID or bind IP"},
    {"key": "to", "required": False, "help": "Asset name, ID or bind IP"},
    {"key": "routes", "required": False, "help": "Calculate routes"},
])
@Command.with_name("reachability")
@Command
def mp_asset_reachability(command_context: CommandContext) -> CommandContext:
    """
    Asset reachability
    """

    def unpack_string(source_string: str) -> list:
        """
        Split string by comma with possible quotes
        :param source_string: string
        """
        out_list = []
        current_expression = ""
        in_quotes = False
        for idx in range(0, len(source_string)):
            if source_string[idx] == '"' or source_string[idx] == "'":
                if in_quotes:
                    in_quotes = False
                    continue
                if not in_quotes:
                    in_quotes = True
                    continue
            if source_string[idx] == "," and not in_quotes:
                current_expression = current_expression.strip()
                out_list.append(current_expression)
                current_expression = ""
                continue
            current_expression += source_string[idx]
        if len(current_expression) > 0:
            current_expression = current_expression.strip()
            out_list.append(current_expression)
        return out_list

    def get_targets(targets_list: list) -> dict:
        """
        Resolve targets from raw list
        :param targets_list: targets
        """
        network_targets = []
        group_targets = []
        asset_targets = []
        for itm in targets_list:
            # Looking for network addresses
            address_pattern1 = re.compile("\b(?:(?:2(?:[0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9])\.)"
                                          "{3}(?:(?:2([0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9]))\b")
            address_pattern2 = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.)"
                                          "{3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/\d{1,2})?$")
            if address_pattern1.match(itm) or address_pattern2.match(itm):
                network_targets.append({
                    "from": itm,
                    "to": itm
                })
                continue
            # Looking for asset group target
            if itm == "Все активы":
                group_targets.append("00000000-0000-0000-0000-000000000002")
                continue
            lookup_group = iface_group.get_by_name(itm)
            if lookup_group:
                if isinstance(lookup_group, dict):
                    group_targets.append(lookup_group.get("id"))
                    continue
                if isinstance(lookup_group, list):
                    for i in lookup_group:
                        group_targets.append(i.get("id"))
                    continue
            # Looking for assets
            search_result = iface_asset.qsearch(search_str=itm)
            if search_result.state:
                search_list = search_result.message.get_offset_list(offset=0, limit=50000)
                if search_list.state:
                    search_list = search_list.message
                    for it in search_list:
                        asset_id = it.get("@Host", {}).get("id")
                        if asset_id not in asset_targets:
                            asset_targets.append(asset_id)
        return {
            "network": network_targets,
            "group": group_targets,
            "asset": asset_targets
        }

    valid = command_context.validate([
        {
            "type": "list",
            "fields": ["@Host"]
        },
        {
            "type": "dict",
            "fields": ["@Host"]
        },
        {
            "type": "str"
        },
        {
            "type": "none"
        }
    ])
    if not valid:
        mp_asset_reachability.logger.error("Context validation failed")
        return CommandContext(state=False, state_msg="Context validation failed")
    try:
        iface_reach = iface_MP_Reachability()
        iface_asset = iface_MP_Asset()
        iface_group = iface_MP_Group()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_asset_reachability.logger.error("MP asset reachability API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP asset reachability API init failed: {}".format(err))
    mp_asset_reachability.logger.debug("Run mp asset reachability")
    source_targets = None
    destination_targets = None
    # Looking context
    context_targets = None
    if isinstance(command_context.context_data, list):
        cntx = []
        for item in command_context.context_data:
            cntx.append(item.get("id"))
        context_targets = {
            "network": [],
            "group": [],
            "asset": cntx
        }
    # Looking argument
    argument_targets = None
    if command_context.get_arg():
        unpacked_arg = unpack_string(command_context.get_arg())
        argument_targets = get_targets(targets_list=unpacked_arg)
    # Check both 'from' and 'to' present, but empty
    if (('from' in command_context.get_kwarg() and command_context.get_kwarg("from") is None) and
            ('to' in command_context.get_kwarg() and command_context.get_kwarg("to") is None)):
        return CommandContext(state=False, state_msg="Wrong targets: both `from` and `to` are empty")
    # Check calculation type
    if "where" in command_context.get_kwarg():
        if context_targets:
            source_targets = context_targets
        if argument_targets:
            source_targets = argument_targets
        # If `from` provided - override context
        if command_context.get_kwarg("from"):
            from_unpacked = unpack_string(command_context.get_kwarg("from"))
            source_targets = get_targets(targets_list=from_unpacked)
        destination_targets = {
                "network": [{"from": "0.0.0.0", "to": "255.255.255.255"}],
                "group": [],
                "asset": []
            }
        # If 'to' provided - override default
        if command_context.get_kwarg("to"):
            to_unpacked = unpack_string(command_context.get_kwarg("to"))
            destination_targets = get_targets(targets_list=to_unpacked)
    else:
        if context_targets:
            destination_targets = context_targets
        if argument_targets:
            destination_targets = argument_targets
        # If `from` provided - override context
        if command_context.get_kwarg("from"):
            from_unpacked = unpack_string(command_context.get_kwarg("from"))
            source_targets = get_targets(targets_list=from_unpacked)
        # If 'to' provided - override default
        if command_context.get_kwarg("to"):
            to_unpacked = unpack_string(command_context.get_kwarg("to"))
            destination_targets = get_targets(targets_list=to_unpacked)
        if not source_targets:
            source_targets = {
                "network": [],
                "group": [],
                "asset": []
            }
    if not destination_targets or not source_targets:
        return CommandContext(state=False, state_msg="No targets defined")
    if (not source_targets.get("network") and not source_targets.get("group") and not source_targets.get("asset") and
            not destination_targets.get("network") and not destination_targets.get("group") and
            not destination_targets.get("asset")):
        return CommandContext(state=False, state_msg="No targets defined")
    print("Calculation parameters:")
    print("Sources:\t", source_targets)
    print("Destinations: \t", destination_targets)
    # Calculate
    result = iface_reach.calculate(source_targets=source_targets, destination_targets=destination_targets,
                                   where="where" in command_context.get_kwarg())
    if not result.state:
        return CommandContext(state=False, state_msg=result.message)
    return command_context.instead(context_data=result.message, data_transform=iface_reach.reduce, data_fmt="table")


mp_asset.add(mp_asset_reachability)
