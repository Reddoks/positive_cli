from app.app import validate_mp_connect
from app.core.command import Command, CommandContext
from app.mp.asset.iface_asset_scope import iface_MP_Scope
from app.mp.asset.cmd_asset_root import mp_asset


@Command.validate(validate_mp_connect)
@Command.with_help("Get infrastructure scopes")
@Command.with_name("scope")
@Command
def mp_asset_scope(command_context: CommandContext) -> CommandContext:
    """
    Infrastructure scope interface
    """
    try:
        iface_scope = iface_MP_Scope()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_asset_scope.logger.error("MP task profile API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP task profile API init failed: {}".format(err))
    return command_context.instead(context_data=iface_scope.list, data_fmt="table")


mp_asset.add(mp_asset_scope)
