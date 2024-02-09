from app.core.command import Command, CommandContext
from app.mp.site import iface_MP_Site
from app.app import validate_mp_connect
from app.mp.cmd_mp import mp


@Command.validate(validate_mp_connect)
@Command.with_help("MaxPatrol site commands tree, get sites hierarchy")
@Command.with_name("site")
@Command
def mp_site(command_context: CommandContext) -> CommandContext:
    """
    Site root, sites hierarchy
    """
    mp_site.logger.debug("Run mp site")
    try:
        iface_site = iface_MP_Site()
    except KeyboardInterrupt:
        return CommandContext(state=False, state_msg="Operation interrupted")
    except BaseException as err:
        mp_site.logger.error("MP site API init failed: {}".format(err))
        return CommandContext(state=False, state_msg="MP site API init failed: {}".format(err))
    return command_context.instead(context_data=iface_site.list, data_fmt="yaml")


mp.add(mp_site)