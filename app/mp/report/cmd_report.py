from app.core.command import Command, CommandContext
from app.mp.cmd_mp import mp


@Command.with_help("MaxPatrol Report commands tree")
@Command.with_name("report")
@Command
def mp_report(_command_context: CommandContext) -> CommandContext:
    """
    Report root
    """
    return CommandContext(state=False, state_msg="Wrong command")


mp.add(mp_report)
