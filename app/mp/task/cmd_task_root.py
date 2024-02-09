from app.core.command import Command, CommandContext
from app.mp.cmd_mp import mp


@Command.with_help("MaxPatrol Task commands tree")
@Command.with_name("task")
@Command
def mp_task(_command_context: CommandContext) -> CommandContext:
    """
    Task root
    """
    return CommandContext(state=False, state_msg="Wrong command")


mp.add(mp_task)
