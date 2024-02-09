from app.core.command import Command, CommandContext, core


@Command.with_help("MaxPatrol commands tree")
@Command.with_name("mp")
@Command
def mp(_command_context: CommandContext) -> CommandContext:
    """
    MaxPatrol commands tree
    """
    return CommandContext(state=False, state_msg="Wrong command")


core.add(mp)
