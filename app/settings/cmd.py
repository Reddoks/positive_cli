import app
from app.core.command import Command, CommandContext, core


# MaxPatrol Settings Tree instance
@Command.with_name("settings")
@Command.with_help("Settings tree")
@Command
def settings(_command_context: CommandContext) -> CommandContext:
    """
    Settings tree
    """
    return CommandContext(state=True, context_data=app.app.SETTINGS.data, data_fmt="yaml")


# MaxPatrol Settings Tree instance
@Command.with_options([
    {"key": "log_level", "required": False, "help": "Set log level: INFO, ERROR, DEBUG"},
    {"key": "log_path", "required": False, "help": "Set log path"},
    {"key": "history_path", "required": False, "help": "Set history path"}
])
@Command.with_name("set")
@Command.with_help("Set settings parameter - use --parameter=value")
@Command
def settings_set(command_context: CommandContext) -> CommandContext:
    """
    Set settings
    """
    args = command_context.get_arg()
    arg_split = args.split(" ")
    for item in arg_split:
        if len(item) > 2:
            if item[0] == "-" and item[1] == "-":
                stripped_item = item[2:]
                if "=" in stripped_item:
                    spl_item = stripped_item.split("=")
                    for key, value in app.app.SETTINGS.data.items():
                        if key == spl_item[0]:
                            app.app.SETTINGS.set(spl_item[0], spl_item[1])
    return CommandContext(state=True)


settings.add(settings_set)
core.add(settings)
