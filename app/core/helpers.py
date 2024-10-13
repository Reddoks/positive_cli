import base64

import json
import logging
import os
import yaml
from operator import itemgetter
from sys import exit

from cryptography.fernet import Fernet
from rich.prompt import Prompt
from rich import print as rich_print

from app import app
from app.core.command import Command, CommandContext, core, Variables
from app.core.func import deep_set, deep_get, get_fmt_data, paged_std_output, validate_pipe, search_in_object, \
    get_string_from_fmt, get_file_list_by_pattern, LogicValidation, JSONParse, json_setter, quoted_comma_split


# Helpers
@Command.validate(validate_pipe)
@Command.with_name("first")
@Command.with_options([
    {"key": "arg", "required": False}
])
@Command
def helper_first(command_context: CommandContext) -> CommandContext:
    """
    Helper, works only in pipe
    Get first N lines
    """
    if not command_context.context_data:
        helper_first.logger.error("First: Data is empty")
        return CommandContext(parent=command_context.parent, state=False,
                              state_msg="First: Data is empty")
    if isinstance(command_context.context_data, list):
        output = []
        if len(command_context.context_data) > 0:
            if command_context.get_arg():
                if command_context.get_arg().isdigit():
                    num_lines = int(command_context.get_arg())
                    if len(command_context.context_data) > num_lines:
                        for idx in range(0, num_lines):
                            output.append(command_context.context_data[idx])
            else:
                output = [command_context.context_data[0]]
            return command_context.instead(context_data=output)
    helper_first.logger.error("First: Wrong data context")
    return CommandContext(parent=command_context.parent, state=False,
                          state_msg="First: Wrong data context")


# Getting Last N
@Command.validate(validate_pipe)
@Command.with_name("last")
@Command.with_options([
    {"key": "arg", "required": False}
])
@Command
def helper_last(command_context: CommandContext) -> CommandContext:
    """
    Helper, works only in pipe
    Get last N lines
    """
    if not command_context.context_data:
        helper_last.logger.error("Last: Data is empty")
        return CommandContext(parent=command_context.parent, state=False,
                              state_msg="Last: Data is empty")
    if isinstance(command_context.context_data, list):
        output = []
        if len(command_context.context_data) > 0:
            if command_context.get_arg():
                if command_context.get_arg().isdigit():
                    num_lines = int(command_context.get_arg())
                    if len(command_context.context_data) > num_lines:
                        for idx in range(len(command_context.context_data) -
                                         num_lines, len(command_context.context_data)):
                            output.append(command_context.context_data[idx])
            else:
                output = [command_context.context_data[len(command_context.context_data) - 1]]
            return command_context.instead(context_data=output)
    helper_last.logger.error("Last: Wrong data context")
    return CommandContext(parent=command_context.parent, state=False,
                          state_msg="Last: Wrong data context")


@Command.with_help("Assign variable with value")
@Command.with_options([
    {"key": "arg", "required": False,
     "help": "Variable assignment string: $variable=value or $variable=$(command expression)"},
])
@Command.with_name("set")
@Command
def helper_set(command_context: CommandContext) -> CommandContext:
    """
    Set variable by value or by expression result
    """
    local_context = command_context
    if not command_context.get_arg():
        return CommandContext(state=False,
                              state_msg="Invalid variable assignment string. Can`t find assignment string")
    assignment_string = command_context.get_arg()
    if assignment_string[0] != "$":
        helper_set.logger.error("Invalid variable assignment string: {}".format(assignment_string))
        return CommandContext(state=False, state_msg="Invalid variable assignment string")
    if not command_context.context_data and "=" not in assignment_string:
        helper_set.logger.error("Invalid variable assignment string: {}".format(assignment_string))
        return CommandContext(state=False, state_msg="Invalid variable assignment string")
    assignment_split = assignment_string.split('=')
    if command_context.context_data:
        var_name = assignment_split[0].strip()[1:]
        var_value = command_context.context_data
    else:
        var_name = assignment_split[0].strip()[1:]
        var_value = assignment_split[1].strip()
    if " " in var_name:
        helper_set.logger.error("Invalid variable name: {}".format(var_name))
        return CommandContext(state=False, state_msg="Invalid variable name")
    # If command expression
    if isinstance(var_value, str):
        if len(var_value) > 3 and isinstance(var_value, str):
            if var_value[0] == "$" and var_value[1] == '(' and var_value[-1] == ')':
                expression = var_value[2:]
                expression = expression[:-1]
                expression_result = core(CommandContext(tail_string=expression))
                if not expression_result:
                    return CommandContext()
                var_value = expression_result.context_data
                local_context.data_fmt = expression_result.data_fmt
                local_context.parent = expression_result.parent
                local_context.data_transform = expression_result.data_transform
                local_context.data_islist_transform = expression_result.data_islist_transform
    # If no data format provided
    if not local_context.data_fmt:
        local_context.data_fmt, var_value = get_fmt_data(var_value)
    # If complex assignment
    if '.' in var_name:
        split = var_name.split(".", 1)
        primary = split[0]
        secondary = split[1]
        if primary not in Variables:
            helper_set.logger.error("Invalid root variable: {}".format(primary))
            return CommandContext(state=False, state_msg="Invalid root variable: {}".format(primary))
        deep_set(Variables[primary].context_data, secondary, var_value)
    else:
        helper_set.logger.debug("Variable '{}' has set to {}".format(var_name, var_value))
        Variables[var_name] = CommandContext(context_data=var_value, parent=local_context.parent,
                                             data_fmt=local_context.data_fmt,
                                             data_transform=local_context.data_transform,
                                             data_islist_transform=local_context.data_islist_transform)
    return CommandContext()


@Command.with_help("Print variable value")
@Command.with_options([
    {"key": "arg", "required": False, "help": "Variable name: $variable"},
])
@Command.with_name("echo")
@Command
def helper_echo(command_context: CommandContext) -> CommandContext:
    """
    Print variable value
    """
    if command_context.context_data:
        return command_context
    if not command_context.get_arg():
        return CommandContext(state=False)
    return command_context.instead(context_data=command_context.get_arg(), data_fmt="json")


@Command.with_help("Exit from CLI")
@Command.with_name("exit")
@Command
def helper_exit(_command_context: CommandContext) -> None:
    """
    Exit from CLI
    """
    logger = logging.getLogger("core.cmd")
    logger.info("Terminate requested")
    exit()


@Command.with_help("Clear CLI screen")
@Command.with_name("cls")
@Command
def helper_cls(_command_context: CommandContext) -> CommandContext:
    """
    Clear console
    """
    os.system('cls' if os.name == 'nt' else 'clear')
    return CommandContext()


@Command.with_help("CLI Version")
@Command.with_name("version")
@Command
def helper_version(_command_context: CommandContext) -> CommandContext:
    """
    Version information
    """
    print("PT CLI Version " + app.app.VERSION)
    return CommandContext()


@Command.with_help("Show commands history")
@Command.with_options([
    {"key": "clear", "required": False, "help": "Clean history"},
])
@Command.with_name("history")
@Command
def helper_history(command_context: CommandContext) -> CommandContext:
    """
    Display history
    """
    if "clear" in command_context.get_kwarg():
        try:
            os.remove(app.HISTORY_PATH)
            return CommandContext(state=True, state_msg="Command history cleaned.")
        except BaseException as err:
            helper_history.logger.error("Failed to history cleanup: {}".format(err))
    output = []
    try:
        cipher_suite = Fernet(app.app.SECRET_KEY)
    except BaseException as err:
        helper_history.logger.error("Crypto module failed: {}".format(err))
        return CommandContext(state=False, state_msg="Crypto module failed: {}".format(err))
    with open(app.app.HISTORY_PATH, "rb") as f:
        for line in f:
            line = line[:-1]
            decrypted = cipher_suite.decrypt(line)
            clear_line = decrypted.decode("utf-8")
            cont_split = clear_line.split("\n")
            for ln in cont_split:
                if ln.startswith("+"):
                    output.append(ln[1:])
    if command_context.is_piped:
        return command_context.instead(context_data=output, data_fmt="list")
    paged_std_output(CommandContext(context_data=output, data_fmt="list"))


@Command.validate(validate_pipe)
@Command.with_name("more")
@Command
def helper_more(command_context: CommandContext) -> CommandContext:
    """
    Helper, works only in pipe
    Paginated display
    """
    if not command_context.context_data:
        return CommandContext(parent=command_context.parent, state=False,
                              state_msg="More: Data is empty")
    paged_std_output(command_context)


@Command.validate(validate_pipe)
@Command.with_options([
    {"key": "position", "required": False, "help": "Get value from list position (0 by default)."},
    {"key": "property", "required": False, "help": "Get value from property"},
    {"key": "unique", "required": False, "help": "Only unique values"},
])
@Command.with_name("get")
@Command
def helper_get(command_context: CommandContext) -> CommandContext:
    """
    Helper, works only in pipe
    Get parameter from context: ... | get parameter
    Also can get item from list with --position=N key
    """
    if not command_context.context_data:
        helper_get.logger.error("Data is empty")
        return CommandContext(parent=command_context.parent, state=False,
                              state_msg="Get: Data is empty")
    output = None
    if "position" in command_context.get_kwarg() and isinstance(command_context.context_data, list):
        if not command_context.get_kwarg("position"):
            position = 0
        else:
            if not command_context.get_kwarg("position").isdigit():
                helper_get.logger.error("Position must be digit")
                return CommandContext(parent=command_context.parent, state=False,
                                      state_msg="Get: Position must be digit")
            position = int(command_context.get_kwarg("position"))
        if len(command_context.context_data) > position:
            if command_context.get_arg():
                output = deep_get(command_context.context_data[position], command_context.get_arg())
                if isinstance(output, list):
                    if len(output) == 1:
                        output = output[0]
            else:
                output = command_context.context_data[int(position)]
        else:
            helper_get.logger.error("List position out of range")
            return CommandContext(parent=command_context.parent, state=False,
                                  state_msg="Get: List position out of range")
    if "property" in command_context.get_kwarg():
        output = deep_get(command_context.context_data, command_context.get_kwarg("property"))
        if isinstance(output, list):
            if len(output) == 1:
                output = output[0]
    if "unique" in command_context.get_kwarg():
        if isinstance(output, list):
            out_list = []
            for item in output:
                exist = False
                for itm in out_list:
                    if itm == item:
                        exist = True
                        break
                if exist:
                    continue
                out_list.append(item)
            output = out_list
    if output:
        data_fmt, out_value = get_fmt_data(output)
    else:
        return CommandContext()
    return command_context.instead(context_data=out_value, data_fmt=data_fmt, data_transform="reset")


@Command.validate(validate_pipe)
@Command.with_options([
    {"key": "arg", "required": True, "help": "Property path i.e. key1.key2.key3"},
    {"key": "new", "required": True, "help": "New value to set"},
    {"key": "old", "required": False, "help": "Old value to replace. Skip this parameter to set value instead replace"},
])
@Command.with_name("replace")
@Command
def helper_replace(command_context: CommandContext) -> CommandContext:
    """
    Helper, works only in pipe
    Replace or set value on given path
    """

    def replace_instance(json_object: dict, tgt, old_val, new_val) -> dict | int:
        # Check property exists
        parsed_json = JSONParse(source=json_object)
        prop = parsed_json.get(path_list=[tgt])
        # Second chance with quotes
        if not prop:
            quoted_target = '"' + tgt + '"'
            prop = parsed_json.get(path_list=[quoted_target])
            if prop:
                tgt = quoted_target
        if not prop and old_val:
            return -1
        # Setting new value
        res = json_object
        if not old_val:
            res = json_setter(json_object, tgt, new_val)
            if res == -1:
                return -2
        else:
            res = json_setter(json_object, tgt, new_val, old_val)
            if res == -1:
                return -2
        return res

    # Check context is list or dict
    if not isinstance(command_context.context_data, dict | list):
        return CommandContext(parent=command_context.parent, state=False,
                              state_msg="Wrong context. Context should be dict or list type.")
    target_path = command_context.get_arg()
    if command_context.get_kwarg("old"):
        value_old = command_context.get_kwarg("old")
    else:
        value_old = None
    value_new = command_context.get_kwarg("new")
    # Look for lists and quoting
    if value_old:
        value_old = quoted_comma_split(value_old)
    value_new = quoted_comma_split(value_new)
    if value_old:
        rich_print("[bright_black]Trying to replace [grey50]{}[bright_black] to [grey50]{} [bright_black]in [grey50]"
                   "{}".format(value_old, value_new, target_path))
    else:
        rich_print("[bright_black]Trying to set [grey50]{}[bright_black] in "
                   "[grey50]{}".format(value_new, target_path))
    replace_result = None
    if isinstance(command_context.context_data, list):
        replace_result = []
        for itm in command_context.context_data:
            result = replace_instance(itm, target_path, value_old, value_new)
            if result == -1:
                return CommandContext(parent=command_context.parent, state=False,
                                      state_msg="Property {} not found or null. You can use '--old=null' "
                                                "to set this property.".format(target_path))
            if result == -2:
                return CommandContext(parent=command_context.parent, state=False,
                                      state_msg="Unable to set property {}.".format(target_path))
            if result == -3:
                return CommandContext(parent=command_context.parent, state=False,
                                      state_msg="No matched values found for {}.".format(target_path))
            replace_result.append(result)
    else:
        replace_result = replace_instance(command_context.context_data, target_path, value_old, value_new)
        if replace_result == -1:
            return CommandContext(parent=command_context.parent, state=False,
                                  state_msg="Property {} not found or null. You can use '--old=null' "
                                            "to set this property.".format(target_path))
        if replace_result == -2:
            return CommandContext(parent=command_context.parent, state=False,
                                  state_msg="Unable to set property {}.".format(target_path))
        if replace_result == -3:
            return CommandContext(parent=command_context.parent, state=False,
                                  state_msg="No matched values found for {}.".format(target_path))

    return command_context.instead(context_data=replace_result)


@Command.validate(validate_pipe)
@Command.with_options([
    {"key": "arg", "required": True, "help": "Tuple of property names(paths)"},
])
@Command.with_name("extract")
@Command
def helper_extract(command_context: CommandContext) -> CommandContext:
    """
    Helper, works only in pipe
    Extract selected keys from data structure
    """

    def extract_from_dict(k_list: list, source_data: dict) -> dict:
        output = {}
        for key in k_list:
            key_result = deep_get(source_data, key)
            if key_result:
                output[key] = key_result
        return output

    def extract_from_list(k_list: list, source_data: list) -> list:
        output = []
        for itm in source_data:
            if isinstance(itm, dict):
                dict_result = extract_from_dict(k_list, itm)
                if len(dict_result) > 0:
                    output.append(dict_result)
        return output

    # Getting keys list
    keys_list = command_context.get_arg().split(",")
    parsed_json = JSONParse(source=command_context.context_data)
    out_data = parsed_json.get(path_list=keys_list)
    # for idx, item in enumerate(keys_list):
    # parsed_json = JSONParse(source=command_context.context_data)
    # parsed_json.get_multi(path_list=keys_list))
    # Get multi
    # keys_list[idx] = item.strip()
    # out_data = None
    # if isinstance(command_context.context_data, list):
    #    out_data = extract_from_list(keys_list, command_context.context_data)
    # if isinstance(command_context.context_data, dict):
    #    out_data = extract_from_dict(keys_list, command_context.context_data)
    return command_context.instead(context_data=out_data, data_fmt="yaml", data_transform="reset")


@Command.with_help("Get context from last command")
@Command.with_name("context")
@Command.with_options([
    {"key": "last", "required": False, "help": "Get previous context"},
])
@Command
def helper_context(command_context: CommandContext) -> CommandContext:
    """
    Get context from last command
    """
    if "last" in command_context.get_kwarg():
        if not app.app.LAST_CONTEXT:
            helper_context.logger.error("Previous context: Is empty")
            return CommandContext(parent=command_context.parent, state=False,
                                  state_msg="Previous context: Is empty")
        out_context = app.app.LAST_CONTEXT
    else:
        if not app.app.CONTEXT:
            helper_context.logger.error("Context: Is empty")
            return CommandContext(parent=command_context.parent, state=False,
                                  state_msg="Context: Is empty")
        out_context = app.app.CONTEXT
    return out_context.instead(is_piped=command_context.is_piped)


@Command.validate(validate_pipe)
@Command.with_help("Limit context list")
@Command.with_name("limit")
@Command.with_options([
    {"key": "arg", "required": True, "help": "Number of limit items"},
    {"key": "offset", "required": False, "help": "Optional set start offset"}
])
@Command
def helper_limit(command_context: CommandContext) -> CommandContext:
    """
    Limit context list for N items
    """
    def get_frame(raw_list: list, lim: int, off: int) -> list:
        """
        Getting dataframe related to offset and limit
        """
        out_data = []
        frame_len = lim
        if off >= len(raw_list):
            return []
        if (off + lim) > len(raw_list):
            frame_len = len(raw_list) - off
        for idx_x in range(off, off + frame_len):
            out_data.append(raw_list[idx_x])
        return out_data

    limit = command_context.get_arg()
    offset = app.app.CONTEXT_OFFSET
    if not limit.isnumeric():
        return CommandContext(state=False,
                              state_msg="Argument should be number")
    limit = int(limit)
    if command_context.get_kwarg("offset"):
        kw_offset = command_context.get_kwarg("offset")
        if not kw_offset.isnumeric():
            return CommandContext(state=False,
                                  state_msg="Offset should be number")
        offset = int(kw_offset)
    if not isinstance(command_context.context_data, list):
        return CommandContext(state=False,
                              state_msg="Applicable only for 'list' context")
    if offset > len(command_context.context_data):
        return CommandContext(state=False,
                              state_msg="Offset is out off range context data")
    out_list = get_frame(command_context.context_data, limit, offset)
    app.app.CONTEXT_OFFSET = offset + limit
    return command_context.instead(context_data=out_list)


@Command.validate(validate_pipe)
@Command.with_options([
    {"key": "arg", "required": True, "help": "Data format: 'table', 'csv', 'json', 'yaml'"},
])
@Command.with_name("fmt")
@Command
def helper_fmt(command_context: CommandContext) -> CommandContext:
    """
    Helper, works only in pipe
    Change output format for context: table, csv, json, yaml
    """
    from app.core.command import BlockContextData
    if not command_context.context_data:
        helper_fmt.logger.error("Data is empty")
        return CommandContext(parent=command_context.parent, state=False,
                              state_msg="Format: Data is empty")
    # Block Context handle
    if isinstance(command_context.context_data, BlockContextData):
        match command_context.get_arg():
            case "tree":
                new_context = command_context.instead(data_fmt='tree')
            case "table":
                new_context = command_context.instead(data_fmt='table')
            case "json":
                new_context = command_context.instead(data_fmt='json', force_transform=False)
            case "yaml":
                new_context = command_context.instead(data_fmt='yaml', force_transform=False)
            case "csv":
                new_context = command_context.instead(data_fmt='csv')
            case _:
                return CommandContext(parent=command_context.parent, state=False,
                                      state_msg="Format: Wrong format")
        return new_context
    match command_context.get_arg():
        case "tree":
            return command_context.instead(data_fmt='tree')
        case "table":
            return command_context.instead(data_fmt='table')
        case "json":
            return command_context.instead(data_fmt='json', force_transform=False)
        case "yaml":
            return command_context.instead(data_fmt='yaml', force_transform=False)
        case "csv":
            return command_context.instead(data_fmt='csv')
    helper_fmt.logger.info("Wrong format: {}".format(command_context.get_arg()))
    return CommandContext(parent=command_context.parent, state=False,
                          state_msg="Format: Wrong format")


@Command.validate(validate_pipe)
@Command.with_options([
    {"key": "arg", "required": True, "help": "String to find"},
])
@Command.with_name("find_property")
@Command
def helper_find_prop(command_context: CommandContext) -> CommandContext:
    """
    Helper, works only in pipe
    Find property with given name
    """
    if not command_context.context_data:
        helper_find_prop.logger.error("Data is empty")
        return CommandContext(parent=command_context.parent, state=False,
                              state_msg="Find: Data is empty")
    pattern = command_context.get_arg()
    kind = "plain"
    if command_context.data_fmt == "tree":
        kind = "tree"
    output = search_in_object(command_context.context_data, pattern, kind, typ="key")
    if not output:
        return CommandContext()
    if len(output) == 0:
        return CommandContext()
    return command_context.instead(context_data=output, data_fmt="json", data_transform="reset")


@Command.validate(validate_pipe)
@Command.with_options([
    {"key": "arg", "required": True, "help": "String to find"},
])
@Command.with_name("find")
@Command
def helper_find(command_context: CommandContext) -> CommandContext:
    """
    Helper, works only in pipe
    Find elements with given value
    """
    if not command_context.context_data:
        helper_find.logger.error("Data is empty")
        return CommandContext(parent=command_context.parent, state=False,
                              state_msg="Find: Data is empty")
    pattern = command_context.get_arg()
    kind = "plain"
    if command_context.data_fmt == "tree":
        kind = "tree"
    if isinstance(pattern, str):
        pattern = pattern.replace('"', "")
    output = search_in_object(command_context.context_data, pattern, kind)
    if not output:
        return CommandContext()
    if len(output) == 0:
        return CommandContext()
    # If initial fmt is table - keep format
    if command_context.data_fmt:
        if command_context.data_fmt == "yaml":
            return command_context.instead(context_data=output, data_fmt='yaml')
        if command_context.data_fmt == "json":
            return command_context.instead(context_data=output, data_fmt='json')
        if command_context.data_fmt == "table":
            return command_context.instead(context_data=output, data_fmt='table')
        if command_context.data_fmt == "tree":
            return command_context.instead(context_data=output, data_fmt='tree')
    return command_context.instead(context_data=output, data_fmt='list')


@Command.validate(validate_pipe)
@Command.with_options([
    {"key": "arg", "required": True,
     "help": "Expression: property==value, also possible ~= and != operators. "
             "Also you can use `and` & `or` logical operators"},
])
@Command.with_name("select")
@Command
def helper_select(command_context: CommandContext) -> CommandContext:
    if not command_context.context_data:
        helper_select.logger.error("Data is empty")
        return CommandContext(parent=command_context.parent, state=False,
                              state_msg="Select: Data is empty")
    output = []
    if not isinstance(command_context.context_data, list):
        helper_select.logger.error("Wrong data type - expecting "
                                   "list, got {}".format(type(command_context.context_data)))
        return CommandContext(parent=command_context.parent, state=False,
                              state_msg="Wrong data type - expecting "
                                        "list, got {}".format(type(command_context.context_data)))
    if not isinstance(command_context.context_data[0], dict):
        helper_select.logger.error("Wrong data type - expecting "
                                   "list of dicts, got list of {}".format(type(command_context.context_data[0])))
        return CommandContext(parent=command_context.parent, state=False,
                              state_msg="Wrong data type - expecting "
                                        "list of dicts, got list of {}".format(type(command_context.context_data[0])))
    if command_context.data_fmt == "tree":
        return CommandContext(state=False, state_msg="Not applicable for tree type of data")
    try:
        validate_logic = LogicValidation(command_context.get_arg())
    except BaseException as err:
        return CommandContext(state=False, state_msg=err)
    # Process items
    for item in command_context.context_data:
        verdict = validate_logic.validate(item)
        if verdict:
            output.append(item)
    if not output:
        return CommandContext(state=False, state_msg="No items found")
    return command_context.instead(context_data=output)


@Command.validate(validate_pipe)
@Command.with_options([
    {"key": "arg", "required": True, "help": "Target filename"},
    {"key": "encryption", "required": False, "help": "Export encrypted specification(s)"}
])
@Command.with_name("export")
@Command
def helper_export(command_context: CommandContext) -> CommandContext:
    """
    Helper, works only in pipe
    Export context to file. Can export to encrypted file.
    """
    if not command_context.context_data:
        helper_export.logger.error("Data is empty")
        return CommandContext(parent=command_context.parent, state=False,
                              state_msg="Export: Data is empty")
    output = get_string_from_fmt(data=command_context.context_data, fmt=command_context.data_fmt,
                                 transform=command_context.data_transform,
                                 is_transform_list=command_context.data_islist_transform)
    mode = "w"
    encoding = "utf-8"
    if "encryption" in command_context.get_kwarg():
        try:
            source_key = Prompt.ask("Secret key", password=True)
        except KeyboardInterrupt:
            return CommandContext(state=False, state_msg="Operation interrupted")
        code_bytes = source_key.encode("utf-8")
        secret_key = base64.urlsafe_b64encode(code_bytes.ljust(32)[:32])
        cipher_suite = Fernet(secret_key)
        mode = "wb"
        encoding = None
        output = cipher_suite.encrypt(output.encode("utf-8"))
    try:
        with open(command_context.get_arg(), mode, encoding=encoding) as file:
            file.write(output)
        return CommandContext(state=True)
    except file.write:
        helper_export.logger.error("Export: Failed output to file {}".format(command_context.get_arg()), exc_info=False)
        helper_export.logger.debug("Error info: ", exc_info=True)
        return CommandContext(state=False,
                              state_msg="Failed to write file {}".format(command_context.get_arg()))


# Import from file
@Command.with_help("Import data from file(s). Only JSON or YAML content supported")
@Command.with_options([
    {"key": "arg", "required": True, "help": "Source filename"},
    {"key": "encryption", "required": False, "help": "Import encrypted specification(s)"}
])
@Command.with_name("import")
@Command
def helper_import(command_context: CommandContext) -> CommandContext:
    """
    Import data from files
    """

    # Read file content
    def read_file(path: str, encrypt: bool) -> dict | list | None:
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
            with open(path, mode, encoding=encoding) as file:
                # Try to read JSON structure from file
                if encrypt:
                    try:
                        encrypted = file.read()
                        data = cipher_suite.decrypt(encrypted)
                        data = data.decode('utf-8')
                    except BaseException as err:
                        print("Something went wrong. Probably secret key is invalid. Error: {}".format(err))
                        return
                else:
                    data = file.read()
        except BaseException as err:
            path, name = os.path.split(path)
            print("Unable to read file {}. Error: {}".format(name, err))
            return None
        try:
            json_data = json.loads(data)
            helper_import.logger.debug("Import: Loaded JSON from file " + command_context.get_arg(),
                                       exc_info=False)
            return json_data
        except BaseException as err:
            helper_import.logger.debug("Import: File does not contains valid JSON: {}".format(err), exc_info=False)
            helper_import.logger.debug("Error info: ", exc_info=True)
            # Try to read YAML structure from file
            try:
                # Reset read cursor
                yaml_data = yaml.safe_load(data)
                helper_import.logger.debug("Import: Loaded YAML from file {}".format(command_context.get_arg()),
                                           exc_info=False)
                return yaml_data
            except BaseException as err:
                helper_import.logger.debug("Import: File does not contains valid YAML: {}".format(err), exc_info=False)
                helper_import.logger.debug("Error info: ", exc_info=True)
                path, name = os.path.split(path)
                print("Import: File {} does not contains valid JSON or YAML data".format(name))
                return

    # Looking multiple files
    targets = get_file_list_by_pattern(command_context.get_arg())
    if not targets:
        return CommandContext(state=False, state_msg="No files found")
    # If we have multiple - iterate on list
    output = []
    if len(targets) > 0:
        for target in targets:
            encryption = False
            if "encryption" in command_context.get_kwarg():
                encryption = True
            # Reading files
            iterated_data = read_file(target, encryption)
            if not iterated_data:
                continue
            if isinstance(iterated_data, dict):
                output.append(iterated_data)
            if isinstance(iterated_data, list):
                output += iterated_data
    if len(output) > 0:
        return command_context.instead(context_data=output, data_fmt="json")
    return CommandContext(state=False, state_msg="No data in file(s)")


@Command.validate(validate_pipe)
@Command.with_options([
    {"key": "arg", "required": False, "help": "Optional. Sort property, first by default"},
    {"key": "desc", "required": False, "help": "Optional. Sort direction descending, ascending by default"}
])
@Command.with_name("sort")
@Command
def helper_sort(command_context: CommandContext) -> CommandContext:
    """
    Helper, works only in pipe
    Sorting by given property value
    """
    if not command_context.context_data:
        helper_sort.logger.error("Data is empty")
        return CommandContext(parent=command_context.parent, state=False,
                              state_msg="Sort: Data is empty")
    if not isinstance(command_context.context_data, list):
        helper_sort.logger.error("Wrong type: {}. Only list data type "
                                 "can be sorted".format(type(command_context.context_data)))
        return CommandContext(parent=command_context.parent, state=False,
                              state_msg="Sort: Only list data type can be sorted")
    if len(command_context.context_data) == 0:
        helper_sort.logger.error("Data is empty")
        return CommandContext(parent=command_context.parent, state=False,
                              state_msg="Sort: Data is empty")
    data_tmp = command_context.context_data
    if command_context.data_transform:
        if command_context.data_islist_transform:
            data_tmp = []
            for item in command_context.context_data:
                data_tmp.append(command_context.data_transform(item))
        else:
            data_tmp = command_context.data_transform(data_tmp)
    # Simple list processing
    if isinstance(data_tmp[0], str):
        if "desc" in command_context.options[1]:
            output = sorted(data_tmp, reverse=True)
        else:
            output = sorted(data_tmp)
    # Key list processing
    else:
        # If property defined
        param = None
        param_arg = command_context.get_arg()
        if param_arg:
            for itm in data_tmp[0].keys():
                if param_arg.lower() == itm.lower():
                    param = itm
            if not param:
                param = list(data_tmp[0].keys())[0]
        if not param_arg:
            param = list(data_tmp[0].keys())[0]
        if "desc" in command_context.options[1]:
            output = sorted(data_tmp, key=itemgetter(param), reverse=True)
        else:
            output = sorted(data_tmp, key=itemgetter(param))
    return command_context.instead(context_data=output, data_transform="reset", data_islist_transform=False)


core.add(helper_exit)
core.add(helper_cls)
core.add(helper_context)
core.add(helper_limit)
core.add(helper_first)
core.add(helper_last)
core.add(helper_more)
core.add(helper_sort)
core.add(helper_version)
core.add(helper_find)
core.add(helper_find_prop)
core.add(helper_select)
core.add(helper_get)
core.add(helper_extract)
core.add(helper_replace)
core.add(helper_export)
core.add(helper_import)
core.add(helper_fmt)
core.add(helper_set)
core.add(helper_echo)
core.add(helper_history)
