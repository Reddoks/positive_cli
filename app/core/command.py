import logging
import re

from app.core.func import deep_get


class Command:
    """
    Main command class
    """

    def __init__(self, function):
        self.function = function
        self.name = function.__name__
        self.help_string = "No command description provided"
        self.nested_help = {}
        self.options = []
        self.run_validator = None
        self.logger = logging.getLogger("core.cmd.{}".format(self.name))

    def __call__(self, command_context=None):
        """
        Command function call
        :param command_context: Context for command function
        :return: Command_context structure
        """
        # Call run validator if present
        if self.run_validator:
            if isinstance(self.run_validator, list):
                for item in self.run_validator:
                    validate = item(self, command_context)
                    if not validate:
                        return validate
            else:
                validate = self.run_validator(self, command_context)
                if not validate:
                    return validate
        # If no context, execute
        if not command_context:
            options_validation = self.__validate_options({})
            if not options_validation.state:
                self.logger.error("Failed to execute command - no required options provided:"
                                  " {}".format(options_validation.state_msg))
                return CommandContext(parent=self.name, state=False,
                                      state_msg="Failed to execute command - no "
                                                "required options provided: {}".format(options_validation.state_msg))
            try:
                return self.function(CommandContext(parent=self.name))
            except BaseException as err:
                self.logger.error("Failed to execute command {}".format(self.name), exc_info=False)
                self.logger.debug("Error debug info: ", exc_info=True)
                return CommandContext(parent=self.name, state=False,
                                      state_msg="Failed to execute command {}: {}".format(self.name, err))
        # If context, processing
        self.logger.debug("Processing context: state: {}, parent:{}, is piped:{}".format(
            command_context.state, command_context.parent, command_context.is_piped))
        # If context with failed state
        if not command_context.state:
            self.logger.error("Got failed context for piped command"
                              ": {}".format(command_context.state_msg))
            self.logger.error("Failed to execute command {}".format(self.name))
            return CommandContext(parent=self.name, state=False,
                                  state_msg="Got failed context for piped command"
                                            ": {}".format(command_context.state_msg))
        # If no tail string
        if not command_context.tail_string:
            options_validation = self.__validate_options({})
            if not options_validation.state:
                self.logger.error("Failed to execute command - no required options "
                                  "provided: {}".format(options_validation.state_msg))
                return CommandContext(parent=self.name, state=False,
                                      state_msg="Failed to execute command - no "
                                                "required options provided: {}".format(options_validation.state_msg))
            self.logger.info("Execute final: {}".format(self.name))
            return self.function(CommandContext(parent=command_context.parent,
                                                context_data=command_context.context_data,
                                                data_fmt=command_context.data_fmt,
                                                data_transform=command_context.data_transform,
                                                data_islist_transform=command_context.data_islist_transform,
                                                is_piped=command_context.is_piped,
                                                piped_next=command_context.piped_next))
        # Looking pipe in current tail, if exist - run pipe runner
        # Clean possible wrapped expression
        # Trying to get parts, if parts exist, run pipe
        l_tail, r_tail = self.__get_pipe_parts(command_context)
        if l_tail and r_tail:
            return self.__run_pipe(command_context)
        # Looking for primary tag and tail
        primary, tail = self.__get_primary_and_tail(command_context.tail_string)
        self.logger.debug("Split context result: primary: {} tail: {}".format(primary, tail))
        # Handle help request
        if primary == "help" or primary == "?" or primary == "--help":
            return CommandContext(parent=self.name, data_fmt="string", context_data=self.__get_help_message(True))
        # Looking nested command if present
        if primary in self.__dict__ and primary != "name":
            # Execute nested command
            self.logger.debug("Executing nested: {} with tail: {}".format(primary, tail))
            return self.__dict__[primary](CommandContext(tail_string=tail, context_data=command_context.context_data,
                                                         parent=self.name, data_fmt=command_context.data_fmt,
                                                         data_transform=command_context.data_transform,
                                                         data_islist_transform=command_context.data_islist_transform,
                                                         is_piped=command_context.is_piped,
                                                         piped_next=command_context.piped_next))
        else:
            tail = command_context.tail_string
        options = self.__parse_options(tail)
        self.logger.debug("Options parsing result: {}".format(options))
        options_validation = self.__validate_options(options)
        self.logger.debug("Options validation result: {}".format(options_validation.__dict__))
        if not options_validation.state:
            self.logger.error("Failed to execute command - no required "
                              "options provided: {}".format(options_validation.state_msg))
            return CommandContext(parent=self.name, state=False,
                                  state_msg="Failed to execute command - "
                                            "no required options provided: {}".format(options_validation.state_msg))
        self.logger.info("Execute final: {}".format(self.name))
        return self.function(CommandContext(parent=command_context.parent, options=options,
                                            context_data=command_context.context_data,
                                            data_fmt=command_context.data_fmt,
                                            data_transform=command_context.data_transform,
                                            data_islist_transform=command_context.data_islist_transform,
                                            is_piped=command_context.is_piped,
                                            piped_next=command_context.piped_next))

    @staticmethod
    def with_name(name):
        """
        Wrapper for command name definition. Core will use name defined with this wrapper
        :param name: Command name
        :return: object
        """

        def decorator(obj):
            obj.name = name
            return obj

        return decorator

    @staticmethod
    def with_help(help_string):
        """
        Wrapper for command help. Core will use this help string for command
        :param help_string: Help string
        :return: object
        """

        def decorator(obj):
            obj.help_string = help_string
            return obj

        return decorator

    # Wrap. Options validator
    @staticmethod
    def with_options(options):
        """
        Wrapper for expected command options
        :param options: Should be defined as list of options [{option}, {option}]:
        - If you would like to get argument for command, key should be named 'arg':
            {"key": "arg", "required": True/False, "help": "Help string"}
        - If you would like to get key named arguments:
            {"key": "keyname", "required": True/False, "help": "Help string"}
        :return: object
        """

        def decorator(obj):
            obj.options = options
            return obj

        return decorator

    @staticmethod
    def validate(validator):
        """
        Wrapper for validators running before command execution
        :param validator: Is function or list of functions that will run before command execution
        Validator function should get two parameters: Command and CommandContext and return bool value:
            def validator(_command: Command, _context: CommandContext) -> bool:
                # Validate logic
                return True
        :return: object
        """

        def decorator(obj):
            obj.run_validator = validator
            return obj

        return decorator

    def add(self, obj) -> None:
        """
        Add subcommand to current. This will create nested command:
            command_root.add(nested_command)
            core.add(command_root)
        :param obj: nested command function name
        """
        self.__dict__[obj.name] = obj
        if obj.help_string != "No command description provided":
            self.nested_help[obj.name] = obj.help_string

    def __run_pipe(self, command_context):
        """
        Run piped command chain
        :param command_context: Context
        :return: Command_context structure
        """
        # tail_split = command_context.tail_string.rsplit('|', 1)
        # right_tail = tail_split[1].strip()
        # left_tail = tail_split[0].strip()
        # print("LTT:", left_tail)
        # print("RTT:", right_tail)
        left_tail, right_tail = self.__get_pipe_parts(command_context)
        # Execute pipe
        self.logger.debug("Execute pipes chain: {} with tail {}".format(right_tail, left_tail))
        # Getting next command
        primary = None
        if right_tail:
            primary, tail = self.__get_primary_and_tail(right_tail)
        left_tail_context = core(CommandContext(tail_string=left_tail, is_piped=True, piped_next=primary))
        if left_tail_context:
            left_tail_context.tail_string = right_tail
            self.logger.debug("Execute last command in pipes chain: {}".format(left_tail_context.__dict__))
            return core(left_tail_context)
        return CommandContext()

    @staticmethod
    def __get_pipe_parts(context) -> [str, str]:
        """
        Getting pipe parts from right side
        """

        def check_token_in_expression(cxt: str, token_pos: int) -> bool:
            """
            Check is pipe token in expression
            :param cxt: string
            :param token_pos: token position
            """
            right_exp = False
            left_exp = False
            # Check right shoulder
            for ix in range(token_pos + 1, len(cxt)):
                if cxt[ix] == ")":
                    right_exp = True
                    break
            # Check left shoulder
            for ix in range(token_pos, 0, -1):
                if cxt[ix] == "(" and cxt[ix - 1] == "$":
                    left_exp = True
                    break
            if right_exp and left_exp:
                return True

        # Starting from end of the string looking for quotes and pipes
        context = context.tail_string
        double_quoted = False
        single_quoted = False
        right_tail = None
        left_tail = None
        for idx in range(len(context) - 1, 0, -1):
            if context[idx] == '"':
                double_quoted = not double_quoted
            if context[idx] == "'":
                single_quoted = not single_quoted
            if context[idx] == "|" and not double_quoted and not single_quoted:
                if not check_token_in_expression(context, idx):
                    right_tail = context[-(len(context) - idx - 1):].strip()
                    left_tail = context[:idx].strip()
                    break
        return left_tail, right_tail

    @staticmethod
    def __get_primary_and_tail(string):
        """
        Split command string for primary token and tail
        :param string: command string
        :return: primary tag string, tail string
        """
        split = string.split(' ', 1)
        primary = string.split(' ', 1)[0]
        if len(split) > 1:
            tail = string.split(' ', 1)[1]
        else:
            tail = ''
        return primary, tail

    def __parse_options(self, string):
        """
        Extract options from string
        :param string: command string tail
        :return: argument, dict of key-named arguments
        """
        # Looking for args
        if self.name == "set":
            arg_exp = string.replace('"', "")
            kwargs = {}
        else:
            # If all tail is expression
            if len(string) > 2:
                if string[0] == "$" and string[-1] == ")":
                    expression = string.replace('"', "")
                    expression = expression[2:]
                    expression = expression[:-1]
                    expression_result = core(CommandContext(tail_string=expression, is_piped=True))
                    if expression_result.state:
                        arg = expression_result.context_data
                    else:
                        arg = ""
                    return arg, {}
            # Getting kwargs from string
            # Extract kwargs and args expressions
            kwarg_exp = []
            arg_exp = ""
            shift = 0
            for string_index in range(0, len(string)):
                # Looking for kwarg
                if string_index < len(string) - 1:
                    # Kwarg
                    if string[string_index] == "-" and string[string_index + 1] == "-":
                        cur_kwarg_exp = ""
                        in_expr = False
                        for k_inx in range(string_index + 2, len(string)):
                            # If space - end of kwarg expression
                            if string[k_inx] == " " and not in_expr:
                                break
                            if string[k_inx] == "'" or string[k_inx] == '"':
                                in_expr = not in_expr
                            cur_kwarg_exp += string[k_inx]
                        kwarg_exp.append(cur_kwarg_exp)
                        shift = len(cur_kwarg_exp) + 2
                if shift == 0:
                    arg_exp += string[string_index]
                else:
                    shift -= 1
            arg_exp = arg_exp.strip()
            # Looking for variable in argument
            if len(arg_exp) > 0 and self.name != 'set':
                if arg_exp[0] == "$":
                    # And it is not assignment
                    # Check expression if present
                    expression = re.search(r'\$\([^)]*\)', arg_exp)
                    if expression:
                        expression = expression.group(0)
                        expression = expression[2:]
                        expression = expression[:-1]
                        expression_result = core(CommandContext(tail_string=expression, is_piped=True))
                        if expression_result.state:
                            arg_exp = expression_result.context_data
                    elif "=" not in arg_exp:
                        arg_exp = get_var(arg_exp)
                        if not arg_exp:
                            arg_exp = ''
            # Unpack kwargs:
            kwargs = {}
            for item in kwarg_exp:
                # If value assignment in expression
                if "=" in item:
                    kwarg_split = item.strip().split("=")
                    if len(kwarg_split) > 1:
                        # Looking for variable
                        value_part = kwarg_split[1].lstrip()
                        if len(value_part) > 0:
                            if value_part[0] == "$":
                                value_part = get_var(value_part)
                        kwargs[kwarg_split[0].rstrip()] = value_part
                    else:
                        kwargs[kwarg_split[0].rstrip()] = ""
                # If no value
                else:
                    kwargs[item.rstrip()] = None
        # If arg complete in quotes, remove quotes
        if arg_exp:
            if isinstance(arg_exp, str):
                if arg_exp[0] == '"' and arg_exp[-1:] == '"':
                    arg_exp = arg_exp[1:-1]
                elif arg_exp[0] == "'" and arg_exp[-1:] == "'":
                    arg_exp = arg_exp[1:-1]
                elif arg_exp[0] == "`" and arg_exp[-1:] == "`":
                    arg_exp = arg_exp[1:-1]
        return arg_exp, kwargs

    def __get_help_message(self, no_opts=False):
        """
        Build help message
        :param no_opts: disable nested help strings
        :return: help message string
        """
        help_message = ''
        if self.name != 'core':
            help_message += "Command '{}': {}\n\n".format(self.name, self.help_string)
        # Build command list
        if len(self.nested_help) > 0:
            help_message += "COMMANDS:\n"
        else:
            if not no_opts:
                help_message += "NO COMMANDS\n"
        # Build commands help list
        help_list = []
        for key in self.__dict__:
            if key in self.nested_help:
                help_list.append(key.ljust(15) + str(' - ' + self.nested_help[key]).ljust(15) + '\n')
        help_list.sort()
        for item in help_list:
            help_message += item
        req_opts_help = self.__get_required_options_help()
        if len(req_opts_help) > 0:
            help_message += "REQUIRED OPTIONS:\n"
            help_message += req_opts_help
        else:
            if not no_opts:
                help_message += "NO REQUIRED OPTIONS\n"
        opts_help = self.__get_optional_options_help()
        if len(opts_help) > 0:
            help_message += "OPTIONS:\n"
            help_message += opts_help
        else:
            if not no_opts:
                help_message += "NO OPTIONS\n"
        return help_message

    def __get_required_options_help(self):
        """
        Getting help for required options
        :return: help string
        """
        opts_help = ''
        for opt in self.options:
            if opt.get("required"):
                string = opt.get('key')
                if string == "arg":
                    string = "argument"
                else:
                    string = '--' + string
                for sp in range(len(string), 25):
                    string = string + " "
                opts_help += string + opt.get('help') + '\n'
        return opts_help

    def __get_optional_options_help(self):
        """
        Getting help for optional options
        :return: help string
        """
        opts_help = ''
        for opt in self.options:
            if not opt['required']:
                string = opt.get('key')
                if string == "arg":
                    string = "argument"
                else:
                    string = "--" + string
                for sp in range(len(string), 25):
                    string = string + " "
                opts_help += string + opt.get('help') + '\n'
        return opts_help

    def __validate_options(self, option_dict=None):
        """
        Validate command options according to requirements
        :param option_dict: options dictionary
        :return: Command_context structure
        """
        if len(option_dict) < 2:
            option_dict = ('', {})
        # Check options dict
        if len(self.options) == 0:
            return CommandContext()
        for item in self.options:
            if item.get("key") == 'arg' and item.get("required"):
                if len(str(option_dict[0])) < 1:
                    return CommandContext(parent=self.name, state=False,
                                          state_msg="argument")
                continue
            if item.get("required"):
                if item.get("key") not in option_dict[1]:
                    return CommandContext(parent=self.name, state=False,
                                          state_msg="--{}".format(item.get("key")))
        return CommandContext()


class BlockContextData:
    """
    Blocked context data class
    Used to transfer specific context as objects
    Context objects must have the following methods: count, get_block
    """

    def __init__(self, source_object=None):
        """
        :param source_object: Source callable object
        """
        self.source_object = source_object
        self.intermediate = []

    def count(self) -> int | None:
        """
        Get rows count in source object
        """
        return self.source_object.count()

    def block(self, offset: int, limit: int) -> list | None:
        """
        Get final block context according to offset and limit.
        Run intermediate commands when piped
        :param offset: int
        :param limit: int
        """
        block_content = CommandContext(context_data=self.source_object.block(offset=offset,
                                                                             limit=limit), data_fmt="list")
        for item in self.intermediate:
            block_content = item(block_content.instead(is_piped=True))
        return block_content.context_data


# CommandContext class
class CommandContext:
    """
    Command context class
    """

    def __init__(self, tail_string=None, context_data=None, parent=None, state=True, state_msg='', data_fmt=None,
                 data_transform=None, data_islist_transform=False, force_transform=False, table_transform=False,
                 options=('', {}), is_piped=False, piped_next=None):
        self.state = state
        self.state_msg = state_msg
        self.tail_string = tail_string
        self.context_data = context_data
        self.data_fmt = data_fmt
        self.data_transform = data_transform
        self.data_islist_transform = data_islist_transform
        self.force_transform = force_transform
        self.table_transform = table_transform
        self.parent = parent
        self.options = options
        self.is_piped = is_piped
        self.piped_next = piped_next

    def get_arg(self):
        """
        Get argument
        :return: argument string or None
        """
        if self.options[0] == '':
            return None
        else:
            return self.options[0]

    def get_kwarg(self, kwarg=None):
        """
        Get key named argument
        :param kwarg: key named argument name
        :return: kwarg string or None
        """
        if not kwarg:
            return self.options[1]
        if kwarg in self.options[1]:
            return self.options[1][kwarg]
        else:
            return None

    def validate_next(self, rules) -> [bool, str]:
        """
        Context validator based on rules
        :param rules:
            Example (all cases):
                valid = command_context.validate({
                        "must": {
                            "or": [
                            ],
                            "and": [
                            ],
                            "struct": {
                                "type": "dict",
                                "fields": [],
                                "validate": {
                                    "field": "",
                                    "validator": function
                                }
                            }
                        },
                        "or": [
                        ],
                        "and": [
                        ]
                })
        """

        def check_structure(struct: dict) -> [bool, str]:
            if struct.get("type") == "str":
                if isinstance(self.context_data, str):
                    if struct.get("validate"):
                        try:
                            ch_str_valid, message = struct["validate"](self.context_data)
                        except BaseException as err:
                            return False, "Error in validation function execution: {}".format(err)
                        return ch_str_valid, message
                    return True, "OK"
                return False, "Wrong context type: {}, expected `string`".format(type(self.context_data))
            if struct.get("type") == "list":
                if isinstance(self.context_data, list):
                    if len(self.context_data) > 0:
                        # Validate fields set
                        pass
                    else:
                        return False, "Context data is empty"
                return False, "Wrong context type: {}, expected `list`".format(type(self.context_data))

        valid = False
        if not isinstance(rules, dict):
            return valid, "Wrong validation rules"

    def validate(self, rules):
        """
        Context validator based on rules
        :param rules: Validation example:
            valid = command_context.validate([
                {"type": "list", "fields": ["type", "id", "name", "description"]},
                { "type": "str" }, { "type": "none" }
            ])
        :return: Boolean
        """
        valid = False
        for item in rules:
            if item.get("type") == "str":
                if isinstance(self.context_data, str):
                    valid = True
            if item.get("type") == "list":
                if isinstance(self.context_data, list):
                    if len(self.context_data) > 0:
                        list_valid = True
                        for itm in item.get("fields"):
                            if itm not in self.context_data[0]:
                                list_valid = False
                        is_present = False
                        if item.get("some_fields"):
                            for itm in item.get("some_fields"):
                                if itm in self.context_data[0]:
                                    is_present = True
                            if not is_present:
                                list_valid = False
                        if list_valid:
                            valid = True
            if item.get("type") == "dict":
                if isinstance(self.context_data, dict):
                    dict_valid = True
                    for itm in item.get("fields"):
                        if itm not in self.context_data:
                            dict_valid = False
                    is_present = False
                    if item.get("some_fields"):
                        for itm in item.get("some_fields"):
                            if itm in self.context_data:
                                is_present = True
                        if not is_present:
                            dict_valid = False
                    if dict_valid:
                        valid = True
            if item.get("type") == "none":
                if not self.context_data:
                    valid = True
        return valid

    def instead(self, tail_string=None, context_data=None, parent=None, state=None, state_msg=None, data_fmt=None,
                data_transform=None, data_islist_transform=None, options=None, is_piped=None, force_transform=None,
                table_transform=None):
        """
        Use same command context, but replace some properties
        :param tail_string: prompt tail string
        :param context_data: data transferred with context
        :param parent: parent command name string
        :param state: bool state
        :param state_msg: string state message
        :param data_fmt: string data format: json, yaml, csv, table, tree
        :param data_transform: data transform function
        :param data_islist_transform: iterate list transforms
        :param options: options structure
        :param is_piped: bool piped flag
        :param force_transform: bool force flag
        :param table_transform: bool optional flag
        :return: Command context structure
        """
        if state:
            self.state = state
        if state_msg:
            self.state_msg = state_msg
        if tail_string:
            self.tail_string = tail_string
        if context_data:
            self.context_data = context_data
        if data_fmt:
            self.data_fmt = data_fmt
        if data_transform:
            if data_transform == "reset":
                self.data_transform = None
            else:
                self.data_transform = data_transform
        if data_islist_transform:
            self.data_islist_transform = data_islist_transform
        if force_transform:
            self.force_transform = force_transform
        if table_transform:
            self.table_transform = table_transform
        if parent:
            self.parent = parent
        if options:
            self.options = options
        if is_piped:
            self.is_piped = is_piped
        return self


# Variables store
Variables = {}


def get_var(variable: str) -> any:
    """
    Get variable from variables store
    :param variable: Variable name string: $name
    :return: variable value
    """
    var_name = variable[1:]
    # If deep
    if "." in var_name:
        split = var_name.split(".", 1)
        primary = split[0]
        secondary = split[1]
        if primary not in Variables:
            return None
        var_value = deep_get(Variables[primary].context_data, secondary)
    else:
        if var_name not in Variables:
            return None
        var_value = Variables[var_name].context_data

    return var_value


# Core instance
@Command
def core(_command_context: CommandContext) -> CommandContext:
    """
    Root command tree
    """
    return CommandContext(state=False, state_msg="Wrong command")


@Command.with_name("data_test")
@Command.with_help("Testing command. Use argument")
@Command.with_options([
    {"key": "arg", "required": True, "help": "Data type to out: json_dict, json_list, string, multistring"},
])
@Command
def data_test(command_context: CommandContext) -> CommandContext:
    """
    Command for testing
    """
    match command_context.get_arg():
        case "json_dict":
            output = {
                "top_key1": {
                    "2nd_level_1_key1": "Key",
                    "2nd_level_1_key2": "Key"
                },
                "top_key2": {
                    "2nd_level_2_key1": "Key",
                    "2nd_level_2_key2": "Key"
                }
            }
            return command_context.instead(context_data=output, data_fmt="json")
        case "json_list":
            output = [
                {
                    "top_key1": {
                        "2nd_level_1_key1": "Key",
                        "2nd_level_1_key2": "Key"
                    },
                    "top_key2": {
                        "2nd_level_2_key1": "Key",
                        "2nd_level_2_key2": "Key"
                    }
                },
                {
                    "top_key1": {
                        "2nd_level_1_key1": "Key2",
                        "2nd_level_1_key2": "Key2"
                    },
                    "top_key2": {
                        "2nd_level_2_key1": "Key2",
                        "2nd_level_2_key2": "Key2"
                    }
                }
            ]
            return command_context.instead(context_data=output, data_fmt="json")
        case "string":
            output = "Lorem ipsum dolor sit amet, ipsum dolor sit amet"
            return command_context.instead(context_data=output, data_fmt="string")
        case "multistring":
            output = "Lorem ipsum dolor sit amet, ipsum dolor sit amet\nText with Multi line here\nThird line"
            return command_context.instead(context_data=output, data_fmt="string")
    return CommandContext(parent=command_context.parent, state=False,
                          state_msg="Test: Wrong format")


core.add(data_test)
