import logging
from prompt_toolkit import prompt, PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.shortcuts import CompleteStyle
from colorama import init

from app import app
from app.core.command import core, CommandContext
from app.core.func import fmt_std_output
import platform


# Prompt class
class Prompt:
    """
    CLI prompt class
    """

    def __init__(self, completer, style, history_file, prefix_constructor=None, welcome_msg=None):
        self.prefix_constructor = prefix_constructor
        self.completer = completer
        self.style = style
        self.history = app.EncryptedFileHistory(history_file)  # noqa
        self.welcome_msg = welcome_msg
        self.EXIT_TRIGGER = False
        self.logger = logging.getLogger("core.prompt")

    def run(self) -> None:
        """
        Prompt runner
        """
        # Enable console ANSI if windows
        if platform.system() == "Windows":
            init()
        # Run prompt loop
        self.logger.info("Starting CLI prompt loop.")
        if self.welcome_msg:
            print(self.welcome_msg)
        while not self.EXIT_TRIGGER:
            # Getting prompt
            if self.prefix_constructor:
                try:
                    prefix_prompt = self.prefix_constructor()
                except BaseException as err:
                    self.logger.fatal("Failed to get prompt prefix: {}".format(err), exc_info=False)
                    self.logger.debug("Error debug info: ", exc_info=True)
                    exit()
            else:
                prefix_prompt = "CLI-CORE > "
            self.logger.debug("Got prefix: {}".format(prefix_prompt))
            session = PromptSession(style=self.style, history=self.history, completer=self.completer,
                                    complete_while_typing=False, complete_style=CompleteStyle.READLINE_LIKE,
                                    auto_suggest=AutoSuggestFromHistory())
            prefix_before_len = len(prefix_prompt)
            # Ignore exception during prompt session
            try:
                prompt_text = session.prompt(prefix_prompt)
            except BaseException as err:
                self.logger.debug("Exception during prompt: {}".format(err))
                continue
            prompt_text = prompt_text.strip()
            # Ignore empty input
            if prompt_text:
                if len(prompt_text) == 0:
                    self.logger.debug("Prompt is empty - Ignoring")
                    continue
            else:
                continue
            self.logger.debug("Got from prompt: {}".format(prompt_text))
            # Cascading in prompt
            if prompt_text[-1] == "\\":
                self.logger.debug("Prompt continuation begin")
                prompt_continuation = True
                prompt_text = prompt_text[:-1]
                while prompt_continuation:
                    try:
                        cascaded_prompt = session.prompt(" " * prefix_before_len)
                    except BaseException as err:
                        self.logger.debug("Exception during prompt: {}".format(err))
                        continue
                    if len(cascaded_prompt) == 0:
                        self.logger.debug("Prompt is empty - Ignoring")
                        continue
                    if cascaded_prompt[-1] != "\\":
                        prompt_continuation = False
                        self.logger.debug("Prompt continuation end")
                    else:
                        cascaded_prompt = cascaded_prompt[:-1]
                        self.logger.debug("Got cascaded prompt: {}".format(cascaded_prompt))
                    prompt_text += cascaded_prompt
            # Cascading in entered prompt
            if "\n" in prompt_text:
                # Reassemble prompt
                prompt_text_split = prompt_text.split("\\\n")
                idx = 0
                for item in prompt_text_split:
                    clear_item = item.replace("\\\n", "")
                    clear_item = clear_item.strip()
                    if idx == 0:
                        prompt_text = clear_item
                    else:
                        prompt_text += " " + clear_item
                    idx += 1
            # Processing prompt
            self.logger.info("Final prompt string: {}".format(prompt_text))
            # Looking for chain
            if '&&' in prompt_text:
                self.logger.debug("Chain found in prompt string. Running chain")
                prompt_chain = prompt_text.split('&&')
                for item in prompt_chain:
                    command = item.strip()
                    result_context = core(command_context=CommandContext(tail_string=command))
                    if app.app.CONTEXT:
                        app.app.LAST_CONTEXT = app.app.CONTEXT
                    app.app.CONTEXT = result_context
                    fmt_std_output(result_context)
            else:
                result_context = core(command_context=CommandContext(tail_string=prompt_text))
                if app.app.CONTEXT:
                    app.app.LAST_CONTEXT = app.app.CONTEXT
                app.app.CONTEXT = result_context
                fmt_std_output(result_context)


def input_prompt(prompt_string: str, is_password=False) -> str:
    """
    Safe prompt function
    :param prompt_string: String for prompt
    :param is_password: Mask input
    :return: Input string or none
    """
    try:
        value = prompt(prompt_string, is_password=is_password)
        return value
    except BaseException as err:  # noqa
        return ""
