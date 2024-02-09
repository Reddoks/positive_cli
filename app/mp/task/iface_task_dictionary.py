import logging
import app
import re
from app.app import EVENTS
from app.core.func import console_clear_up, get_keys_from_dict, get_string_from_fmt
from app.mp.func import (func_select_list_item,
                         func_apply_mixin, fnmatch_ext)
from app.mp.api import MPAPIResponse
from rich.progress import Progress
from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter
from rich import print as rich_print


class iface_MP_TaskDictionary: # noqa
    def __init__(self, load=True):
        """
        Interface for dictionaries
        :param load: if false - do not load dictionaries list
        """
        self.logger = logging.getLogger("mp.task.iface_dictionary")
        if load:
            response = self.__load_list()
            if not response.state:
                if response.message == "Operation interrupted":
                    raise KeyboardInterrupt()
                else:
                    raise Exception(response.message)
            self.list = response.message
        else:
            self.list = []

    def info(self, pattern=None, dct=None, lst=None) -> MPAPIResponse:
        """
        Get dictionary information
        :param pattern: string name or ID
        :param lst: dict list
        :param dct: dict dct
        """
        dictionary_list = None
        # If pattern
        if pattern:
            dictionary_list = self.get_by_pattern(pattern=pattern)
            if dictionary_list:
                if len(dictionary_list) > 1:
                    dictionary_list = [func_select_list_item(dictionary_list)]
                    if dictionary_list == [False] or dictionary_list == [None]:
                        return MPAPIResponse(state=False, message="No dictionary found")
            else:
                return MPAPIResponse(state=False, message="No dictionary found")
        # If dict
        if dct:
            dictionary_list = [dct]
        # If lst
        if lst:
            dictionary_list = lst
        if dictionary_list:
            out_list = []
            if len(dictionary_list) > 5:
                rich_print("[yellow]It can get some time")
            with Progress() as progress:
                task = progress.add_task("Getting dictionaries information...", total=len(dictionary_list))
                for item in dictionary_list:
                    progress.update(task, advance=1)
                    info = self.__get_info(item.get("id"))
                    if info.state:
                        info = info.message
                        out_list.append(info)
            console_clear_up(skip_line=True)
            if len(out_list) == 0:
                return MPAPIResponse(state=False, message="No dictionaries info found")
            out_list = func_apply_mixin(out_list, "dictionary")
            return MPAPIResponse(state=True, message=out_list)
        else:
            return MPAPIResponse(state=False, message="No dictionaries info found")

    def create(self, raw_spec: dict, disarm=True) -> MPAPIResponse:
        """
        Create dictionary from specification
        :param raw_spec: source spec
        :param disarm: run in test mode
        """
        self.logger.debug("Trying to create dictionary from specification")
        # Reload profile list
        response = self.__load_list()
        if not response.state:
            EVENTS.push(status="Fail", action="Create", instance="Dictionary",
                        name=raw_spec.get("name"), instance_id=raw_spec.get("id"),
                        details=response.message)
            return response
        self.list = response.message
        exist = self.get_by_name(raw_spec.get("name"))
        if exist:
            EVENTS.push(status="Fail", action="Create", instance="Dictionary",
                        name=raw_spec.get("name"), instance_id=raw_spec.get("id"),
                        details="Dictionary {} exist. Can`t create".format(raw_spec.get("name")))
            return MPAPIResponse(state=False,
                                 message="Dictionary {} exist. Can`t create".format(raw_spec.get("name")))
        spec = {
            "name": raw_spec.get("name"),
            "content": raw_spec.get("content")
        }
        if not app.app.GLOBAL_DISARM and not disarm:
            response = app.API_MP.post(app.API_MP.url_dictionary, spec)
        else:
            return MPAPIResponse(state=False, message="Success - disarmed")
        if not response.state:
            EVENTS.push(status="Fail", action="Create", instance="Dictionary",
                        name=raw_spec.get("name"), instance_id=raw_spec.get("id"),
                        details=response.message)
            return response
        self.logger.debug("Dictionary {} successfully created".format(response.message.json().get("id")))
        return MPAPIResponse(state=True,
                             message="Dictionary {} successfully created".format(response.message.json().get("id")))

    def delete(self, data: str, disarm=True) -> MPAPIResponse:
        """
        Delete dictionary
        :param data: string ID
        :param disarm: run in test mode
        """
        self.logger.debug("Trying to delete dictionary {}".format(data))
        if not app.app.GLOBAL_DISARM and not disarm:
            response = app.API_MP.delete(app.API_MP.url_dictionary_instance.format(data), data)
        else:
            print("Success - disarmed")
            return MPAPIResponse(state=True, message="Success - disarmed")
        if not response.state:
            return response
        self.logger.debug("Dictionary {} successfully deleted".format(data))
        return MPAPIResponse(state=True, message="Dictionary {} successfully deleted".format(data))

    def get_dictionary_picker(self, prompt_string: str) -> MPAPIResponse:
        """
        Pick dictionary dialog with autocompletion
        :param prompt_string: dialog prompt
        """
        dict_names, dict_ids = self.get_short_list()
        dict_completer = WordCompleter(dict_names, sentence=True)
        while True:
            try:
                dict_input = prompt(prompt_string, completer=dict_completer, complete_while_typing=True)
            except KeyboardInterrupt:
                return MPAPIResponse(state=False, message="Operation interrupted")
            if dict_input == "":
                return MPAPIResponse(state=False, message="Skip profile enter")
            if dict_input == "?":
                print("Available dictionaries:")
                print(get_string_from_fmt(dict_names, fmt="yaml"))
                continue
            if "*" in dict_input:
                print("Available dictionaries:")
                for item in dict_names:
                    if fnmatch_ext(item, dict_input):
                        print("- {}".format(item))
                continue
            for idx in range(0, len(dict_names)):
                if dict_names[idx] == dict_input:
                    return MPAPIResponse(state=True, message={"name": dict_names[idx],
                                                              "id": dict_ids[idx]})
            rich_print("[red]Wrong dictionary")

    def get_by_name(self, name: str) -> dict | None:
        """
        Get dictionary by name
        :param name: string
        """
        self.logger.debug("Trying to get dictionary for name: {}".format(name))
        for credential in self.list:
            if credential.get("name") == name:
                return credential
        self.logger.debug("No dictionary found")
        return

    def get_by_id(self, dict_id: str) -> dict | None:
        """
        Get dictionary by ID
        :param dict_id: string
        """
        self.logger.debug("Trying to get dictionary for ID: {}".format(dict_id))
        for credential in self.list:
            if credential["id"] == dict_id:
                return credential
        self.logger.debug("No dictionary found")
        return

    def get_by_pattern(self, pattern: str) -> list | None:
        """
        Get dictionary by name or ID
        :param pattern: string name or ID
        """
        out_list = []
        # Trying to get by ID
        dictionary = self.get_by_id(dict_id=str(pattern))
        if dictionary:
            return [dictionary]
        # Trying to get by name
        for item in self.list:
            if fnmatch_ext(item.get("name").lower(), str(pattern).lower()):
                out_list.append(item)
        if len(out_list) == 0:
            return
        else:
            return out_list

    def get_short_list(self) -> [list, list]:
        """
        Get dictionary short list - name and ID
        """
        names = []
        ids = []
        for item in self.list:
            names.append(item.get("name"))
            ids.append(item.get("id"))
        return names, ids

    def get_reference(self, spec: dict) -> MPAPIResponse:
        """
        Look instance for dictionary IDs and return reference
        :param spec: specification instance
        """

        def build_originals(reference: list) -> list:
            out_lst = []
            for item in reference:
                is_present = False
                for itm in out_lst:
                    if itm.get("id") == item.get("id"):
                        is_present = True
                if not is_present:
                    out_lst.append(item)
            return out_lst

        def lookup_in_key(struct: any) -> list | None:
            if isinstance(struct, list):
                out_lst = []
                for item in struct:
                    ins = lookup_in_key(struct=item)
                    if ins:
                        out_lst += ins
                if len(out_lst) == 0:
                    return
                else:
                    return out_lst
            if isinstance(struct, dict):
                out_lst = []
                for ky, vue in struct.items():
                    ins = lookup_in_key(struct=vue)
                    if ins:
                        out_lst += ins
                if len(out_lst) == 0:
                    return
                else:
                    return out_lst
            if isinstance(struct, str):
                id_pattern = re.compile("[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+")
                if re.match(id_pattern, struct) and struct != spec.get("id"):
                    dictionary_info = self.get_by_id(dict_id=struct)
                    if dictionary_info:
                        return [{"id": struct, "kind": "dictionary", "name": dictionary_info.get("name")}]
                return

        out_list = []
        for key, value in spec.items():
            inst = lookup_in_key(value)
            if inst:
                out_list += inst
        out_list = build_originals(out_list)
        return MPAPIResponse(state=True, message=out_list)

    @staticmethod
    def reduce_info(data: dict | list) -> dict | list:
        """
        Dictionary info reducer
        """
        if type(data) == list:
            output = []
            for item in data:
                output.append(
                    get_keys_from_dict(item,
                                       ["id", "name", "isSystem", "content"]))
        else:
            output = get_keys_from_dict(data,
                                        ["id", "name", "isSystem", "content"])
        return output

    @staticmethod
    def remove_builtin(lst: list) -> list:
        """
        Remove built-in dictionaries from list
        :param lst: source list
        """
        output = []
        for item in lst:
            if not item.get("isSystem"):
                output.append(item)
        return output

    def __get_info(self, dictionary_id: str) -> MPAPIResponse:
        """
        Get dictionary information
        :param dictionary_id: string
        """
        self.logger.debug("Trying to load dictionary info")
        response = app.API_MP.get(app.API_MP.url_dictionary_instance.format(dictionary_id))
        if not response.state:
            self.logger.error("Dictionary information load failed: {}".format(response.message))
            return response
        self.logger.debug("Dictionary information load succeeded")
        return MPAPIResponse(state=True, message=response.message.json())

    def __load_list(self) -> MPAPIResponse:
        """
        Dictionary list loader
        """
        self.logger.debug("Trying to load dictionaries")
        response = app.API_MP.get(app.API_MP.url_dictionary)
        if not response.state:
            self.logger.error("'Dictionaries load failed: {}".format(response.message))
            return response
        self.logger.debug("'Dictionaries load succeeded")
        return MPAPIResponse(state=True, message=response.message.json())
