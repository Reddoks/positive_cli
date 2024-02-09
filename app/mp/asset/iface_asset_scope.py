import logging
import re

import app
from app.mp.api import MPAPIResponse
from app.core.func import fnmatch_ext, get_string_from_fmt
from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter


class iface_MP_Scope: # noqa
    def __init__(self, load=True):
        """
        Interface for Infrastructure Scopes
        """
        self.logger = logging.getLogger("mp.asset.iface_scope")
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

    def get_by_id(self, scope_id: str) -> dict | None:
        """
        Get Scope by ID
        :param scope_id: string ID
        """
        for item in self.list:
            if item.get("id") == scope_id:
                return item
        return

    def get_by_name(self, name: str) -> dict | None:
        """
        Get Scope by name
        :param name: string name
        """
        for item in self.list:
            if item.get("name") == name:
                return item
        return

    def get_reference(self, spec: dict) -> MPAPIResponse:
        """
        Look instance for asset query IDs and return reference
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
                    scope = self.get_by_id(scope_id=struct)
                    if scope:
                        return [{"id": struct, "kind": "scope", "name": scope.get("name")}]
                return

        out_list = []
        for key, value in spec.items():
            inst = lookup_in_key(value)
            if inst:
                out_list += inst
        out_list = build_originals(out_list)
        return MPAPIResponse(state=True, message=out_list)

    def get_scope_picker(self, prompt_string: str) -> MPAPIResponse:
        """
        Scope selection dialog with autocompletion
        :param prompt_string: prompt for dialog
        """
        # Build plain scope list based on hierarchy
        scope_names, scope_ids = self.__get_short_list()
        scope_completer = WordCompleter(scope_names, sentence=True)
        while True:
            try:
                scope_input = prompt(prompt_string, completer=scope_completer, complete_while_typing=True)
            except KeyboardInterrupt:
                return MPAPIResponse(state=False, message="Operation interrupted")
            if scope_input == "":
                return MPAPIResponse(state=False, message="Skip scope enter")
            if scope_input == "?":
                print("Available scopes:")
                print(get_string_from_fmt(scope_names, fmt="yaml"))
                continue
            if "*" in scope_input:
                print("Available scopes:")
                for item in scope_names:
                    if fnmatch_ext(item, scope_input):
                        print("- {}".format(item))
                continue
            for idx in range(0, len(scope_names)):
                if scope_names[idx] == scope_input:
                    return MPAPIResponse(state=True, message={"name": scope_names[idx],
                                                              # noqa
                                                              "id": scope_ids[idx]})
            print("Wrong scope")

    def __get_short_list(self) -> [list, list]:
        """
        Get rules short list - name and ID
        """
        names = []
        ids = []
        for scope in self.list:
            names.append(scope.get("name"))
            ids.append(scope.get("id"))
        return names, ids

    def __load_list(self) -> MPAPIResponse:
        """
        Scope list load
        """
        self.logger.debug("Trying to load scopes list")
        response = app.API_MP.get(app.API_MP.url_asset_scope)
        if not response.state:
            self.logger.error("Scopes list load failed: {}".format(response.message))
            return response
        self.logger.debug("Scopes list load succeeded")
        return MPAPIResponse(state=True, message=response.message.json())
