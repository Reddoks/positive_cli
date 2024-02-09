import logging
import app
import re
from app.core.func import get_keys_from_dict, get_string_from_fmt
from app.mp.func import func_get_list_ids_from_list, func_get_list_by_pattern, func_select_list_item, fnmatch_ext
from app.mp.api import MPAPIResponse
from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter


class iface_MP_AEC: # noqa
    def __init__(self, load=True):
        """
        Interface for AECs
        :param load: if false - do not load AEC list
        """
        self.logger = logging.getLogger("mp.iface_aec")
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

    def __load_list(self) -> MPAPIResponse:
        """
        AEC list loader
        :return: AEC list
        """
        self.logger.debug("Trying to load AEC list")
        response = app.API_MP.get(app.API_MP.url_aecs)
        if not response.state:
            self.logger.error("AEC list load failed: {}".format(response.message))
            return response
        self.logger.debug("AEC list load succeeded")
        return MPAPIResponse(state=True, message=response.message.json())

    def info(self, pattern=None, lst=None) -> MPAPIResponse:
        """
        Get AEC information
        :param pattern: string or ID
        :param lst: list of AEC ids
        :return: list with AEC information
        """
        # If pattern
        if pattern:
            self.logger.debug("Trying to get AEC info for pattern: {}".format(pattern))
            aec_list = func_get_list_by_pattern(self.list, pattern)
            if aec_list:
                self.logger.debug("Found {} AECs".format(len(aec_list)))
                if len(aec_list) > 1:
                    aec_list = [func_select_list_item(aec_list)]
                    if aec_list == [False] or aec_list == [None]:
                        return MPAPIResponse(state=False, message="No AECs found")
                return MPAPIResponse(state=True, message=aec_list)
            else:
                self.logger.debug("No AECs found")
                return MPAPIResponse(state=False, message="No AECs found")
        if lst:
            out_list = []
            aec_list = func_get_list_ids_from_list(lst)
            if aec_list:
                for item in aec_list:
                    info = self.get_by_id(item)
                    if info:
                        out_list.append(info)
            return MPAPIResponse(state=True, message=out_list)
        else:
            self.logger.debug("Missing pattern to get AEC info")
            return MPAPIResponse(state=False, message="Missing pattern to get AEC info")

    def get_by_pattern(self, pattern: str) -> dict | None:
        """
        Get AEC from list by pattern
        :param pattern: string or ID
        :return: AEC list item
        """
        if pattern:
            self.logger.debug("Trying to get AEC info for pattern: {}".format(pattern))
            aec_list = func_get_list_by_pattern(self.list, pattern)
            if aec_list:
                self.logger.debug("Found {} AECs".format(len(aec_list)))
                if len(aec_list) > 1:
                    aec_list = [func_select_list_item(aec_list)]
                    if aec_list == [False] or aec_list == [None]:
                        return
                return aec_list[0]
            else:
                self.logger.debug("No AECs found")
                return
        else:
            self.logger.debug("Missing pattern to get AEC info")
            return

    def get_aec_picker(self, prompt_string: str) -> MPAPIResponse:
        """
        AEC picker with autocompleter
        :param prompt_string: prompt message
        :return: AEC name and ID
        """
        aec_names, aec_ids = self.get_short_list()
        aec_completer = WordCompleter(aec_names, sentence=True)
        while True:
            try:
                aec_input = prompt(prompt_string, completer=aec_completer, complete_while_typing=True)
            except KeyboardInterrupt:
                return MPAPIResponse(state=False, message="Operation interrupted")
            if aec_input == "":
                return MPAPIResponse(state=False, message="Skip AEC enter")
            if aec_input == "?":
                print("Available AECs:")
                print(get_string_from_fmt(aec_names, fmt="yaml"))
                continue
            if "*" in aec_input:
                print("Available AECs:")
                for item in aec_names:
                    if fnmatch_ext(item, aec_input):
                        print("- {}".format(item))
                continue
            for idx in range(0, len(aec_names)):
                if aec_names[idx] == aec_input:
                    return MPAPIResponse(state=True, message={"name": aec_names[idx],
                                                              "id": aec_ids[idx]})
            print("Wrong AEC")

    def get_by_name(self, name: str) -> dict | None:
        """
        Get AEC from list by name
        :param name: string
        :return: AEC list item
        """
        self.logger.debug("Trying to get AEC info for name: {}".format(name))
        for aec in self.list:
            if aec.get("name") == name:
                return aec
        self.logger.debug("No AECs found")
        return

    # Get aec by ID
    def get_by_id(self, aec_id: str) -> dict | None:
        """
        Get AEC from list by ID
        :param aec_id: string
        :return: AEC list item
        """
        self.logger.debug("Trying to get aec info for ID: {}".format(aec_id))
        for aec in self.list:
            if aec.get("id") == aec_id:
                return aec
        self.logger.debug("No AECs found")
        return

    def get_short_list(self) -> [list, list]:
        """
        Get reduced AEC list
        :return: AEC names, AEC ids
        """
        names = []
        ids = []
        for item in self.list:
            names.append(item.get("name"))
            ids.append(item.get("id"))
        return names, ids

    def get_reference(self, spec: dict) -> MPAPIResponse:
        """
        Look instance for AEC IDs and return reference
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
                    aec_info = self.get_by_id(aec_id=struct)
                    if aec_info:
                        return [{"id": struct, "kind": "aec", "name": aec_info.get("name")}]
                return

        out_list = []
        for key, value in spec.items():
            inst = lookup_in_key(value)
            if inst:
                out_list += inst
        out_list = build_originals(out_list)
        return MPAPIResponse(state=True, message=out_list)

    @staticmethod
    def reduce_list(data: dict | list) -> dict | list:
        """
        AEC list reducer
        :param data: AEC list
        :return: reduced AEC list
        """
        if isinstance(data, list):
            output = []
            for item in data:
                output.append(
                    get_keys_from_dict(item, ["name", "platform", "version", "roleNames", "ipAddresses", "status"]))
        else:
            output = get_keys_from_dict(data, ["name", "platform", "version", "roleNames", "ipAddresses", "status"])
        return output
