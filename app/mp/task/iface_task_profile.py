import logging
import app
import re
import datetime
from app.app import EVENTS
from app.core.func import get_keys_from_dict, console_clear_up, get_string_from_fmt
from app.mp.func import (func_select_list_item, fnmatch_ext)
from app.mp.api import MPAPIResponse
from rich.progress import Progress
from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter
from rich import print as rich_print


class iface_MP_TaskProfile:  # noqa
    def __init__(self, load=True):
        """
        Interface for task profiles
        :param load: if false - do not load profiles list
        """
        self.logger = logging.getLogger("mp.task.iface_profile")
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
        Get task profile information
        :param pattern: string
        :param dct: profile dict
        :param lst: profile list
        """
        from app.mp.mp.iface_mp import ID_refs

        profiles_list = None
        # If pattern
        if pattern:
            profiles_list = self.get_by_pattern(pattern=pattern)
            if profiles_list:
                if len(profiles_list) > 1:
                    profiles_list = [func_select_list_item(profiles_list)]
                    if profiles_list == [False] or profiles_list == [None]:
                        return MPAPIResponse(state=False, message="No profile found")
            else:
                return MPAPIResponse(state=False, message="No profile found")
        # If dict
        if dct:
            profiles_list = [dct]
        # If lst
        if lst:
            profiles_list = lst
        if profiles_list:
            out_list = []
            if len(profiles_list) > 5:
                rich_print("[yellow]It can get some time")
            try:
                id_refs = ID_refs(["credential", "profile", "dictionary"])
            except KeyboardInterrupt:
                return MPAPIResponse(state=False, message="Operation interrupted")
            except BaseException as err:
                self.logger.error("Failed to initialize reference APIs: {}".format(err))
                return MPAPIResponse(state=False, message="Failed to initialize reference APIs: {}".format(err))
            with Progress() as progress:
                task = progress.add_task("Getting profiles information...", total=len(profiles_list))
                for item in profiles_list:
                    progress.update(task, advance=1)
                    info = self.__get_info(item.get("id"))
                    if not info.state and info.message == "Operation interrupted":
                        return MPAPIResponse(state=False, message="Operation interrupted")
                    if info.state:
                        info = info.message
                        refs = id_refs.get_references(info)
                        if not refs.state:
                            return refs
                        info["cli-mixin"] = {
                            "mixin_ref_version": app.MIXIN_REF_VERSION,
                            "kind": "profile",
                            "timestamp": str(datetime.datetime.now()),
                            "product": app.API_MP.product,
                            "references_id": refs.message
                        }
                        out_list.append(info)
                    else:
                        self.logger.error("Profile {} not found".format(item))
                        return MPAPIResponse(state=False, message="Profile {} not found".format(item))
            console_clear_up(skip_line=True)
            if len(out_list) == 0:
                return MPAPIResponse(state=False, message="No profiles found")
            return MPAPIResponse(state=True, message=out_list)
        else:
            return MPAPIResponse(state=False, message="No profiles found")

    def create(self, raw_spec: dict, disarm=True) -> MPAPIResponse:
        """
        Create task profile from spec
        :param raw_spec: source spec
        :param disarm: run in test mode
        """
        from app.mp.mp.iface_mp import ID_refs
        self.logger.debug("Trying to create profile from specification")
        # Reload profile list
        response = self.__load_list()
        if not response.state:
            EVENTS.push(status="Fail", action="Create", instance="Profile",
                        name=raw_spec.get("name"), instance_id=raw_spec.get("id"),
                        details=response.message)
            return response
        self.list = response.message
        # Prepare specification
        print("Trying to create profile: {}... ".format(raw_spec.get("name")))
        exist = self.get_by_name(raw_spec.get("name"))
        if exist:
            EVENTS.push(status="Fail", action="Create", instance="Profile",
                        name=raw_spec.get("name"), instance_id=raw_spec.get("id"),
                        details="Profile {} exist. Can`t create".format(raw_spec.get("name")))
            return MPAPIResponse(state=False,
                                 message="Profile {} exist. Can`t create".format(raw_spec.get("name")))
        self.logger.debug("Profile {} not exist".format(raw_spec.get("name")))
        try:
            id_refs = ID_refs(["credential", "profile", "dictionary"])
        except KeyboardInterrupt:
            return MPAPIResponse(state=False, message="Operation interrupted")
        except BaseException as err:
            self.logger.error("Failed to initialize reference APIs: {}".format(err))
            return MPAPIResponse(state=False, message="Failed to initialize reference APIs: {}".format(err))
        out_spec = id_refs.replace(raw_spec)
        if not out_spec.state:
            EVENTS.push(status="Fail", action="Create", instance="Profile",
                        name=raw_spec.get("name"), instance_id="N/A",
                        details=out_spec.message)
            return out_spec
        out_spec = out_spec.message
        del out_spec["cli-mixin"]
        spec = {
            "name": out_spec.get("name"),
            "description": out_spec.get("description"),
            "baseProfileId": out_spec.get("baseProfileId"),
            "overrides": out_spec.get("overrides")
        }
        if not app.app.GLOBAL_DISARM and not disarm:
            response = app.API_MP.post(app.API_MP.url_profile, spec)
        else:
            return MPAPIResponse(state=False, message="Success - disarmed")
        if not response.state:
            EVENTS.push(status="Fail", action="Create", instance="Profile",
                        name=raw_spec.get("name"), instance_id=raw_spec.get("id"),
                        details=response.message)
            return response
        self.logger.debug("Profile {} successfully created".format(response.message.json().get("id")))
        return MPAPIResponse(state=True,
                             message="MaxPatrol profile created: {}".format(response.message.json().get("id")))

    def delete(self, data: str, disarm=True) -> MPAPIResponse:
        """
        Delete task profile
        :param data: profile id string
        :param disarm: run in test mode
        """
        self.logger.debug("Trying to delete profile {}".format(data))
        if not app.app.GLOBAL_DISARM and not disarm:
            response = app.API_MP.delete(app.API_MP.url_profile_instance.format(data), data)
        else:
            print("Success - disarmed")
            return MPAPIResponse(state=True, message="Success - disarmed")
        if not response.state:
            return response
        self.logger.debug("Profile {} successfully deleted".format(data))
        return MPAPIResponse(state=True, message="Profile {} successfully deleted".format(data))

    def get_profile_picker(self, prompt_string: str) -> MPAPIResponse:
        """
        Pick scan profile dialog with autocompletion
        :param prompt_string: dialog prompt
        """
        profile_names, profile_ids = self.get_short_list()
        profile_completer = WordCompleter(profile_names, sentence=True)
        while True:
            try:
                profile_input = prompt(prompt_string, completer=profile_completer, complete_while_typing=True)
            except KeyboardInterrupt:
                return MPAPIResponse(state=False, message="Operation interrupted")
            if profile_input == "":
                return MPAPIResponse(state=False, message="Skip profile enter")
            if profile_input == "?":
                print("Available profiles:")
                print(get_string_from_fmt(profile_names, fmt="yaml"))
                continue
            if "*" in profile_input:
                print("Available profiles:")
                for item in profile_names:
                    if fnmatch_ext(item, profile_input):
                        print("- {}".format(item))
                continue
            for idx in range(0, len(profile_names)):
                if profile_names[idx] == profile_input:
                    return MPAPIResponse(state=True, message={"name": profile_names[idx],
                                                              "id": profile_ids[idx]})
            rich_print("[red]Wrong profile")

    def get_by_name(self, name: str) -> dict | None:
        """
        Get profile by name
        :param name: string
        """
        self.logger.debug("Trying to get profile info for name: {}".format(name))
        for profile in self.list:
            if profile.get("name") == name:
                return profile
        self.logger.debug("No profiles found")
        return

    def get_by_id(self, source_id: str) -> dict | None:
        """
        Get profile by name
        :param source_id: string
        """
        self.logger.debug("Trying to get profile info for ID: {}".format(source_id))
        for profile in self.list:
            if profile.get("id") == source_id:
                return profile
        self.logger.debug("No profiles found")
        return

    def get_by_pattern(self, pattern: str) -> list | None:
        """
        Get profile by name or ID
        :param pattern: string name or ID
        """
        out_list = []
        # Trying to get by ID
        profile = self.get_by_id(source_id=str(pattern))
        if profile:
            return [profile]
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
        Get profile short list - name and ID
        """
        names = []
        ids = []
        for item in self.list:
            names.append(item.get("name"))
            ids.append(item.get("id"))
        return names, ids

    def get_reference(self, spec: dict) -> MPAPIResponse:
        """
        Look instance for profile IDs and return reference
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
                    profile_info = self.get_by_id(source_id=struct)
                    if profile_info:
                        return [{"id": struct, "kind": "profile", "name": profile_info.get("name")}]
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
        Profile info reducer
        """
        if type(data) == list:
            output = []
            for item in data:
                output.append(
                    get_keys_from_dict(item,
                                       ["id", "name", "output", "isSystem", "baseProfileName", "moduleName"]))
        else:
            output = get_keys_from_dict(data,
                                        ["id", "name", "output", "isSystem", "baseProfileName", "moduleName"])
        return output

    @staticmethod
    def reduce_list(data: dict | list) -> dict | list:
        """
        Profile list reducer
        """
        if type(data) == list:
            output = []
            for item in data:
                output.append(
                    get_keys_from_dict(item, ["name", "isSystem", "baseProfileName", "moduleName", "output"]))
        else:
            output = get_keys_from_dict(data, ["name", "isSystem", "baseProfileName", "moduleName", "output"])
        return output

    @staticmethod
    def remove_builtin(lst: list) -> list:
        """
        Remove built-in profiles from list
        :param lst: source list
        """
        output = []
        for item in lst:
            if not item.get("isSystem"):
                output.append(item)
        return output

    def __get_info(self, profile_id: str) -> MPAPIResponse:
        """
        Get profile information
        :param profile_id: string
        """
        self.logger.debug("Trying to load scanning profile info")
        response = app.API_MP.get(app.API_MP.url_profile_instance.format(profile_id))
        if not response.state:
            self.logger.error("Scanning profile information load failed: {}".format(response.message))
            return response
        self.logger.debug("Scanning profile information load succeeded")
        return MPAPIResponse(state=True, message=response.message.json())

    def __load_list(self) -> MPAPIResponse:
        """
        Profile list loader
        """
        self.logger.debug("Trying to load scanning profiles")
        response = app.API_MP.get(app.API_MP.url_profile)
        if not response.state:
            self.logger.error("Scanning profiles load failed: {}".format(response.message))
            return response
        self.logger.debug("Scanning profiles load succeeded")
        return MPAPIResponse(state=True, message=response.message.json())
