import logging
import re
from datetime import datetime, timedelta

from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter
from rich.progress import Progress
from rich import print as rich_print

import app
from app.app import EVENTS
from app.core.func import get_keys_from_dict, console_clear_up, fnmatch_ext, get_string_from_fmt
from app.mp.api import MPAPIResponse
from app.mp.func import (func_select_list_item, func_get_list_ids_from_list)
from app.mp.user.iface_user_roles import iface_MP_UserRole


class iface_MP_User:  # noqa
    def __init__(self, load=True):
        """
        Interface for users
        :param load: if false - do not load user list
        """
        self.logger = logging.getLogger("mp.iface_user")
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
        self.actions_list = None

    def get_current_user(self) -> MPAPIResponse:
        """
        Get current user information
        """
        user_info = self.get_by_login(app.API_MP.login)
        if not user_info:
            return MPAPIResponse(state=False, message="Get current user {} failed".format(app.API_MP.login))
        return MPAPIResponse(state=True, message=user_info)

    def info(self, pattern=None, lst=None, dct=None) -> MPAPIResponse:
        """
        Get user information
        :param pattern: string
        :param lst: report list
        :param dct: report dct
        """
        from app.mp.mp.iface_mp import ID_refs
        user_list = None
        # If pattern
        if pattern:
            user_list = self.get_by_pattern(pattern=pattern)
            if user_list:
                if len(user_list) > 1:
                    user_list = [func_select_list_item(user_list, namefield="userName")]
                    if user_list == [False] or user_list == [None]:
                        return MPAPIResponse(state=False, message="No user found")
                user_list = func_get_list_ids_from_list(user_list)
            else:
                return MPAPIResponse(state=False, message="No user found")
        # If lst
        if lst:
            user_list = func_get_list_ids_from_list(lst)
        if dct:
            user_list = [dct]
        if user_list:
            out_list = []
            if len(user_list) > 5:
                rich_print("[yellow]It can get some time")
            try:
                id_refs = ID_refs(["user_role", "site"])
            except KeyboardInterrupt:
                return MPAPIResponse(state=False, message="Operation interrupted")
            except BaseException as err:
                self.logger.error("Failed to initialize reference APIs: {}".format(err))
                return MPAPIResponse(state=False, message="Failed to initialize reference APIs: {}".format(err))
            with Progress() as progress:
                task = progress.add_task("Getting user information...", total=len(user_list))
                for item in user_list:
                    progress.update(task, advance=1)
                    info = self.__get_info(item)
                    if not info.state and info.message == "Operation interrupted":
                        return MPAPIResponse(state=False, message="Operation interrupted")
                    if info.state:
                        info = info.message
                        refs = id_refs.get_references(info)
                        if not refs:
                            return refs
                        info["cli-mixin"] = {
                            "mixin_ref_version": app.MIXIN_REF_VERSION,
                            "kind": "user",
                            "timestamp": str(datetime.now()),
                            "product": app.API_MP.product,
                            "references_id": refs.message
                        }
                        out_list.append(info)
                    else:
                        self.logger.error("User {} not found".format(item.get("id")))
                        return MPAPIResponse(state=False, message="User {} not found".format(item.get("id")))
            console_clear_up(skip_line=True)
            if len(out_list) == 0:
                return MPAPIResponse(state=False, message="No user found")
            return MPAPIResponse(state=True, message=out_list)
        else:
            return MPAPIResponse(state=False, message="No user found")

    def privilege(self, pattern=None, lst=None, dct=None) -> MPAPIResponse:
        """
        Get user or users privileges
        :param pattern: string
        :param lst: user list
        :param dct: user dct
        """
        user_list = None
        # If pattern
        if pattern:
            user_list = self.get_by_pattern(pattern=pattern)
            if user_list:
                if len(user_list) > 1:
                    user_list = [func_select_list_item(user_list, namefield="userName")]
                    if user_list == [False] or user_list == [None]:
                        return MPAPIResponse(state=False, message="No user found")
                user_list = func_get_list_ids_from_list(user_list)
            else:
                return MPAPIResponse(state=False, message="No user found")
        # If lst
        if lst:
            user_list = func_get_list_ids_from_list(lst)
        if dct:
            user_list = [dct]
        if user_list:
            try:
                iface_user_role = iface_MP_UserRole()
            except KeyboardInterrupt:
                return MPAPIResponse(state=False, message="Operation interrupted")
            except BaseException as err:
                self.logger.error("MP user role API init failed: {}".format(err))
                return MPAPIResponse(state=False, message="MP user role API init failed: {}".format(err))
            out_list = []
            if len(user_list) > 5:
                rich_print("[yellow]It can get some time")
            with Progress() as progress:
                task = progress.add_task("Getting user privileges information...", total=len(user_list))
                for item in user_list:
                    progress.update(task, advance=1)
                    info = self.__get_info(item)
                    if not info.state and info.message == "Operation interrupted":
                        return MPAPIResponse(state=False, message="Operation interrupted")
                    if info.state:
                        info = info.message
                        privileges = []
                        for role in info.get("roles"):
                            role_info = iface_user_role.privilege(pattern=role.get("roleId"))
                            if not role_info.state:
                                return role_info
                            privileges += role_info.message
                        result_item = {
                            "id": info.get("id"),
                            "userName": info.get("userName"),
                            "fullName": "{} {} {}".format(info.get("lastName"), info.get("firstName"),
                                                          info.get("middleName")),
                            "privileges": privileges
                        }
                        out_list.append(result_item)
            console_clear_up(skip_line=True)
            if len(out_list) == 0:
                return MPAPIResponse(state=False, message="No user found")
            return MPAPIResponse(state=True, message=out_list)
        else:
            return MPAPIResponse(state=False, message="No user found")

    def create(self, source_spec: dict, disarm=True) -> MPAPIResponse:
        """
        Create user for MaxPatrol from spec
        :param source_spec: specification structure
        :param disarm: run in test mode
        """
        from app.mp.mp.iface_mp import ID_refs
        # Reload template list
        response = self.__load_list()
        if not response.state:
            EVENTS.push(status="Fail", action="Create", instance="User",
                        name=source_spec.get("userName"), instance_id=source_spec.get("id"),
                        details=response.message)
            return response
        self.list = response.message
        # Prepare specification
        print("Trying to create user: {}... ".format(source_spec.get("userName")))
        exist = self.get_by_name(source_spec.get("userName"))
        if exist:
            EVENTS.push(status="Fail", action="Create", instance="User",
                        name=source_spec.get("userName"), instance_id=source_spec.get("id"),
                        details="User {} exist. Can`t create".format(source_spec.get("userName")))
            return MPAPIResponse(state=False, message="User {} exist. Can`t create".format(source_spec.get("userName")))
        self.logger.debug("User {} not exist".format(source_spec.get("userName")))
        try:
            id_refs = ID_refs(["user_role", "site"])
        except KeyboardInterrupt:
            return MPAPIResponse(state=False, message="Operation interrupted")
        except BaseException as err:
            self.logger.error("Failed to initialize reference APIs: {}".format(err))
            return MPAPIResponse(state=False, message="Failed to initialize reference APIs: {}".format(err))
        out_spec = id_refs.replace(source_spec)
        if not out_spec.state:
            return out_spec
        out_spec = out_spec.message
        del out_spec["cli-mixin"]
        del out_spec["id"]
        out_spec["status"] = "blocked"
        out_spec["password"] = "Dummy_Pa55word"
        if not app.app.GLOBAL_DISARM and not disarm:
            self.logger.debug("Starting create process")

            response = app.API_MP.post(app.API_MP.url_user, out_spec)
            if not response.state:
                return response
            response = response.message.json()
            self.logger.debug("User {} successfully created".format(out_spec.get("userName")))
            return MPAPIResponse(state=True,
                                 message="User {} successfully created with ID: "
                                         "{}".format(out_spec.get("userName"), response))
        else:
            return MPAPIResponse(state=True, message="Success - disarmed")

    def log(self, pattern=None, lst=None, dct=None, time_from=None, limit=15) -> MPAPIResponse:
        """
        Get user log list
        :param pattern: string
        :param time_from: starting point
        :param limit: result limit
        :param lst: list of users
        :param dct: user
        """
        # Check actions list loaded
#        if not self.actions_list:
#            response = app.API_MP.post(app.API_MP.url_user_action_categories)
#            if not response.state:
#                return response
#            response = response.message.json()
#            self.actions_list = response.get("domains")
        user_list = None
        # If pattern
        if pattern:
            user_list = self.get_by_pattern(pattern=pattern)
            if user_list:
                if len(user_list) > 1:
                    user_list = [func_select_list_item(user_list, namefield="userName")]
                    if user_list == [False] or user_list == [None]:
                        return MPAPIResponse(state=False, message="No user found")
                user_list = func_get_list_ids_from_list(user_list)
            else:
                return MPAPIResponse(state=False, message="No user found")
        # If lst
        if lst:
            user_list = func_get_list_ids_from_list(lst)
        if dct:
            user_list = [dct]
        out_list = []
        # Getting full action log started for time
        if not time_from:
            time_from = datetime.now() - timedelta(hours=5)
            time_from = time_from.strftime('%Y-%m-%dT%H:%M:%SZ')
        response = app.API_MP.post(app.API_MP.url_user_action.format(limit), data={"timeFrom": str(time_from)})
        if not response.state:
            return response
        action_list = response.message.json()
        action_list = action_list.get("items")
        # Build list
        if user_list:
            for item in action_list:
                if item.get("userId") in user_list:
                    out_list.append(item)
        else:
            out_list = action_list
        if len(out_list) == 0:
            return MPAPIResponse(state=False, message="No logs found")
        return MPAPIResponse(state=True, message=out_list)

    def get_user_picker(self, prompt_string: str) -> MPAPIResponse:
        """
        Pick user dialog with autocompletion
        :param prompt_string: user prompt
        """
        user_names, user_ids = self.get_short_list()
        user_completer = WordCompleter(user_names, sentence=True)
        while True:
            try:
                user_input = prompt(prompt_string, completer=user_completer, complete_while_typing=True)
            except KeyboardInterrupt:
                return MPAPIResponse(state=False, message="Operation interrupted")
            if user_input == "":
                return MPAPIResponse(state=False, message="Skip user enter")
            if user_input == "?":
                print("Available users:")
                print(get_string_from_fmt(user_names, fmt="yaml"))
                continue
            if "*" in user_input:
                print("Available users:")
                for item in user_names:
                    if fnmatch_ext(item, user_input):
                        print("- {}".format(item))
                continue
            for idx in range(0, len(user_names)):
                if user_names[idx] == user_input:
                    return MPAPIResponse(state=True, message={"name": user_names[idx],
                                                              "id": user_ids[idx]})
            rich_print("[red]Wrong user")

    def get_short_list(self) -> [list, list]:
        """
        Get users short list - name and ID
        """
        names = []
        ids = []
        for item in self.list:
            names.append(item.get("userName"))
            ids.append(item.get("id"))
        return names, ids

    def get_by_login(self, name: str) -> dict | None:
        """
        Get user by login
        :param name: string
        """
        self.logger.debug("Trying to get user for login: {}".format(name))
        for user in self.list:
            if user.get("login") == name:
                return user
        self.logger.debug("No user found")
        return

    def get_by_name(self, name: str) -> dict | None:
        """
        Get user by name
        :param name: string
        """
        self.logger.debug("Trying to get user for name: {}".format(name))
        for user in self.list:
            if user.get("name") == name:
                return user
        self.logger.debug("No user found")
        return

    def get_by_id(self, user_id: str) -> dict | None:
        """
        Get user by ID
        :param user_id: string
        """
        self.logger.debug("Trying to get user for ID: {}".format(user_id))
        for report in self.list:
            if report.get("id") == user_id:
                return report
        self.logger.debug("No user found")
        return

    def get_by_pattern(self, pattern: str) -> list | None:
        """
        Get user by name, login or ID
        :param pattern: string name, login or ID
        """
        out_list = []
        # Trying to get by ID
        user = self.get_by_id(user_id=str(pattern))
        if user:
            return [user]
        # Trying to get by name
        for item in self.list:
            full_name_str = (str(item.get("lastName")) + " " + str(item.get("firstName")) + " " +
                             str(item.get("middleName")))
            if fnmatch_ext(full_name_str.lower(), str(pattern).lower()):
                out_list.append(item)
                continue
            if fnmatch_ext(item.get("userName", "None").lower(), str(pattern).lower()):
                out_list.append(item)
                continue
        if len(out_list) == 0:
            return
        else:
            return out_list

    def get_reference(self, spec: dict) -> MPAPIResponse:
        """
        Look instance for user IDs and return reference
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
                if struct == "00000000-0000-0000-0000-000000000000":
                    return [{"id": struct, "kind": "user", "user_login": "null"}]
                if re.match(id_pattern, struct) and struct != spec.get("id"):
                    user_info = self.get_by_id(user_id=struct)
                    if user_info:
                        return [{"id": struct, "kind": "user", "user_login": user_info.get("login")}]
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
        User info reducer
        """
        output = []
        if isinstance(data, list):
            for item in data:
                item_info = {
                    "id": item.get("id"),
                    "userName": item.get("userName"),
                    "status": item.get("status"),
                    "roles": [],
                    "personal": {
                        "firstName": item.get("firstName"),
                        "lastName": item.get("lastName"),
                        "middleName": item.get("middleName"),
                        "email": item.get("email"),
                        "phone": item.get("phone")
                    },
                    "organization": {
                        "manager": item.get("manager"),
                        "department": item.get("department")
                    }
                }
                for role in item.get("roles"):
                    item_info["roles"].append("{}: {}".format(role.get("applicationId"), role.get("roleName")))
                output.append(item_info)
        else:
            item_info = {
                "id": data.get("id"),
                "userName": data.get("userName"),
                "status": data.get("status"),
                "roles": [],
                "personal": {
                    "firstName": data.get("firstName"),
                    "lastName": data.get("lastName"),
                    "middleName": data.get("middleName"),
                    "email": data.get("email"),
                    "phone": data.get("phone")
                },
                "organization": {
                    "position": data.get("position"),
                    "manager": data.get("manager"),
                    "department": data.get("department")
                }
            }
            for role in data.get("roles"):
                item_info["roles"].append("{}: {}".format(role.get("applicationId"), role.get("roleName")))
            output = item_info
        return output

    @staticmethod
    def reduce_log(data: dict | list) -> dict | list:
        """
        User log reducer
        """
        if isinstance(data, list):
            output = []
            for item in data:
                output.append(
                    get_keys_from_dict(item, ["beginDateTime", "userLogin", "objectDomain", "objectType",
                                              "objectDisplayName", "applicationName", "code", "result"]))
        else:
            output = get_keys_from_dict(data, ["beginDateTime", "userLogin", "objectDomain", "objectType",
                                               "objectDisplayName", "applicationName", "code", "result"])
        return output

    @staticmethod
    def reduce_list(data: dict | list) -> dict | list:
        """
        User list reducer
        """
        if isinstance(data, list):
            output = []
            for item in data:
                output.append(
                    get_keys_from_dict(item, ["id", "userName", "status", "firstName", "lastName",
                                              "ldapSyncEnabled"]))
        else:
            output = get_keys_from_dict(data, ["id", "userName", "status", "firstName", "lastName",
                                               "ldapSyncEnabled"])
        return output

    def __get_info(self, user_id: str) -> MPAPIResponse:
        """
        Get user information
        :param user_id: string
        """
        self.logger.debug("Trying to load user info")
        response = app.API_MP.get(app.API_MP.url_user_instance.format(user_id))
        if not response.state:
            self.logger.error("User information load failed: {}".format(response.message))
            return response
        self.logger.debug("User information load succeeded")
        return MPAPIResponse(state=True, message=response.message.json())

    def __load_list(self) -> MPAPIResponse:
        """
        Load user list
        """
        self.logger.debug("Trying to load users")
        # Load templates list
        response = app.API_MP.get(app.API_MP.url_user)
        if not response.state:
            self.logger.error("User list load failed: {}".format(response.message))
            return response
        self.logger.debug("User list load succeeded")
        return MPAPIResponse(state=True, message=response.message.json().get("items"))
