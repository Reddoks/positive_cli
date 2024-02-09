import copy
import logging
import re

from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter
from rich.progress import Progress
from rich import print as rich_print

import app
from app.app import EVENTS
from app.core.func import console_clear_up, fnmatch_ext, get_string_from_fmt
from app.mp.api import MPAPIResponse
from app.mp.func import (func_select_list_item, func_apply_mixin)


class iface_MP_UserRole:  # noqa
    def __init__(self, load=True):
        """
        Interface for users roles
        :param load: if false - do not load user roles list
        """
        self.logger = logging.getLogger("mp.iface_user_role")
        if load:
            response = self.__load_list()
            if not response.state:
                if response.message == "Operation interrupted":
                    raise KeyboardInterrupt()
                else:
                    raise Exception(response.message)
            self.list = response.message
            response = self.__load_privileges_list()
            if not response.state:
                if response.message == "Operation interrupted":
                    raise KeyboardInterrupt()
                else:
                    raise Exception(response.message)
            self.privileges_list = response.message
        else:
            self.privileges_list = []

    def privilege(self, pattern=None, lst=None, dct=None) -> MPAPIResponse:
        """
        Get user role privilege
        :param pattern: string
        :param lst: role list
        :param dct: role dct
        """
        roles_list = None
        # If pattern
        if pattern:
            roles_list = self.get_by_pattern(pattern=pattern)
            if roles_list:
                if len(roles_list) > 1:
                    # REFINE
                    roles_list = [func_select_list_item(roles_list)]
                    if roles_list == [False] or roles_list == [None]:
                        return MPAPIResponse(state=False, message="No roles found")
            else:
                return MPAPIResponse(state=False, message="No roles found")
        # If lst
        if lst:
            roles_list = lst
        if dct:
            roles_list = [dct]
        if roles_list:
            out_list = []
            for item in roles_list:
                privileges = []
                for pv in item.get("privileges"):
                    for itm in self.privileges_list:
                        if pv == itm.get("code"):
                            privileges.append(itm.get("privilege"))
                privileges.sort()
                out_list.append({
                    "id": item.get("id"),
                    "application": item.get("application"),
                    "name": item.get("name"),
                    "privileges": privileges
                })
        else:
            return MPAPIResponse(state=False, message="No roles found")
        return MPAPIResponse(state=True, message=out_list)

    def create(self, source_spec: dict, disarm=True) -> MPAPIResponse:
        """
        Create user role for MaxPatrol from spec
        :param source_spec: specification structure
        :param disarm: run in test mode
        """
        # Reload roles list
        response = self.__load_list(with_progress=False)
        if not response.state:
            EVENTS.push(status="Fail", action="Create", instance="User ROle",
                        name=source_spec.get("name"), instance_id=source_spec.get("id"),
                        details=response.message)
            return response
        self.list = response.message
        # Prepare specification
        print("Trying to create user role {}:{}... ".format(source_spec.get("application"),
                                                            source_spec.get("name")))
        exist = self.get_by_name(application=source_spec.get("application"), name=source_spec.get("name"))
        if exist:
            EVENTS.push(status="Fail", action="Create", instance="User Role",
                        name=source_spec.get("name"), instance_id=source_spec.get("id"),
                        details="User role {} exist for app {}. Can`t create".format(source_spec.get("name"),
                                                                                     source_spec.get("application")))
            return MPAPIResponse(state=False,
                                 message="User role {} exist for app {}. "
                                         "Can`t create".format(source_spec.get("name"), source_spec.get("application")))
        self.logger.debug("User role {} not exist for app {}".format(source_spec.get("name"),
                                                                     source_spec.get("application")))
        out_spec = copy.deepcopy(source_spec)
        del out_spec["cli-mixin"]
        del out_spec["id"]
        del out_spec["type"]
        del out_spec["application"]
        if not app.app.GLOBAL_DISARM and not disarm:
            self.logger.debug("Starting create process")
            match source_spec.get("application"):
                case "mpx":
                    response = app.API_MP.post(app.API_MP.url_user_roles_mpx, out_spec)
                case "idmgr":
                    response = app.API_MP.post(app.API_MP.url_user_roles_idmgr, out_spec)
                case "ptkb":
                    response = app.API_MP.post(app.API_MP.url_user_roles_ptkb, out_spec)
                case _:
                    EVENTS.push(status="Fail", action="Create", instance="User Role",
                                name=source_spec.get("name"), instance_id=source_spec.get("id"),
                                details="Wrong application: {}".format(source_spec.get("application")))
                    self.logger.error("Wrong application: {}".format(source_spec.get("application")))
                    return MPAPIResponse(state=False,
                                         message="Wrong application: {}".format(source_spec.get("application")))
            if not response.state:
                return response
            response = response.message.json()
            self.logger.debug("User role {} successfully created for app {}".format(out_spec.get("name"),
                                                                                    source_spec.get("application")))
            return MPAPIResponse(state=True,
                                 message="User role {} successfully created with ID: "
                                         "{}".format(out_spec.get("name"), response))
        else:
            return MPAPIResponse(state=True, message="Success - disarmed")

    def delete(self, role_id: str, disarm=True) -> MPAPIResponse:
        """
        Delete user role
        :param role_id: string
        :param disarm: run in test mode
        """
        self.logger.debug("Trying to delete user role {}".format(role_id))
        role = self.get_by_id(role_id)
        if not app.app.GLOBAL_DISARM and not disarm:
            match role.get("application"):
                case "mpx":
                    response = app.API_MP.delete(app.API_MP.url_user_roles_mpx_delete, [role_id])
                case "idmgr":
                    response = app.API_MP.delete(app.API_MP.url_user_roles_idmgr_delete, [role_id])
                case "ptkb":
                    response = app.API_MP.delete(app.API_MP.url_user_roles_ptkb_delete, [role_id])
                case _:
                    EVENTS.push(status="Fail", action="Delete", instance="User Role",
                                name=role.get("name"), instance_id=role.get("id"),
                                details="Wrong application: {}".format(role.get("application")))
                    self.logger.error("Wrong application: {}".format(role.get("application")))
                    return MPAPIResponse(state=False,
                                         message="Wrong application: {}".format(role.get("application")))
        else:
            print("Success - disarmed")
            return MPAPIResponse(state=True, message="Success - disarmed")
        if not response.state:
            return response
        self.logger.debug("User role {} successfully deleted".format(role_id))
        return MPAPIResponse(state=True, message="User role {} successfully deleted".format(role_id))

    def get_user_role_picker(self, prompt_string: str) -> MPAPIResponse:
        """
        Pick user role dialog with autocompletion
        :param prompt_string: user prompt
        """
        role_names, role_ids = self.get_short_list()
        role_completer = WordCompleter(role_names, sentence=True)
        while True:
            try:
                role_input = prompt(prompt_string, completer=role_completer, complete_while_typing=True)
            except KeyboardInterrupt:
                return MPAPIResponse(state=False, message="Operation interrupted")
            if role_input == "":
                return MPAPIResponse(state=False, message="Skip role enter")
            if role_input == "?":
                print("Available roles:")
                print(get_string_from_fmt(role_names, fmt="yaml"))
                continue
            if "*" in role_input:
                print("Available roles:")
                for item in role_names:
                    if fnmatch_ext(item, role_input):
                        print("- {}".format(item))
                continue
            for idx in range(0, len(role_names)):
                if role_names[idx] == role_input:
                    return MPAPIResponse(state=True, message={"name": role_names[idx],
                                                              "id": role_ids[idx]})
            rich_print("[red]Wrong role")

    def get_short_list(self) -> [list, list]:
        """
        Get user roles short list - name and ID
        """
        names = []
        ids = []
        for item in self.list:
            names.append("{}:{}".format(item.get("application"), item.get("name")))
            ids.append(item.get("id"))
        return names, ids

    def get_app_roles(self, application: str) -> list:
        """
        Get user roles for specific application
        :param application: string
        """
        output = []
        for item in self.list:
            if item.get("application") == application:
                output.append(item)
        return output

    def get_by_name(self, application: str, name: str) -> dict | None:
        """
        Get user role by name
        :param application APP
        :param name: string
        """
        self.logger.debug("Trying to get user role for name: {}".format(name))
        role_list = self.get_app_roles(application)
        for role in role_list:
            if role.get("name") == name:
                return role
        self.logger.debug("No roles found")
        return

    def get_by_id(self, role_id: str) -> dict | None:
        """
        Get user role by ID
        :param role_id: string
        """
        self.logger.debug("Trying to get user role for ID: {}".format(role_id))
        for role in self.list:
            if role.get("id") == role_id:
                return role
        self.logger.debug("No roles found")
        return

    def get_by_pattern(self, pattern: str) -> list | None:
        """
        Get user role by name or ID
        :param pattern: string name or ID
        """
        out_list = []
        # Trying to get by ID
        role = self.get_by_id(role_id=str(pattern))
        if role:
            return [role]
        # Trying to get by name
        for item in self.list:
            if fnmatch_ext(item.get("name").lower(), str(pattern).lower()):
                out_list.append(item)
                continue
        if len(out_list) == 0:
            return
        else:
            return out_list

    def get_reference(self, spec: dict) -> MPAPIResponse:
        """
        Look instance for user role IDs and return reference
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
                    return [{"id": struct, "kind": "ignore"}]
                if re.match(id_pattern, struct) and struct != spec.get("id"):
                    role_info = self.get_by_id(role_id=struct)
                    if role_info:
                        return [{"id": struct, "kind": "user_role", "application": role_info.get("application"),
                                 "name": role_info.get("name")}]
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
                    "manager": data.get("manager"),
                    "department": data.get("department")
                }
            }
            for role in data.get("roles"):
                item_info["roles"].append("{}: {}".format(role.get("applicationId"), role.get("roleName")))
            output = item_info
        return output

    @staticmethod
    def reduce_list(data: dict | list) -> dict | list:
        """
        User list reducer
        """
        if isinstance(data, list):
            output = []
            for item in data:
                role = {
                    "id": item.get("id"),
                    "name": item.get("name"),
                    "description": item.get("description"),
                    "application": item.get("application"),
                    "type": item.get("type"),
                    "privilege": len(item.get("privileges"))
                }
                output.append(role)
        else:
            output = {
                "id": data.get("id"),
                "name": data.get("name"),
                "description": data.get("description"),
                "application": data.get("application"),
                "type": data.get("type"),
                "privilege": len(data.get("privileges"))
            }
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

    def __load_privileges_list(self) -> MPAPIResponse:
        """
        Load privileges list
        """

        def extract_privileges(privileges: list, application: str) -> list:
            """
            Extract privilege from source data
            :param privileges: source data
            :param application: application tag
            """
            out_privileges = []
            for pr in privileges:
                if len(pr.get("groups")):
                    nested = extract_privileges(privileges=pr.get("groups"), application=application)
                    for nsd_item in nested:
                        out_privileges.append({
                            "privilege": "{}->{}".format(pr.get("name"), nsd_item.get("privilege")),
                            "application": nsd_item.get("application"),
                            "code": nsd_item.get("code")
                        })
                for pr_piv in pr.get("privileges"):
                    out_privileges.append({
                        "privilege": "{}->{}".format(pr.get("name"), pr_piv.get("name")),
                        "application": application,
                        "code": pr_piv.get("code")
                    })
            return out_privileges

        self.logger.debug("Trying to load privilege list")
        # Get MPX privilege
        response = app.API_MP.get(app.API_MP.url_user_privileges_mpx)
        if not response.state:
            self.logger.error("User mpx privilege list load failed: {}".format(response.message))
            return response
        mpx_privileges = response.message.json()
        mpx_privileges = extract_privileges(privileges=mpx_privileges, application="mpx")
        # Get IDMGR privilege
        response = app.API_MP.get(app.API_MP.url_user_privileges_idmgr)
        if not response.state:
            self.logger.error("User idmgr privilege list load failed: {}".format(response.message))
            return response
        idmgr_privileges = response.message.json()
        idmgr_privileges = extract_privileges(privileges=idmgr_privileges, application="idmgr")
        # Get PTKB privilege
        response = app.API_MP.get(app.API_MP.url_user_privileges_ptkb)
        if not response.state:
            self.logger.error("User ptkb privilege list load failed: {}".format(response.message))
            return response
        ptkb_privileges = response.message.json()
        ptkb_privileges = extract_privileges(privileges=ptkb_privileges, application="ptkb")
        output = mpx_privileges + idmgr_privileges + ptkb_privileges
        self.logger.debug("Privileges list load succeeded")
        return MPAPIResponse(state=True, message=output)

    def __load_list(self, with_progress=True) -> MPAPIResponse:
        """
        Load user roles list
        """
        self.logger.debug("Trying to load user roles")
        if with_progress:
            with Progress() as progress:
                task = progress.add_task("Getting user roles information...", total=3)
                # Get MPX roles
                response = app.API_MP.get(app.API_MP.url_user_roles_mpx)
                if not response.state:
                    self.logger.error("User mpx roles list load failed: {}".format(response.message))
                    return response
                mpx_roles = response.message.json()
                for item in mpx_roles:
                    item["application"] = "mpx"
                progress.update(task, advance=1)
                # Get IDMGR roles
                response = app.API_MP.get(app.API_MP.url_user_roles_idmgr)
                if not response.state:
                    self.logger.error("User idmgr roles list load failed: {}".format(response.message))
                    return response
                idmgr_roles = response.message.json()
                for item in idmgr_roles:
                    item["application"] = "idmgr"
                progress.update(task, advance=1)
                # Get PTKB roles
                response = app.API_MP.get(app.API_MP.url_user_roles_ptkb)
                if not response.state:
                    self.logger.error("User ptkb roles list load failed: {}".format(response.message))
                    return response
                ptkb_roles = response.message.json()
                for item in ptkb_roles:
                    item["application"] = "ptkb"
                progress.update(task, advance=1)
            console_clear_up(skip_line=True)
        else:
            # Get MPX roles
            response = app.API_MP.get(app.API_MP.url_user_roles_mpx)
            if not response.state:
                self.logger.error("User mpx roles list load failed: {}".format(response.message))
                return response
            mpx_roles = response.message.json()
            for item in mpx_roles:
                item["application"] = "mpx"
            # Get IDMGR roles
            response = app.API_MP.get(app.API_MP.url_user_roles_idmgr)
            if not response.state:
                self.logger.error("User idmgr roles list load failed: {}".format(response.message))
                return response
            idmgr_roles = response.message.json()
            for item in idmgr_roles:
                item["application"] = "idmgr"
            # Get PTKB roles
            response = app.API_MP.get(app.API_MP.url_user_roles_ptkb)
            if not response.state:
                self.logger.error("User ptkb roles list load failed: {}".format(response.message))
                return response
            ptkb_roles = response.message.json()
            for item in ptkb_roles:
                item["application"] = "ptkb"
        output = mpx_roles + idmgr_roles + ptkb_roles
        output = func_apply_mixin(output, "user_role")
        self.logger.debug("User roles list load succeeded")
        return MPAPIResponse(state=True, message=output)
