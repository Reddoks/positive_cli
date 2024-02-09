import logging
import re

from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter
from rich.progress import Progress
from rich.prompt import Prompt
from rich import print as rich_print

import app
from app.app import EVENTS
from app.core.func import get_keys_from_dict, console_clear_up, get_string_from_fmt, fnmatch_ext
from app.mp.api import MPAPIResponse
from app.mp.func import (func_select_list_item,
                         func_apply_mixin)


class iface_MP_TaskCredential: # noqa
    def __init__(self, load=True):
        """
        Interface for task credentials
        :param load: if false - do not load credential list
        """
        self.logger = logging.getLogger("mp.task.iface_credential")
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

    def info(self, pattern=None, lst=None, dct=None) -> MPAPIResponse:
        """
        Get credential information
        :param pattern: string
        :param lst: credentials list
        :param dct: credentials dict
        :return: credential information list
        """
        credential_list = None
        # If pattern
        if pattern:
            credential_list = self.get_by_pattern(pattern=pattern)
            if credential_list:
                if len(credential_list) > 1:
                    credential_list = [func_select_list_item(credential_list)]
                    if credential_list == [False] or credential_list == [None]:
                        return MPAPIResponse(state=False, message="No credential found")
            else:
                return MPAPIResponse(state=False, message="No credential found")
        # If dict
        if dct:
            credential_list = [dct]
        # If lst
        if lst:
            credential_list = lst
        if credential_list:
            out_list = []
            if len(credential_list) > 5:
                rich_print("[yellow]It can get some time")
            with Progress() as progress:
                task = progress.add_task("Getting credential information...", total=len(credential_list))
                for item in credential_list:
                    progress.update(task, advance=1)
                    info = False
                    match item.get("type"):
                        case "LoginPassword":
                            info = self.__get_login_password_info(item.get("id"))
                        case "PasswordOnly":
                            info = self.__get_password_only_info(item.get("id"))
                        case "Certificate":
                            info = self.__get_certificate_info(item.get("id"))
                        case "LapsProvider":
                            info = self.__get_laps_info(item.get("id"))
                    if info:
                        out_list.append(info)
                    else:
                        return MPAPIResponse(state=False, message="No credential info found "
                                                                  "for {}".format(item.get("name")))
            console_clear_up(skip_line=True)
            if len(out_list) == 0:
                return MPAPIResponse(state=False, message="No credential info found")
            out_list = func_apply_mixin(out_list, "credential")
            return MPAPIResponse(state=True, message=out_list)
        else:
            return MPAPIResponse(state=False, message="No credential info found")

    def delete(self, data: str, disarm) -> MPAPIResponse:
        """
        Delete credential
        :param data: string credential ID
        :param disarm: run in test mode
        """
        self.logger.debug("Trying to delete credential {}".format(data))
        if not app.app.GLOBAL_DISARM and not disarm:
            response = app.API_MP.delete(app.API_MP.url_credential_instance.format(data), data)
        else:
            print("Success - disarmed")
            return MPAPIResponse(state=True, message="Success - disarmed")
        if not response.state:
            return response
        self.logger.debug("Credential {} successfully deleted".format(data))
        return MPAPIResponse(state=True, message="Credential {} successfully deleted".format(data))

    def create(self, raw_spec: dict, disarm) -> MPAPIResponse:
        """
        Create credential from specification
        :param raw_spec: specification structure
        :param disarm: run in test mode
        """
        self.logger.debug("Trying to create credential from specification")
        # Reload credential list
        response = self.__load_list()
        if not response.state:
            EVENTS.push(status="Fail", action="Create", instance="Credential",
                        name=raw_spec.get("name"), instance_id=raw_spec.get("id"),
                        details=response.message)
            return response
        self.list = response.message
        # Check profile exist
        exist = self.get_by_name(raw_spec.get("name"))
        if exist:
            EVENTS.push(status="Fail", action="Create", instance="Credential",
                        name=raw_spec.get("name"), instance_id=raw_spec.get("id"),
                        details="Credential {} exist. Can`t create".format(raw_spec.get("name")))
            return MPAPIResponse(state=False, message="Credential {} exist. Can`t create".format(raw_spec.get("name")))
        match raw_spec.get("type"):
            case "LoginPassword":
                spec = {
                    "name": raw_spec.get("name"),
                    "description": raw_spec.get("description")
                }
                if "credentialTags" in raw_spec:
                    spec["credentialTags"] = raw_spec.get("credentialTags")
                if "domain" in raw_spec:
                    spec["domain"] = raw_spec.get("domain")
                if "login" in raw_spec:
                    spec["login"] = raw_spec.get("login")
                spec["password"] = "dummypassword"
                response = self.create_login_password(spec, disarm)
            case "PasswordOnly":
                spec = {
                    "name": raw_spec.get("name"),
                    "description": raw_spec.get("description")
                }
                if "credentialTags" in raw_spec:
                    spec["credentialTags"] = raw_spec.get("credentialTags")
                spec["password"] = "dummypassword"
                response = self.create_password(spec, disarm)
            case "Certificate":
                spec = {
                    "name": raw_spec.get("name"),
                    "description": raw_spec.get("description")
                }
                if "credentialTags" in raw_spec:
                    spec["credentialTags"] = raw_spec.get("credentialTags")
                if "login" in raw_spec:
                    spec["login"] = raw_spec.get("login")
                if "password" in raw_spec:
                    spec["password"] = "dummypassword"
                try:
                    cert_path = Prompt.ask("Please enter certificate path for credential {} ".format(spec.get("name")))
                except KeyboardInterrupt:
                    EVENTS.push(status="Fail", action="Create", instance="Credential",
                                name=raw_spec.get("name"), instance_id=raw_spec.get("id"),
                                details="Operation interrupted")
                    return MPAPIResponse(state=False, message="Operation interrupted")
                if not cert_path:
                    EVENTS.push(status="Fail", action="Create", instance="Credential",
                                name=raw_spec.get("name"), instance_id=raw_spec.get("id"),
                                details="Certificate not provided. Skip creation")
                    return MPAPIResponse(state=False, message="Certificate not provided. Skip creation")
                else:
                    spec["certificate"] = cert_path
                response = self.create_certificate(spec, disarm)
            case "LapsProvider":
                spec = {
                    "name": raw_spec.get("name"),
                    "description": raw_spec.get("description")
                }
                if "credentialTags" in raw_spec:
                    spec["credentialTags"] = raw_spec.get("credentialTags")
                if "domain" in raw_spec:
                    spec["domain"] = raw_spec.get("domain")
                if "port" in raw_spec:
                    spec["port"] = raw_spec.get("port")
                if "searchBases" in raw_spec:
                    spec["searchBases"] = raw_spec.get("searchBases")
                if "targetLogin" in raw_spec:
                    spec["targetLogin"] = raw_spec.get("targetLogin")
                # Resolve AD Creds
                if "activeDirectoryCredentialsName" in raw_spec:
                    cred_id = self.get_by_name(raw_spec.get("activeDirectoryCredentialsName"))
                    if cred_id:
                        spec["activeDirectoryCredentialsId"] = cred_id.get("id")
                    else:
                        EVENTS.push(status="Fail", action="Create", instance="Credential",
                                    name=raw_spec.get("name"), instance_id=raw_spec.get("id"),
                                    details="Failed to resolve credential {}. "
                                            "Skip creation.".format(raw_spec.get("activeDirectoryCredentialsName")))
                        return MPAPIResponse(state=False,
                                             message="Failed to resolve credential {}. Skip "
                                                     "creation.".format(raw_spec.get("activeDirectoryCredentialsName")))
                response = self.create_laps(spec, disarm)
            case _:
                EVENTS.push(status="Fail", action="Create", instance="Credential", name=raw_spec.get("name"),
                            instance_id=raw_spec.get("id"),
                            details="Wrong credential type for {}".format(raw_spec.get("name")))
                return MPAPIResponse(state=False,
                                     message="Wrong credential type for {}".format(raw_spec.get("name")))
        if response.state:
            return MPAPIResponse(state=True, message="MaxPatrol credential "
                                                     "created: {}".format(response.message.json().get("id")))
        else:
            EVENTS.push(status="Fail", action="Create", instance="Credential", name=raw_spec.get("name"),
                        instance_id=raw_spec.get("id"), details=response.message)
            return response

    def create_login_password(self, spec: dict, disarm: bool) -> MPAPIResponse:
        """
        Create login-password credential
        :param spec: specification
        :param disarm: run in test mode
        """
        self.logger.debug("Trying to create login-password credential")
        process_data = spec
        # If mixin in data - clean
        if "cli-mixin" in process_data:
            del process_data["cli-mixin"]
        if not app.app.GLOBAL_DISARM and not disarm:
            response = app.API_MP.post(app.API_MP.url_credential_login, process_data)
        else:
            return MPAPIResponse(state=False, message="Success - disarmed")
        if not response.state:
            return response
        self.logger.debug("Credential {} successfully created".format(response.message.json().get("id")))
        return response

    def create_password(self, spec: dict, disarm: bool) -> MPAPIResponse:
        """
        Create password credential
        :param spec: specification
        :param disarm: run in test mode
        """
        self.logger.debug("Trying to create password credential")
        process_data = spec
        # If mixin in data - clean
        if "cli-mixin" in process_data:
            del process_data["cli-mixin"]
        if not app.app.GLOBAL_DISARM and not disarm:
            response = app.API_MP.post(app.API_MP.url_credential_password, process_data)
        else:
            return MPAPIResponse(state=False, message="Success - disarmed")
        if not response.state:
            return response
        self.logger.debug("Credential {} successfully created".format(response.message.json().get("id")))
        return response

    def create_certificate(self, spec: dict, disarm: bool) -> MPAPIResponse:
        """
        Create certificate credential
        :param spec: specification
        :param disarm: run in test mode
        """
        self.logger.debug("Trying to create certificate credential")
        process_data = spec
        # If mixin in data - clean
        if "cli-mixin" in process_data:
            del process_data["cli-mixin"]
        if not app.app.GLOBAL_DISARM and not disarm:
            response = app.API_MP.post(app.API_MP.url_credential_certificate, process_data)
        else:
            return MPAPIResponse(state=False, message="Success - disarmed")
        if not response.state:
            return response
        self.logger.debug("Credential {} successfully created".format(response.message.json().get("id")))
        return response

    def create_laps(self, spec: dict, disarm: bool) -> MPAPIResponse:
        """
        Create LAPS credential
        :param spec: specification
        :param disarm: run in test mode
        """
        self.logger.debug("Trying to create laps credential")
        process_data = spec
        # If mixin in data - clean
        if "cli-mixin" in process_data:
            del process_data["cli-mixin"]
        if not app.app.GLOBAL_DISARM and not disarm:
            response = app.API_MP.post(app.API_MP.url_credential_laps, process_data)
        else:
            return MPAPIResponse(state=False, message="Success - disarmed")
        if not response.state:
            return response
        self.logger.debug("Credential {} successfully created".format(response.message.json().get("id")))
        return response

    def get_credential_picker(self, prompt_string: str) -> MPAPIResponse:
        """
        Credential selection dialog with autocompletion
        :param prompt_string: prompt for dialog
        :return: credential item
        """
        creds_names, creds_ids = self.get_short_list()
        creds_completer = WordCompleter(creds_names, sentence=True)
        while True:
            try:
                creds_input = prompt(prompt_string, completer=creds_completer, complete_while_typing=True)
            except KeyboardInterrupt:
                return MPAPIResponse(state=False, message="Operation interrupted")
            if creds_input == "":
                return MPAPIResponse(state=False, message="Skip credential enter")
            if creds_input == "?":
                print("Available credentials:")
                print(get_string_from_fmt(creds_names, fmt="yaml"))
                continue
            if "*" in creds_input:
                print("Available credentials:")
                for item in creds_names:
                    if fnmatch_ext(item, creds_input):
                        print("- {}".format(item))
                continue
            for idx in range(0, len(creds_names)):
                if creds_names[idx] == creds_input:
                    return MPAPIResponse(state=True, message={"name": creds_names[idx],
                                                              "id": creds_ids[idx]})
            print("Wrong credential")

    def get_by_name(self, name: str) -> dict | None:
        """
        Get credential by name
        :param name: string
        :return: credential item
        """
        self.logger.debug("Trying to get credential for name: {}".format(name))
        for credential in self.list:
            if credential["name"] == name:
                return credential
        self.logger.debug("No credential found")
        return

    def get_by_id(self, cred_id: str) -> dict | None:
        """
        Get credential by ID
        :param cred_id: string
        :return: credential item
        """
        self.logger.debug("Trying to get credential for ID: {}".format(cred_id))
        for credential in self.list:
            if credential["id"] == cred_id:
                return credential
        self.logger.debug("No credential found")
        return

    def get_by_pattern(self, pattern: str) -> list | None:
        """
        Get credential by name or ID
        :param pattern: string name or ID
        """
        out_list = []
        # Trying to get by ID
        credential = self.get_by_id(cred_id=str(pattern))
        if credential:
            return [credential]
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
        Get creds short lists
        :return: names list, ids list
        """
        names = []
        ids = []
        for item in self.list:
            names.append(item.get("name"))
            ids.append(item.get("id"))
        return names, ids

    def get_reference(self, spec: dict) -> MPAPIResponse:
        """
        Look instance for credentials IDs and return reference
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
                    cred = self.get_by_id(cred_id=struct)
                    if cred:
                        return [{"id": struct, "kind": "credential", "name": cred.get("name")}]
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
                                       ["type", "id", "name", "description"]))
        else:
            output = get_keys_from_dict(data,
                                        ["type", "id", "name", "description"])
        return output

    @staticmethod
    def reduce_list(data: dict | list) -> dict | list:
        """
        Credential list reducer
        """
        if isinstance(data, list):
            output = []
            for item in data:
                output.append(
                    get_keys_from_dict(item, ["type", "name", "id", "description", "credentialTags", "laps"]))
        else:
            output = get_keys_from_dict(data, ["type", "name", "id", "description", "credentialTags", "laps"])
        return output

    def __get_login_password_info(self, cred_id: str) -> MPAPIResponse:
        """
        Get information for login-password credential
        :param cred_id: string ID
        """
        self.logger.debug("Trying to load login-password credential info")
        response = app.API_MP.get(app.API_MP.url_credential_login.format(cred_id))
        if not response.state:
            self.logger.error("Login-password credential "
                              "information load failed: {}".format(response.message))
            return response
        self.logger.debug("'Login-password credential information load succeeded")
        return response.message.json()

    def __get_password_only_info(self, cred_id: str) -> MPAPIResponse:
        """
        Get information for password credential
        :param cred_id: string ID
        """
        self.logger.debug("Trying to load password only credential info")
        response = app.API_MP.get(app.API_MP.url_credential_password.format(cred_id))
        if not response.state:
            self.logger.error("'Password only credential "
                              "information load failed: {}".format(response.message))
            return response
        self.logger.debug("Password only credential information load succeeded")
        return response.message.json()

    def __get_certificate_info(self, cred_id: str) -> MPAPIResponse:
        """
        Get information for certificate credential
        :param cred_id: string ID
        """
        self.logger.debug("Trying to load certificate credential info")
        response = app.API_MP.get(app.API_MP.url_credential_certificate.format(cred_id))
        if not response.state:
            self.logger.error("'Certificate credential "
                              "information load failed: {}".format(response.message))
            return response
        self.logger.debug("Certificate credential information load succeeded")
        return response.message.json()

    def __get_laps_info(self, cred_id: str) -> MPAPIResponse:
        """
        Get information for LAPS credential
        :param cred_id: string ID
        """
        self.logger.debug("Trying to load laps info")
        response = app.API_MP.get(app.API_MP.url_credential_laps.format(cred_id))
        if not response.state:
            self.logger.error("'LAPS credential information "
                              "load failed: {}".format(response.message))
            return response
        self.logger.debug("LAPS credential information load succeeded")
        laps_info = response.message.json()
        # Resolve AD creds
        ad_cred = self.get_by_id(laps_info["activeDirectoryCredentialsId"])
        if ad_cred:
            laps_info["activeDirectoryCredentialsName"] = ad_cred.get("name")
        else:
            MPAPIResponse(state=False, message="Unable to find credential "
                                               "{}".format(laps_info.get("activeDirectoryCredentialsId")))
        return laps_info

    def __load_list(self) -> MPAPIResponse:
        """
        Load credentials list
        """
        self.logger.debug("Trying to load scanning credentials")
        response = app.API_MP.get(app.API_MP.url_credential)
        if not response.state:
            self.logger.error("Scanning credentials load failed: {}".format(response.message))
            return response
        self.logger.debug("Scanning credentials load succeeded")
        return MPAPIResponse(state=True, message=response.message.json())
