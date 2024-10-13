import logging
import re

import app
from app.mp.api import MPAPIResponse
from app.mp.asset.iface_asset_group import iface_MP_Group
from app.mp.user.iface_user import iface_MP_User
from app.mp.asset.iface_asset_query import iface_MP_AssetQuery
from app.mp.asset.iface_asset_scope import iface_MP_Scope
from app.mp.policy.iface_policy import iface_MP_Policy
from app.mp.task.iface_task_credential import iface_MP_TaskCredential
from app.mp.task.iface_task_profile import iface_MP_TaskProfile
from app.mp.task.iface_task_dictionary import iface_MP_TaskDictionary
from app.mp.aec.iface_aec import iface_MP_AEC
from app.mp.user.iface_user_roles import iface_MP_UserRole
from app.mp.site.iface_site import iface_MP_Site
from app.mp.event.iface_event_filter import iface_MP_EventFilter

from rich import print as rich_print
from rich.prompt import Prompt
from app.app import EVENTS


class ID_refs:  # noqa
    def __init__(self, types: list):
        """
        Get ID reference values for specification mixin
        :param types: list of types
        """
        self.logger = logging.getLogger("mp.id_refs")
        self.reference = None
        self.types = types
        try:
            if "group" in types:
                self.iface_group = iface_MP_Group()
            if "user" in types:
                self.iface_user = iface_MP_User()
            if "user_role" in types:
                self.iface_user_role = iface_MP_UserRole()
            if "query" in types:
                self.iface_query = iface_MP_AssetQuery()
            if "scope" in types:
                self.iface_scope = iface_MP_Scope()
            if "policy" in types:
                self.iface_policy = iface_MP_Policy()
            if "credential" in types:
                self.iface_credential = iface_MP_TaskCredential()
            if "profile" in types:
                self.iface_profile = iface_MP_TaskProfile()
            if "dictionary" in types:
                self.iface_dictionary = iface_MP_TaskDictionary()
            if "aec" in types:
                self.iface_aec = iface_MP_AEC()
            if "site" in types:
                self.iface_site = iface_MP_Site()
            if "event_filter" in types:
                if "SIEM" in app.MP_APPS:
                    self.iface_event_filter = iface_MP_EventFilter()
        except KeyboardInterrupt:
            raise KeyboardInterrupt()
        except BaseException as err:
            self.logger.error("Failed to initialize APIs for references build: {}".format(err))
            raise Exception()

    def get_resolved_id(self, source_id: str) -> MPAPIResponse:
        if not self.reference:
            return MPAPIResponse(state=False, message="Failed to get ID {}: IDs not resolved".format(source_id))
        self.logger.debug("Getting resolved ID for: {}".format(source_id))
        for item in self.reference:
            if item.get("id") == source_id:
                self.logger.debug("Resolved ID found: {}".format(item.get("resolved_id")))
                return MPAPIResponse(state=True, message=item.get("resolved_id"))
        return MPAPIResponse(state=False, message="Failed to get ID {}: Not found".format(source_id))

    def replace(self, spec, drop_aec=False) -> MPAPIResponse:
        """
        Check IDs in specification and replace it according to reference
        :param spec: specification structure
        :param drop_aec: set AECs to null
        """

        def lookup_in_key(struct: any) -> MPAPIResponse:
            if isinstance(struct, list):
                for index, item in enumerate(struct):
                    result_lst = lookup_in_key(struct=item)
                    if not result_lst.state:
                        return result_lst
                    struct[index] = result_lst.message
                return MPAPIResponse(state=True, message=struct)
            if isinstance(struct, dict):
                for ky, vue in struct.items():
                    result_dct = lookup_in_key(struct=vue)
                    if not result_dct.state:
                        return result_dct
                    struct[ky] = result_dct.message
                return MPAPIResponse(state=True, message=struct)
            if isinstance(struct, str):
                id_pattern1 = re.compile("[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+")
                id_pattern2 = re.compile("([a-z0-9]+(-[a-z0-9]+)+)_root")
                id_pattern3 = re.compile("[a-z0-9]+")
                if re.match(id_pattern3, struct) and len(struct) == 32 and struct != spec.get("id"):
                    # Check is not FQDN
                    if "." not in struct:
                        resolved = self.get_resolved_id(source_id=struct)
                        if not resolved.state:
                            return resolved
                        return MPAPIResponse(state=True, message=resolved.message)
                if re.match(id_pattern2, struct) and len(struct) == 41 and struct != spec.get("id"):
                    resolved = self.get_resolved_id(source_id=struct)
                    if not resolved.state:
                        return resolved
                    return MPAPIResponse(state=True, message=resolved.message)
                if re.match(id_pattern1, struct) and len(struct) == 36 and struct != spec.get("id"):
                    resolved = self.get_resolved_id(source_id=struct)
                    if not resolved.state:
                        return resolved
                    return MPAPIResponse(state=True, message=resolved.message)
                else:
                    return MPAPIResponse(state=True, message=struct)
            return MPAPIResponse(state=True, message=struct)

        response = self.resolve(spec, drop_aec=drop_aec)
        if not response.state:
            return response
        for key, value in spec.items():
            if key == "cli-mixin":
                continue
            result = lookup_in_key(value)
            if not result.state:
                return result
            spec[key] = result.message
        return MPAPIResponse(state=True, message=spec)

    def resolve(self, spec, drop_aec=False) -> MPAPIResponse:
        """
        Resolve IDs in reference if needed
        :param spec: specification structure
        :param drop_aec: set AEC to null
        """
        if "cli-mixin" not in spec:
            self.logger.error("Wrong specification {}. Mixin is missing".format(spec.get("name")))
            return MPAPIResponse(state=False,
                                 message="Wrong specification {}. Mixin is missing".format(spec.get("name")))
        if not spec["cli-mixin"].get("references_id"):
            self.logger.error("Wrong specification {}. References is missing".format(spec.get("name")))
            return MPAPIResponse(state=False,
                                 message="Wrong specification {}. References is missing".format(spec.get("name")))
        reference = spec["cli-mixin"].get("references_id")
        for item in reference:
            if item.get("kind") == "group" and "group" in self.types:
                resolved = self.__resolve_group(source_id=item.get("id"), source_hierarchy=item.get("hierarchy"))
                if not resolved.state:
                    return resolved
                item["resolved_id"] = resolved.message
                # Resolve user
            if item.get("kind") == "user" and "user" in self.types:
                resolved = self.__resolve_user(source_id=item.get("id"), source_user_login=item.get("user_login"),
                                               source_user_name=item.get("user_userName"))
                if not resolved.state:
                    return resolved
                item["resolved_id"] = resolved.message
            if item.get("kind") == "user_role" and "user_role" in self.types:
                resolved = self.__resolve_user_role(source_id=item.get("id"),
                                                    source_application=item.get("application"),
                                                    source_name=item.get("name"))
                if not resolved.state:
                    return resolved
                item["resolved_id"] = resolved.message
            if item.get("kind") == "query" and "query" in self.types:
                resolved = self.__resolve_query(source_id=item.get("id"), source_hierarchy=item.get("hierarchy"))
                if not resolved.state:
                    return resolved
                item["resolved_id"] = resolved.message
            if item.get("kind") == "event_filter" and "event_filter" in self.types:
                if "SIEM" not in app.MP_APPS:
                    EVENTS.push(status="Fail", action="Resolve", instance="Event filter",
                                name=item.get("name"), instance_id="N/A",
                                details="SIEM Role required")
                    return MPAPIResponse(state=False,
                                         message="Event filter {} not resolved. SIEM "
                                                 "required.".format(item.get("name")))
                resolved = self.__resolve_event_filter(source_id=item.get("id"), source_hierarchy=item.get("hierarchy"))
                if not resolved.state:
                    return resolved
                item["resolved_id"] = resolved.message
            if item.get("kind") == "site" and "site" in self.types:
                resolved = self.__resolve_site(source_id=item.get("id"), source_hierarchy=item.get("hierarchy"))
                if not resolved.state:
                    return resolved
                item["resolved_id"] = resolved.message
            if item.get("kind") == "scope" and "scope" in self.types:
                resolved = self.__resolve_scope(source_id=item.get("id"), source_name=item.get("name"))
                if not resolved.state:
                    return resolved
                item["resolved_id"] = resolved.message
            if item.get("kind") == "policy_rule" and "policy_rule" in self.types:
                resolved = self.__resolve_policy(source_id=item.get("id"),
                                                 source_name=item.get("name"),
                                                 source_policy=item.get("policy_id"))
                if not resolved.state:
                    return resolved
                item["resolved_id"] = resolved.message
            if item.get("kind") == "credential" and "credential" in self.types:
                resolved = self.__resolve_credential(source_id=item.get("id"), source_name=item.get("name"))
                if not resolved.state:
                    return resolved
                item["resolved_id"] = resolved.message
            if item.get("kind") == "profile" and "profile" in self.types:
                resolved = self.__resolve_profile(source_id=item.get("id"), source_name=item.get("name"))
                if not resolved.state:
                    return resolved
                item["resolved_id"] = resolved.message
            if item.get("kind") == "dictionary" and "dictionary" in self.types:
                resolved = self.__resolve_dictionary(source_id=item.get("id"), source_name=item.get("name"))
                if not resolved.state:
                    return resolved
                item["resolved_id"] = resolved.message
            if item.get("kind") == "aec" and "aec" in self.types:
                if not drop_aec:
                    resolved = self.__resolve_aec(source_id=item.get("id"), source_name=item.get("name"))
                    if not resolved.state:
                        return resolved
                    item["resolved_id"] = resolved.message
                else:
                    item["resolved_id"] = None
            if item.get("kind") == "ignore":
                item["resolved_id"] = item.get("id")
        self.reference = reference
        spec["cli-mixin"]["references_id"] = reference
        return MPAPIResponse(state=True, message=spec)

    def get_references(self, spec) -> MPAPIResponse:
        """
        Build IDs reference list
        :param spec: specification structure
        """
        references = []
        for t in self.types:
            match t:
                case "group":
                    refs = self.iface_group.get_reference(spec)
                    if not refs.state:
                        return MPAPIResponse(state=False,
                                             message="Failed to build groups reference: {}".format(refs.message))
                    references += refs.message
                case "user":
                    refs = self.iface_user.get_reference(spec)
                    if not refs.state:
                        return MPAPIResponse(state=False,
                                             message="Failed to build user reference: {}".format(refs.message))
                    references += refs.message
                case "user_role":
                    refs = self.iface_user_role.get_reference(spec)
                    if not refs.state:
                        return MPAPIResponse(state=False,
                                             message="Failed to build user role reference: {}".format(refs.message))
                    references += refs.message
                case "query":
                    refs = self.iface_query.get_reference(spec)
                    if not refs.state:
                        return MPAPIResponse(state=False,
                                             message="Failed to build asset query reference: {}".format(refs.message))
                    references += refs.message
                case "event_filter":
                    if "SIEM" in app.MP_APPS:
                        refs = self.iface_event_filter.get_reference(spec)
                        if not refs.state:
                            return MPAPIResponse(state=False,
                                                 message="Failed to build event filter "
                                                         "reference: {}".format(refs.message))
                        references += refs.message
                case "site":
                    refs = self.iface_site.get_reference(spec)
                    if not refs.state:
                        return MPAPIResponse(state=False,
                                             message="Failed to build site reference: {}".format(refs.message))
                    references += refs.message
                case "scope":
                    refs = self.iface_scope.get_reference(spec)
                    if not refs.state:
                        return MPAPIResponse(state=False,
                                             message="Failed to build scope reference: {}".format(refs.message))
                    references += refs.message
                case "policy":
                    refs = self.iface_policy.get_reference(spec)
                    if not refs.state:
                        return MPAPIResponse(state=False,
                                             message="Failed to build policy reference: {}".format(refs.message))
                    references += refs.message
                case "credential":
                    refs = self.iface_credential.get_reference(spec)
                    if not refs.state:
                        return MPAPIResponse(state=False,
                                             message="Failed to build credential reference: {}".format(refs.message))
                    references += refs.message
                case "profile":
                    refs = self.iface_profile.get_reference(spec)
                    if not refs.state:
                        return MPAPIResponse(state=False,
                                             message="Failed to build profile reference: {}".format(refs.message))
                    references += refs.message
                case "dictionary":
                    refs = self.iface_dictionary.get_reference(spec)
                    if not refs.state:
                        return MPAPIResponse(state=False,
                                             message="Failed to build dictionary reference: {}".format(refs.message))
                    references += refs.message
                case "aec":
                    refs = self.iface_aec.get_reference(spec)
                    if not refs.state:
                        return MPAPIResponse(state=False,
                                             message="Failed to build AEC reference: {}".format(refs.message))
                    references += refs.message
        # Build unknown instances list
        refs = self.__get_unknown_refs(spec, references)
        if not refs.state:
            return MPAPIResponse(state=False,
                                 message="Failed to build unknown instances reference: {}".format(refs.message))
        references += refs.message

        return MPAPIResponse(state=True, message=references)

    @staticmethod
    def __get_unknown_refs(spec: dict, refs: list) -> MPAPIResponse:
        """
        Look instances missing in references
        :param refs: refs list
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
                id_pattern1 = re.compile("[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+")
                id_pattern2 = re.compile("([A-Za-z0-9]+(-[A-Za-z0-9]+)+)_root")
                id_pattern3 = re.compile("[A-Za-z0-9]+")
                if (re.match(id_pattern1, struct) or re.match(id_pattern2, struct) or
                        (re.match(id_pattern3, struct) and len(struct) == 32)):
                    # Check is not FQDN
                    if "." not in struct:
                        is_present = False
                        for ref_itm in refs:
                            if ref_itm.get("id") == struct:
                                is_present = True
                        if not is_present:
                            return [{"id": struct, "kind": "unknown"}]
                        else:
                            return None
                return

        out_list = []
        for key, value in spec.items():
            inst = lookup_in_key(value)
            if inst:
                out_list += inst
        out_list = build_originals(out_list)
        return MPAPIResponse(state=True, message=out_list)

    def __resolve_user(self, source_id: str, source_user_login=None, source_user_name=None) -> MPAPIResponse:
        """
        Resolve source user reference
        :param source_id: ID string
        :param source_user_login: User login string
        """
        if source_id == "00000000-0000-0000-0000-000000000000":
            return MPAPIResponse(state=True, message="00000000-0000-0000-0000-000000000000")
        # Check is exist by ID
        exist = self.iface_user.get_by_id(source_id)
        if exist:
            self.logger.debug("User exists: {}({})".format(exist.get("userName"),
                                                           exist.get("id")))
            return MPAPIResponse(state=True, message=exist.get("id"))
        resolved = None
        # If login
        if source_user_login:
            resolved = self.iface_user.get_by_login(name=source_user_login)
        # Second chance
        if source_user_name:
            resolved = self.iface_user.get_by_username(name=source_user_name)
        if resolved:
            self.logger.debug("User resolved: {}({})".format(resolved.get("userName"),
                                                             resolved.get("id")))
            return MPAPIResponse(state=True, message=resolved.get("id"))
        rich_print("[red]Looks problem with resolution user: ", end="")
        if source_user_login:
            print(source_user_login)
        else:
            print(source_user_name)
        rich_print("[yellow]CLI can not find exist user in system according to specification reference")
        rich_print("[yellow]You can replace this user to another, but it can impact functionality")
        try:
            decision = Prompt.ask("Would you like replace this user? ", choices=["y", "n"], default="n")
        except KeyboardInterrupt:
            return MPAPIResponse(state=False, message="Operation interrupted")
        if decision == "y":
            user_info = self.iface_user.get_user_picker("User full name (? for list, wildcards usable): ")
            if not user_info.state:
                EVENTS.push(status="Fail", action="Resolve", instance="User",
                            name=source_user_login, instance_id="N/A",
                            details="User not resolved")
                return MPAPIResponse(state=False,
                                     message="User not {} resolved.".format(source_user_login))
            else:
                self.logger.debug(
                    "User resolved: {}({})".format(user_info.message.get("name"),
                                                   user_info.message.get("id")))
                return MPAPIResponse(state=True, message=user_info.message.get("id"))
        else:
            EVENTS.push(status="Fail", action="Resolve", instance="User",
                        name=source_user_login, instance_id="N/A",
                        details="User not resolved")
            return MPAPIResponse(state=False,
                                 message="User {} not resolved.".format(source_user_login))

    def __resolve_user_role(self, source_id: str, source_application: str, source_name: str) -> MPAPIResponse:
        """
        Resolve source user role reference
        :param source_id: ID string
        :param source_application: Role application string
        :param source_name: Role name
        """
        # Check is exist by ID
        exist = self.iface_user_role.get_by_id(source_id)
        if exist:
            self.logger.debug("User role exists: {}({})".format(exist.get("name"),
                                                                exist.get("id")))
            return MPAPIResponse(state=True, message=exist.get("id"))
        # Get application roles and look in
        roles = self.iface_user_role.get_app_roles(application=source_application)
        resolved = None
        for rle in roles:
            if rle.get("name") == source_name:
                resolved = rle
        if resolved:
            self.logger.debug("User role resolved: {}({})".format(resolved.get("name"),
                                                                  resolved.get("id")))
            return MPAPIResponse(state=True, message=resolved.get("id"))
        rich_print("[red]Looks problem with resolution user role: ", end="")
        print("{}: {}", source_application, source_name)
        rich_print("[yellow]CLI can not find exist user role in system according to specification reference")
        rich_print("[yellow]You can replace this user role to another, but it can impact functionality and security")
        try:
            decision = Prompt.ask("Would you like replace this user role? ", choices=["y", "n"], default="n")
        except KeyboardInterrupt:
            return MPAPIResponse(state=False, message="Operation interrupted")
        if decision == "y":
            role_info = self.iface_user_role.get_user_role_picker("Role app:name (? for list, wildcards usable): ")
            if not role_info.state:
                EVENTS.push(status="Fail", action="Resolve", instance="User Role",
                            name=source_name, instance_id="N/A",
                            details="User role not resolved")
                return MPAPIResponse(state=False,
                                     message="User role {} resolved.".format(source_name))
            else:
                self.logger.debug(
                    "User role resolved: {}({})".format(role_info.message.get("name"),
                                                        role_info.message.get("id")))
                return MPAPIResponse(state=True, message=role_info.message.get("id"))
        else:
            EVENTS.push(status="Fail", action="Resolve", instance="User Role",
                        name=source_name, instance_id="N/A",
                        details="User role not resolved for app {}".format(source_application))
            return MPAPIResponse(state=False,
                                 message="User role {} not resolved for app {}".format(source_name,
                                                                                       source_application))

    def __resolve_scope(self, source_id: str, source_name: str) -> MPAPIResponse:
        """
        Resolve source user reference
        :param source_id: ID string
        :param source_name: Name string
        """
        # Check is exist by ID
        exist = self.iface_scope.get_by_id(source_id)
        if exist:
            self.logger.debug("Scope exists: {}({})".format(exist.get("name"),
                                                            exist.get("id")))
            return MPAPIResponse(state=True, message=exist.get("id"))
        resolved = self.iface_scope.get_by_name(name=source_name)
        if resolved:
            self.logger.debug("Scope resolved: {}({})".format(resolved.get("name"),
                                                              resolved.get("id")))
            return MPAPIResponse(state=True, message=resolved.get("id"))
        rich_print("[red]Looks problem with resolution scope: ", end="")
        print(source_name)
        rich_print("[yellow]CLI can not find exist scope in system according to specification reference")
        rich_print("[yellow]You can replace this scope to another, but it can impact functionality")
        try:
            decision = Prompt.ask("Would you like replace this scope? ", choices=["y", "n"], default="n")
        except KeyboardInterrupt:
            return MPAPIResponse(state=False, message="Operation interrupted")
        if decision == "y":
            scope_info = self.iface_user.get_user_picker("Scope name (? for list, wildcards usable): ")
            if not scope_info.state:
                EVENTS.push(status="Fail", action="Resolve", instance="Scope",
                            name=source_name, instance_id="N/A",
                            details="Scope not resolved")
                return MPAPIResponse(state=False,
                                     message="Scope {} not resolved.".format(source_name))
            else:
                self.logger.debug(
                    "Scope resolved: {}({})".format(scope_info.message.get("name"),
                                                    scope_info.message.get("id")))
                return MPAPIResponse(state=True, message=scope_info.message.get("id"))
        else:
            EVENTS.push(status="Fail", action="Resolve", instance="Scope",
                        name=source_name, instance_id="N/A",
                        details="Scope not resolved")
            return MPAPIResponse(state=False,
                                 message="Scope {} not resolved.".format(source_name))

    def __resolve_credential(self, source_id: str, source_name: str) -> MPAPIResponse:
        """
        Resolve source credential reference
        :param source_id: ID string
        :param source_name: Name string
        """
        # Check is exist by ID
        exist = self.iface_credential.get_by_id(source_id)
        if exist:
            self.logger.debug("Credential exists: {}({})".format(exist.get("name"),
                                                                 exist.get("id")))
            return MPAPIResponse(state=True, message=exist.get("id"))
        resolved = self.iface_credential.get_by_name(name=source_name)
        if resolved:
            self.logger.debug("Credential resolved: {}({})".format(resolved.get("name"),
                                                                   resolved.get("id")))
            return MPAPIResponse(state=True, message=resolved.get("id"))
        rich_print("[red]Looks problem with resolution credential: ", end="")
        print(source_name)
        rich_print("[yellow]CLI can not find exist credential in system according to specification reference")
        rich_print("[yellow]You can replace this credential to another, but it can impact functionality")
        try:
            decision = Prompt.ask("Would you like replace this credential? ", choices=["y", "n"], default="n")
        except KeyboardInterrupt:
            return MPAPIResponse(state=False, message="Operation interrupted")
        if decision == "y":
            credential_info = self.iface_credential.get_credential_picker("Credential name "
                                                                          "(? for list, wildcards usable): ")
            if not credential_info.state:
                EVENTS.push(status="Fail", action="Resolve", instance="Credential",
                            name=source_name, instance_id="N/A",
                            details="Credential not resolved")
                return MPAPIResponse(state=False,
                                     message="Credential {} not resolved.".format(source_name))
            else:
                self.logger.debug(
                    "Credential resolved: {}({})".format(credential_info.message.get("name"),
                                                         credential_info.message.get("id")))
                return MPAPIResponse(state=True, message=credential_info.message.get("id"))
        else:
            EVENTS.push(status="Fail", action="Resolve", instance="Credential",
                        name=source_name, instance_id="N/A",
                        details="Credential not resolved")
            return MPAPIResponse(state=False,
                                 message="Credential {} not resolved.".format(source_name))

    def __resolve_profile(self, source_id: str, source_name: str) -> MPAPIResponse:
        """
        Resolve source profile reference
        :param source_id: ID string
        :param source_name: Name string
        """
        # Check is exist by ID
        exist = self.iface_profile.get_by_id(source_id)
        if exist:
            self.logger.debug("Profile exists: {}({})".format(exist.get("name"),
                                                              exist.get("id")))
            return MPAPIResponse(state=True, message=exist.get("id"))
        resolved = self.iface_profile.get_by_name(name=source_name)
        if resolved:
            self.logger.debug("Profile resolved: {}({})".format(resolved.get("name"),
                                                                resolved.get("id")))
            return MPAPIResponse(state=True, message=resolved.get("id"))
        rich_print("[red]Looks problem with resolution profile: ", end="")
        print(source_name)
        rich_print("[yellow]CLI can not find exist profile in system according to specification reference")
        rich_print("[yellow]You can replace this profile to another, but it can impact functionality")
        try:
            decision = Prompt.ask("Would you like replace this profile? ", choices=["y", "n"], default="n")
        except KeyboardInterrupt:
            return MPAPIResponse(state=False, message="Operation interrupted")
        if decision == "y":
            profile_info = self.iface_profile.get_profile_picker("Profile name (? for list, wildcards usable): ")
            if not profile_info.state:
                EVENTS.push(status="Fail", action="Resolve", instance="Profile",
                            name=source_name, instance_id="N/A",
                            details="Profile not resolved")
                return MPAPIResponse(state=False,
                                     message="Profile {} not resolved.".format(source_name))
            else:
                self.logger.debug(
                    "Profile resolved: {}({})".format(profile_info.message.get("name"),
                                                      profile_info.message.get("id")))
                return MPAPIResponse(state=True, message=profile_info.message.get("id"))
        else:
            EVENTS.push(status="Fail", action="Resolve", instance="Profile",
                        name=source_name, instance_id="N/A",
                        details="Profile not resolved")
            return MPAPIResponse(state=False,
                                 message="Profile {} not resolved.".format(source_name))

    def __resolve_dictionary(self, source_id: str, source_name: str) -> MPAPIResponse:
        """
        Resolve source dictionary reference
        :param source_id: ID string
        :param source_name: Name string
        """
        # Check is exist by ID
        exist = self.iface_dictionary.get_by_id(source_id)
        if exist:
            self.logger.debug("Dictionary exists: {}({})".format(exist.get("name"),
                                                                 exist.get("id")))
            return MPAPIResponse(state=True, message=exist.get("id"))
        resolved = self.iface_dictionary.get_by_name(name=source_name)
        if resolved:
            self.logger.debug("Dictionary resolved: {}({})".format(resolved.get("name"),
                                                                   resolved.get("id")))
            return MPAPIResponse(state=True, message=resolved.get("id"))
        rich_print("[red]Looks problem with resolution dictionary: ", end="")
        print(source_name)
        rich_print("[yellow]CLI can not find exist dictionary in system according to specification reference")
        rich_print("[yellow]You can replace this dictionary to another, but it can impact functionality")
        try:
            decision = Prompt.ask("Would you like replace this dictionary? ", choices=["y", "n"], default="n")
        except KeyboardInterrupt:
            return MPAPIResponse(state=False, message="Operation interrupted")
        if decision == "y":
            dict_info = self.iface_dictionary.get_dictionary_picker("Dictionary name (? for list, wildcards usable): ")
            if not dict_info.state:
                EVENTS.push(status="Fail", action="Resolve", instance="Dictionary",
                            name=source_name, instance_id="N/A",
                            details="Dictionary not resolved")
                return MPAPIResponse(state=False,
                                     message="Dictionary {} not resolved.".format(source_name))
            else:
                self.logger.debug(
                    "Dictionary resolved: {}({})".format(dict_info.message.get("name"),
                                                         dict_info.message.get("id")))
                return MPAPIResponse(state=True, message=dict_info.message.get("id"))
        else:
            EVENTS.push(status="Fail", action="Resolve", instance="Dictionary",
                        name=source_name, instance_id="N/A",
                        details="Dictionary not resolved")
            return MPAPIResponse(state=False,
                                 message="Dictionary {} not resolved.".format(source_name))

    def __resolve_aec(self, source_id: str, source_name: str) -> MPAPIResponse:
        """
        Resolve source aec reference
        :param source_id: ID string
        :param source_name: Name string
        """
        # Check is exist by ID
        exist = self.iface_aec.get_by_id(source_id)
        if exist:
            self.logger.debug("AEC exists: {}({})".format(exist.get("name"),
                                                          exist.get("id")))
            return MPAPIResponse(state=True, message=exist.get("id"))
        resolved = self.iface_aec.get_by_name(name=source_name)
        if resolved:
            self.logger.debug("AEC resolved: {}({})".format(resolved.get("name"),
                                                            resolved.get("id")))
            return MPAPIResponse(state=True, message=resolved.get("id"))
        rich_print("[red]Looks problem with resolution AEC: ", end="")
        print(source_name)
        rich_print("[yellow]CLI can not find exist AEC in system according to specification reference")
        rich_print("[yellow]You can replace this AEC to another, but it can impact functionality")
        try:
            decision = Prompt.ask("Would you like replace this AEC? ", choices=["y", "n"], default="n")
        except KeyboardInterrupt:
            return MPAPIResponse(state=False, message="Operation interrupted")
        if decision == "y":
            aec_info = self.iface_aec.get_aec_picker("AEC name (? for list, wildcards usable): ")
            if not aec_info.state:
                EVENTS.push(status="Fail", action="Resolve", instance="AEC",
                            name=source_name, instance_id="N/A",
                            details="AEC not resolved")
                return MPAPIResponse(state=False,
                                     message="AEC {} not resolved.".format(source_name))
            else:
                self.logger.debug(
                    "AEC resolved: {}({})".format(aec_info.message.get("name"),
                                                  aec_info.message.get("id")))
                return MPAPIResponse(state=True, message=aec_info.message.get("id"))
        else:
            try:
                decision = Prompt.ask("Would you like set automatic AEC? ", choices=["y", "n"], default="n")
            except KeyboardInterrupt:
                return MPAPIResponse(state=False, message="Operation interrupted")
            if decision == "y":
                self.logger.debug("AEC resolved to automatic")
                return MPAPIResponse(state=True, message=None)
            EVENTS.push(status="Fail", action="Resolve", instance="AEC",
                        name=source_name, instance_id="N/A",
                        details="AEC not resolved")
            return MPAPIResponse(state=False,
                                 message="AEC {} not resolved.".format(source_name))

    def __resolve_policy(self, source_id: str, source_name: str, source_policy: str) -> MPAPIResponse:
        """
        Resolve source policy rule reference
        :param source_id: ID string
        :param source_name: Policy rule name string
        """
        # Check is exist by ID
        exist = self.iface_policy.get_rule_by_id(rule_id=source_id)
        if exist:
            self.logger.debug("Policy rule exists: {}({})".format(exist.get("name"),
                                                                  exist.get("id")))
            return MPAPIResponse(state=True, message=exist.get("id"))
        resolved = self.iface_policy.get_rule_by_name(rule_name=source_name)
        if resolved:
            self.logger.debug("Policy rule resolved: {}({})".format(resolved.get("name"),
                                                                    resolved.get("id")))
            return MPAPIResponse(state=True, message=resolved.get("id"))
        rich_print("[red]Looks problem with resolution policy rule: ", end="")
        print(source_name)
        rich_print("[yellow]CLI can not find exist policy rule in system according to specification reference")
        rich_print("[yellow]You can replace this rule to another, but it can impact functionality")
        try:
            decision = Prompt.ask("Would you like replace this policy rule? ", choices=["y", "n"], default="n")
        except KeyboardInterrupt:
            return MPAPIResponse(state=False, message="Operation interrupted")
        if decision == "y":
            rule_info = self.iface_policy.get_rule_picker("Rule name (? for list, wildcards usable): ",
                                                          policy_id=source_policy)
            if not rule_info.state:
                EVENTS.push(status="Fail", action="Resolve", instance="Rule",
                            name=source_name, instance_id="N/A",
                            details="Rule not resolved")
                return MPAPIResponse(state=False,
                                     message="Rule {} not resolved.".format(source_name))
            else:
                self.logger.debug(
                    "Rule resolved: {}({})".format(rule_info.message.get("name"),
                                                   rule_info.message.get("id")))
                return MPAPIResponse(state=True, message=rule_info.message.get("id"))
        else:
            EVENTS.push(status="Fail", action="Resolve", instance="Rule",
                        name=source_name, instance_id="N/A",
                        details="Rule not resolved")
            return MPAPIResponse(state=False,
                                 message="Rule {} not resolved.".format(source_name))

    def __resolve_group(self, source_id: str, source_hierarchy: list) -> MPAPIResponse:
        """
        Resolve source group reference
        :param source_id: ID string
        :param source_hierarchy: Hierarchy list
        """
        # Check is exist by ID
        exist = self.iface_group.get_by_id(source_id)
        if exist:
            self.logger.debug("Group exists: {}({})".format(exist.get("name"),
                                                            exist.get("id")))
            return MPAPIResponse(state=True, message=exist.get("id"))
        resolved = self.iface_group.get_by_hierarchy(hierarchy=source_hierarchy)
        if resolved:
            self.logger.debug("Group resolved: {}({})".format(resolved.get("name"),
                                                              resolved.get("id")))
            return MPAPIResponse(state=True, message=resolved.get("id"))
        rich_print("[red]Looks problem with resolution group: ", end="")
        print(source_hierarchy[-1])
        rich_print("[yellow]CLI can not find exist group in system according to specification reference")
        rich_print("[yellow]You can replace this group to another, but it can impact functionality")
        try:
            decision = Prompt.ask("Would you like replace this group? ", choices=["y", "n"], default="n")
        except KeyboardInterrupt:
            return MPAPIResponse(state=False, message="Operation interrupted")
        if decision == "y":
            group_info = self.iface_group.get_group_picker("Asset Group (? for list, wildcards usable): ")
            if not group_info.state:
                EVENTS.push(status="Fail", action="Resolve", instance="Group",
                            name=source_hierarchy[-1], instance_id="N/A",
                            details="Asset group not resolved")
                return MPAPIResponse(state=False,
                                     message="Assets group {} not resolved.".format(source_hierarchy[-1]))
            else:
                self.logger.debug(
                    "Group resolved: {}({})".format(group_info.message.get("name"),
                                                    group_info.message.get("id")))
                return MPAPIResponse(state=True, message=group_info.message.get("id"))
        else:
            EVENTS.push(status="Fail", action="Resolve", instance="Group",
                        name=source_hierarchy[-1], instance_id="N/A",
                        details="Asset group not resolved")
            return MPAPIResponse(state=False,
                                 message="Assets group {} not resolved.".format(source_hierarchy[-1]))

    def __resolve_query(self, source_id: str, source_hierarchy: list) -> MPAPIResponse:
        """
        Resolve source query reference
        :param source_id: ID string
        :param source_hierarchy: Hierarchy list
        """
        # Check is exist by ID
        self.logger.debug("Look for query source ID: {}".format(source_id))
        exist = self.iface_query.get_by_id(source_id)
        if exist:
            self.logger.debug("Query exists: {}({})".format(exist.get("displayName"),
                                                            exist.get("id")))

            return MPAPIResponse(state=True, message=exist.get("id"))
        resolved = self.iface_query.get_by_hierarchy(hierarchy=source_hierarchy)
        if resolved:
            self.logger.debug("Query resolved: {}({})".format(resolved.get("displayName"),
                                                              resolved.get("id")))
            return MPAPIResponse(state=True, message=resolved.get("id"))
        rich_print("[red]Looks problem with resolution asset query: ", end="")
        print(source_hierarchy[-1])
        rich_print("[yellow]CLI can not find exist asset query in system according to specification reference")
        rich_print("[yellow]You can replace this asset query to another, but it can impact functionality")
        try:
            decision = Prompt.ask("Would you like replace this query? ", choices=["y", "n"], default="n")
        except KeyboardInterrupt:
            return MPAPIResponse(state=False, message="Operation interrupted")
        if decision == "y":
            query_info = self.iface_query.get_query_picker("Asset Query (? for list, wildcards usable): ")
            if not query_info.state:
                EVENTS.push(status="Fail", action="Resolve", instance="Query",
                            name=source_hierarchy[-1], instance_id="N/A",
                            details="Asset query not resolved")
                return MPAPIResponse(state=False,
                                     message="Assets query {} not resolved.".format(source_hierarchy[-1]))
            else:
                self.logger.debug(
                    "Asset query resolved: {}({})".format(query_info.message.get("displayName"),
                                                          query_info.message.get("id")))
                return MPAPIResponse(state=True, message=query_info.message.get("id"))
        else:
            EVENTS.push(status="Fail", action="Resolve", instance="Query",
                        name=source_hierarchy[-1], instance_id="N/A",
                        details="Asset query not resolved")
            return MPAPIResponse(state=False,
                                 message="Assets query {} not resolved.".format(source_hierarchy[-1]))

    def __resolve_event_filter(self, source_id: str, source_hierarchy: list) -> MPAPIResponse:
        """
        Resolve source event filter reference
        :param source_id: ID string
        :param source_hierarchy: Hierarchy list
        """
        # Check is exist by ID
        self.logger.debug("Look for event filter source ID: {}".format(source_id))
        exist = self.iface_event_filter.get_by_id(source_id)
        if exist:
            self.logger.debug("Event filter exists: {}({})".format(exist.get("name"),
                                                                   exist.get("id")))

            return MPAPIResponse(state=True, message=exist.get("id"))
        resolved = self.iface_event_filter.get_by_hierarchy(hierarchy=source_hierarchy)
        if resolved:
            self.logger.debug("Event filter resolved: {}({})".format(resolved.get("name"),
                                                                     resolved.get("id")))
            return MPAPIResponse(state=True, message=resolved.get("id"))
        rich_print("[red]Looks problem with resolution event filter: ", end="")
        print(source_hierarchy[-1])
        rich_print("[yellow]CLI can not find exist event filter in system according to specification reference")
        rich_print("[yellow]You can replace this event filter to another, but it can impact functionality")
        try:
            decision = Prompt.ask("Would you like replace this event filter? ", choices=["y", "n"], default="n")
        except KeyboardInterrupt:
            return MPAPIResponse(state=False, message="Operation interrupted")
        if decision == "y":
            filter_info = self.iface_event_filter.get_event_filter_picker("Event filter (? for list, "
                                                                          "wildcards usable): ")
            if not filter_info.state:
                EVENTS.push(status="Fail", action="Resolve", instance="Event filter",
                            name=source_hierarchy[-1], instance_id="N/A",
                            details="Event filter not resolved")
                return MPAPIResponse(state=False,
                                     message="Event filter {} not resolved.".format(source_hierarchy[-1]))
            else:
                self.logger.debug(
                    "Event filter resolved: {}({})".format(filter_info.message.get("name"),
                                                           filter_info.message.get("id")))
                return MPAPIResponse(state=True, message=filter_info.message.get("id"))
        else:
            EVENTS.push(status="Fail", action="Resolve", instance="Event filter",
                        name=source_hierarchy[-1], instance_id="N/A",
                        details="Event filter not resolved")
            return MPAPIResponse(state=False,
                                 message="Event filter {} not resolved.".format(source_hierarchy[-1]))

    def __resolve_site(self, source_id: str, source_hierarchy: list) -> MPAPIResponse:
        """
        Resolve site reference
        :param source_id: ID string
        :param source_hierarchy: Hierarchy list
        """
        # Check is exist by ID
        exist = self.iface_site.get_by_id(source_id)
        if exist:
            self.logger.debug("Site exists: {}({})".format(exist.get("name"),
                                                           exist.get("id")))
            return MPAPIResponse(state=True, message=exist.get("id"))
        resolved = self.iface_site.get_by_hierarchy(hierarchy=source_hierarchy)
        if resolved:
            self.logger.debug("Site resolved: {}({})".format(resolved.get("name"),
                                                             resolved.get("id")))
            return MPAPIResponse(state=True, message=resolved.get("id"))
        rich_print("[red]Looks problem with resolution site: ", end="")
        print(source_hierarchy[-1])
        rich_print("[yellow]CLI can not find exist site in system according to specification reference")
        rich_print("[yellow]You can replace this site to another, but it can impact functionality")
        try:
            decision = Prompt.ask("Would you like replace this site? ", choices=["y", "n"], default="n")
        except KeyboardInterrupt:
            return MPAPIResponse(state=False, message="Operation interrupted")
        if decision == "y":
            site_info = self.iface_site.get_site_picker("Site (? for list, wildcards usable): ")
            if not site_info.state:
                EVENTS.push(status="Fail", action="Resolve", instance="Site",
                            name=source_hierarchy[-1], instance_id="N/A",
                            details="Site not resolved")
                return MPAPIResponse(state=False,
                                     message="Site {} not resolved.".format(source_hierarchy[-1]))
            else:
                self.logger.debug(
                    "Site resolved: {}({})".format(site_info.message.get("name"),
                                                   site_info.message.get("id")))
                return MPAPIResponse(state=True, message=site_info.message.get("id"))
        else:
            EVENTS.push(status="Fail", action="Resolve", instance="Site",
                        name=source_hierarchy[-1], instance_id="N/A",
                        details="Site not resolved")
            return MPAPIResponse(state=False,
                                 message="Site {} not resolved.".format(source_hierarchy[-1]))
