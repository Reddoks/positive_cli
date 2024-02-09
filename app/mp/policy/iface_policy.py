import logging
import re
import datetime

from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter
from rich.progress import Progress
from rich import print as rich_print

import app
from app.app import EVENTS
from app.core.func import get_keys_from_dict, console_clear_up, fnmatch_ext, get_string_from_fmt
from app.mp.api import MPAPIResponse
from app.mp.func import (func_select_list_item)


class iface_MP_Policy:  # noqa
    def __init__(self, load=True):
        """
        Interface for policies
        :param load: if false - do not load policy list
        """
        self.logger = logging.getLogger("mp.iface_policy")
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

    def info(self, policy_id_pattern=None, policy_lst=None, policy_dct=None) -> MPAPIResponse:
        """
        Get policy information
        :param policy_id_pattern: string with ID
        :param policy_lst: list of policies
        :param policy_dct: policy dict
        """
        from app.mp.mp.iface_mp import ID_refs
        policy_list = None
        if policy_id_pattern:
            policy_list = self.get_policy_by_pattern(policy_id_pattern)
            if policy_list:
                if len(policy_list) > 1:
                    policy_list = [func_select_list_item(policy_list, namefield="policyId", woids=True)]
                    if policy_list == [False] or policy_list == [None]:
                        return MPAPIResponse(state=False, message="No policy found")
            else:
                return MPAPIResponse(state=False, message="No policy found")
        if policy_lst:
            policy_list = policy_lst
        if policy_dct:
            policy_list = [policy_dct]
        if policy_list:
            out_list = []
            if len(policy_list) > 5:
                rich_print("[yellow]It can get some time")
            try:
                id_refs = ID_refs(["group", "policy"])
            except KeyboardInterrupt:
                return MPAPIResponse(state=False, message="Operation interrupted")
            except BaseException as err:
                self.logger.error("Failed to initialize reference APIs: {}".format(err))
                return MPAPIResponse(state=False, message="Failed to initialize reference APIs: {}".format(err))
            with Progress() as progress:
                task = progress.add_task("Getting policy rules...", total=len(policy_list))
                for item in policy_list:
                    progress.update(task, advance=1)
                    response = app.API_MP.get(app.API_MP.url_policy_rules.format(item.get("policyId")))
                    if not response.state:
                        self.logger.error("'Policy rules load failed: {}".format(response.message))
                        return response
                    for rule in response.message.json():
                        rule["policyId"] = item["policyId"]
                        rule["position"] = self.get_rule_position(response.message.json(), rule.get("id")) + 1
                        refs = id_refs.get_references(rule)
                        if not refs.state:
                            return refs
                        rule["cli-mixin"] = {
                            "mixin_ref_version": app.MIXIN_REF_VERSION,
                            "kind": "policy_rule",
                            "timestamp": str(datetime.datetime.now()),
                            "product": app.API_MP.product,
                            "references_id": refs.message
                        }
                        out_list.append(rule)

            console_clear_up(skip_line=True)
            if len(out_list) == 0:
                return MPAPIResponse(state=False, message="No policy rules found")
            return MPAPIResponse(state=True, message=out_list)
        else:
            return MPAPIResponse(state=False, message="No policy rules found")

    def rule(self, pattern=None, lst=None) -> MPAPIResponse:
        """
        Get rule information
        :param pattern: string with ID
        :param lst: IDs list
        """
        from app.mp.mp.iface_mp import ID_refs
        rule_list = None
        if pattern:
            rule_list = self.get_rule_by_pattern(pattern)
            if rule_list:
                if len(rule_list) > 1:
                    rule_list = [func_select_list_item(rule_list)]
                    if rule_list == [False] or rule_list == [None]:
                        return MPAPIResponse(state=False, message="No rule found")
            else:
                return MPAPIResponse(state=False, message="No rule found")
        if lst:
            rule_list = lst
        try:
            id_refs = ID_refs(["group", "policy"])
        except KeyboardInterrupt:
            return MPAPIResponse(state=False, message="Operation interrupted")
        except BaseException as err:
            self.logger.error("Failed to initialize reference APIs: {}".format(err))
            return MPAPIResponse(state=False, message="Failed to initialize reference APIs: {}".format(err))
        for item in rule_list:
            response = app.API_MP.get(app.API_MP.url_policy_rules.format(item.get("policyId")))
            if not response.state:
                self.logger.error("'Policy rules load failed: {}".format(response.message))
                return response
            item["position"] = self.get_rule_position(response.message.json(), item.get("id")) + 1
            refs = id_refs.get_references(item)
            if not refs.state:
                return refs
            item["cli-mixin"] = {
                "mixin_ref_version": app.MIXIN_REF_VERSION,
                "kind": "policy_rule",
                "timestamp": str(datetime.datetime.now()),
                "product": app.API_MP.product,
                "references_id": refs.message
            }
        return MPAPIResponse(state=True, message=rule_list)

    def create(self, source_spec: dict, disarm=True) -> MPAPIResponse:
        """
        Create policy rule from specification
        :param source_spec: specification structure
        :param disarm: run in test mode
        """
        from app.mp.mp.iface_mp import ID_refs
        # Reload policy list
        response = self.__load_list()
        if not response.state:
            EVENTS.push(status="Fail", action="Create", instance="Rule",
                        name=source_spec.get("name"), instance_id=source_spec.get("id"),
                        details=response.message)
            return response
        self.list = response.message
        # Prepare specification
        print("Trying to create policy rule: {}... ".format(source_spec.get("name")))
        # Look rule exist
        exists = self.get_rule_by_name(source_spec.get("name"))
        if exists and exists.get("policyId") == source_spec.get("policyId"):
            return MPAPIResponse(state=False, message="Rule {} exist. Can`t create".format(source_spec.get("name")))
        self.logger.debug("Rule {} not exist".format(source_spec.get("name")))
        try:
            id_refs = ID_refs(["group", "policy"])
        except KeyboardInterrupt:
            return MPAPIResponse(state=False, message="Operation interrupted")
        except BaseException as err:
            self.logger.error("Failed to initialize reference APIs: {}".format(err))
            return MPAPIResponse(state=False, message="Failed to initialize reference APIs: {}".format(err))
        out_spec = id_refs.replace(source_spec)
        if not out_spec.state:
            return out_spec
        else:
            out_spec = out_spec.message
        if not app.app.GLOBAL_DISARM and not disarm:
            self.logger.debug("Starting create process")
            # Evaluate
            self.logger.debug("Trying to evaluate rule {}".format(source_spec.get("name")))
            print("Evaluate rule... ", end="")
            response = app.API_MP.post(app.API_MP.url_policy_condition_evaluate.format(out_spec.get("policyId")),
                                       {"condition": out_spec.get("condition")})
            if not response.state:
                rich_print("[red]FAIL")
                self.logger.error("Failed to evaluate rule: {}".format(response.message))
                EVENTS.push(status="Fail", action="Evaluate", instance="Rule",
                            name=source_spec.get("name"), instance_id="N/A",
                            details=response.message)
                return response
            response = response.message.json()
            if response.get("assetFilterError"):
                rich_print("[red]FAIL")
                self.logger.error("Failed to evaluate rule: {}".format(response.get("assetFilterError")))
                EVENTS.push(status="Fail", action="Evaluate", instance="Rule",
                            name=source_spec.get("name"), instance_id="N/A",
                            details="Asset filter error: {}".format(response.get("assetFilterError")))
                return MPAPIResponse(state=False, message="Asset filter error: {}"
                                     .format(response.get("assetFilterError")))
            rich_print("[green]OK")
            # Create
            print("Create rule... ", end="")
            response = app.API_MP.post(app.API_MP.url_policy_rules.format(out_spec.get("policyId")),
                                       {"name": out_spec.get("name"),
                                        "condition": out_spec.get("condition"),
                                        "actionResult": out_spec.get("actionResult")})
            if not response.state:
                rich_print("[red]FAIL")
                self.logger.error("Failed to create rule: {}".format(response.message))
                EVENTS.push(status="Fail", action="Create", instance="Rule",
                            name=source_spec.get("name"), instance_id="N/A",
                            details=response.message)
                return response
            response = response.message.json()
            rich_print("[green]{}".format(response))
            # Preceding
            print("Set preceding... ", end="")
            put_data = []
            if out_spec.get("precedingRuleId") != "00000000-0000-0000-0000-000000000002":
                put_data.append({
                    "type": "SetRulePosition",
                    "precedingRuleId": out_spec.get("precedingRuleId")
                })
            else:
                put_data.append({
                    "type": "SetRulePosition",
                })
            response = app.API_MP.put(app.API_MP.url_policy_rule_instance.format(out_spec.get("policyId"),
                                                                                 response),
                                      put_data)
            if not response.state:
                rich_print("[red]FAIL")
                self.logger.error("Failed to set preceding for rule: {}".format(out_spec.get("name")))
                EVENTS.push(status="Fail", action="Preceding", instance="Rule",
                            name=source_spec.get("name"), instance_id="N/A",
                            details=response.message)
                return response
            rich_print("[green]OK")
            # Apply
            print("Apply changes... ", end="")
            response = app.API_MP.put(app.API_MP.url_policy_instance.format(out_spec.get("policyId")),
                                      {"type": "ApplyPolicyChanges"})
            if not response.state:
                rich_print("[red]FAIL")
                self.logger.error("Failed to apply rule: {}".format(out_spec.get("name")))
                EVENTS.push(status="Fail", action="Apply", instance="Rule",
                            name=source_spec.get("name"), instance_id="N/A",
                            details=response.message)
                return response
            rich_print("[green]OK")
            self.logger.debug("Policy rule {} successfully created".format(out_spec.get("name")))
            return MPAPIResponse(state=True,
                                 message="Policy rule {} successfully created".format(out_spec.get("name")))
        else:
            return MPAPIResponse(state=True, message="Success - disarmed")

    def delete(self, typ: str, rule_id: str, disarm=True) -> MPAPIResponse:
        """
        Delete policy rule
        :param typ: policyId
        :param rule_id: string
        :param disarm: run in test mode
        """
        self.logger.debug("Trying to delete rule {}".format(rule_id))
        print("Trying to delete rule {}:".format(rule_id))
        if not app.app.GLOBAL_DISARM and not disarm:
            self.logger.debug("Trying to send rule delete request")
            print("Create rule delete request... ", end="")
            put_data = [{
                "type": "RemoveRule"
            }]
            response = app.API_MP.put(app.API_MP.url_policy_rule_instance.format(typ, rule_id), put_data)
            if not response.state:
                rich_print("[red]FAIL")
                self.logger.error("Failed to request deletion for rule: {}".format(rule_id))
                EVENTS.push(status="Fail", action="Delete", instance="Rule",
                            name="N/A", instance_id=rule_id,
                            details=response.message)
                return response
            rich_print("[green]OK")
            self.logger.debug("Trying to apply changes")
            print("Apply changes... ", end="")
            response = app.API_MP.put(app.API_MP.url_policy_instance.format(typ), {"type": "ApplyPolicyChanges"})
            if not response.state:
                rich_print("[red]FAIL")
                self.logger.error("Failed to apply rule deletion: {}".format(rule_id))
                EVENTS.push(status="Fail", action="Apply", instance="Rule",
                            name="N/A", instance_id=rule_id,
                            details=response.message)
                return response
            rich_print("[green]OK")
            self.logger.info("Policy rule {} successfully deleted".format(rule_id))
            return MPAPIResponse(state=True,
                                 message="Policy rule {} successfully deleted".format(rule_id))
        else:
            return MPAPIResponse(state=True, message="Success - disarmed")

    def set_preceding(self, typ: str, rule_id: str, preceding_id: str | None, disarm=True):
        """
        Set rule preceding
        :param typ: policy type string
        :param rule_id: ID string
        :param preceding_id: preceding ID
        :param disarm: run in test mode
        """
        self.logger.debug("Trying to set preceding for rule {}".format(rule_id))
        print("Trying to set preceding for rule {}:".format(rule_id))
        print("Set preceding... ", end="")
        if not app.app.GLOBAL_DISARM and not disarm:
            put_data = []
            if preceding_id:
                put_data.append({
                    "type": "SetRulePosition",
                    "precedingRuleId": preceding_id
                })
            else:
                put_data.append({
                    "type": "SetRulePosition",
                })
            response = app.API_MP.put(app.API_MP.url_policy_rule_instance.format(typ, rule_id), put_data)
            if not response.state:
                rich_print("[red]FAIL")
                self.logger.error("Failed to set preceding for rule: {}".format(rule_id))
                EVENTS.push(status="Fail", action="Preceding", instance="Rule",
                            name="N/A", instance_id=rule_id,
                            details=response.message)
                return response
            rich_print("[green]OK")
            print("Apply changes... ", end="")
            response = app.API_MP.put(app.API_MP.url_policy_instance.format(typ),
                                      {"type": "ApplyPolicyChanges"})
            if not response.state:
                rich_print("[red]FAIL")
                self.logger.error("Failed to apply rule: {}".format(rule_id))
                EVENTS.push(status="Fail", action="Apply", instance="Rule",
                            name="N/A", instance_id=rule_id,
                            details=response.message)
                return response
            rich_print("[green]OK")
            self.logger.info("Policy rule {} successfully changed".format(rule_id))
            return MPAPIResponse(state=True,
                                 message="Policy rule {} successfully changed".format(rule_id))
        else:
            return MPAPIResponse(state=True, message="Success - disarmed")

    def get_rule_position(self, rule_lst: list, rule_id: str) -> int:
        """
        Get rule position in policy
        :param rule_lst: list of rules
        :param rule_id: ID string
        """
        for itm in rule_lst:
            if itm.get("id") == rule_id:
                if itm.get("precedingRuleId"):
                    rule_preceding = self.get_rule_position(rule_lst, rule_id=itm.get("precedingRuleId"))
                    return rule_preceding + 1
                else:
                    return 0

    @staticmethod
    def get_rule_neighbors(rule_lst: list, rule_id: str) -> [str | None, str | None]:
        """
        Get rule previous and subsequent
        :param rule_lst: list of rules
        :param rule_id: ID string
        """
        # Getting previous
        previous = None
        subsequent = None
        for item in rule_lst:
            if item.get("id") == rule_id:
                previous = item.get("precedingRuleId")
            if item.get("precedingRuleId") == rule_id:
                subsequent = item.get("id")
        return previous, subsequent

    @staticmethod
    def reduce_policy_list(data: dict | list) -> dict | list:
        """
        Policy list reducer
        """
        if isinstance(data, list):
            output = []
            for item in data:
                output.append(
                    get_keys_from_dict(item, ["policyId", "lastDateOfRecalculation", "isValid",
                                              "has_Changes", "rules_count"]))
        else:
            output = get_keys_from_dict(data, ["policyId", "lastDateOfRecalculation", "isValid",
                                               "has_Changes", "rules_count"])
        return output

    @staticmethod
    def reduce_policy_information(data: dict | list) -> dict | list:
        """
        Policy list reducer
        """
        if isinstance(data, list):
            output = []
            for item in data:
                output.append(
                    get_keys_from_dict(item, ["position", "id", "policyId", "name",
                                              "state", "sourceType", "objectCount"]))
        else:
            output = get_keys_from_dict(data, ["position", "id", "policyId", "name",
                                               "state", "sourceType", "objectCount"])
        return output

    def get_policy_by_pattern(self, pattern: str) -> list | None:
        """
        Get policy by ID pattern
        :param pattern: string
        """
        out_list = []
        for item in self.list:
            if fnmatch_ext(item["policyId"].lower(), pattern.lower()):
                out_list.append(item)
        if len(out_list) == 0:
            return
        else:
            return out_list

    def get_rule_by_name(self, rule_name: str) -> dict | None:
        """
        Get rule by name
        :param rule_name: string
        """
        for item in self.list:
            for idx, rule in enumerate(item["rule_names"]):
                if rule == rule_name:
                    rule_info = app.API_MP.get(app.API_MP.url_policy_rule_instance.format(
                        item.get("policyId"), item["rule_ids"][idx]))
                    if rule_info.state:
                        rule_info = rule_info.message.json()
                        rule_info["policyId"] = item.get("policyId")
                        return rule_info

    def get_rule_by_id(self, rule_id: str) -> dict | None:
        """
        Get rule by ID
        :param rule_id: string
        """
        for item in self.list:
            if rule_id in item["rule_ids"]:
                rule_info = app.API_MP.get(app.API_MP.url_policy_rule_instance.format(
                    item.get("policyId"), rule_id))
                if rule_info.state:
                    return rule_info.message.json()

    def get_rule_by_pattern(self, pattern: str) -> list | None:
        """
        Get rule by ID or name
        :param pattern: string
        """
        id_pattern = re.compile("[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+")
        out_list = []
        # If pattern is ID
        if id_pattern.match(pattern):
            for item in self.list:
                if pattern in item["rule_ids"]:
                    rule_info = app.API_MP.get(app.API_MP.url_policy_rule_instance.format(
                        item.get("policyId"), pattern))
                    if rule_info.state:
                        rule_info = rule_info.message.json()
                        rule_info["policyId"] = item.get("policyId")
                        out_list.append(rule_info)
        else:
            for item in self.list:
                for index, itm in enumerate(item["rule_names"]):
                    if fnmatch_ext(itm.lower(), pattern.lower()):
                        rule_info = app.API_MP.get(app.API_MP.url_policy_rule_instance.format(
                            item.get("policyId"), item["rule_ids"][index]))
                        if rule_info.state:
                            rule_info = rule_info.message.json()
                            rule_info["policyId"] = item.get("policyId")
                            out_list.append(rule_info)
        if len(out_list) == 0:
            return
        else:
            return out_list

    def get_rule_picker(self, prompt_string: str, policy_id: str) -> MPAPIResponse:
        """
        Pick policy rule with autocompletion
        :param prompt_string: dialog prompt
        :param policy_id: policy_id
        """
        rule_names, rule_ids = self.get_short_rule_list(policy_id)
        rule_completer = WordCompleter(rule_names, sentence=True)
        while True:
            try:
                rule_input = prompt(prompt_string, completer=rule_completer, complete_while_typing=True)
            except KeyboardInterrupt:
                return MPAPIResponse(state=False, message="Operation interrupted")
            if rule_input == "":
                return MPAPIResponse(state=False, message="Skip rule enter")
            if rule_input == "?":
                print("Available rules:")
                print(get_string_from_fmt(rule_names, fmt="yaml"))
                continue
            if "*" in rule_input:
                print("Available rules:")
                for item in rule_names:
                    if fnmatch_ext(item, rule_input):
                        print("- {}".format(item))
                continue
            if len(rule_names) == 1:
                if rule_names[0] == rule_input:
                    return MPAPIResponse(state=True, message={"name": rule_names[0], "id": rule_ids[0]})
            for idx in range(0, len(rule_names)):
                print(rule_names[idx])
                if rule_names[idx] == rule_input:
                    return MPAPIResponse(state=True, message={"name": rule_names[idx], "id": rule_ids[idx]})
            rich_print("[red]Wrong rule")

    def get_short_rule_list(self, policy_id: str) -> [list, list]:
        """
        Get rules short list - name and ID
        """
        names = []
        ids = []
        names.append("Root")
        ids.append("00000000-0000-0000-0000-000000000002")
        for policy in self.list:
            if policy_id == policy.get("policyId"):
                names += policy.get("rule_names")
                ids += policy.get("rule_ids")
        return names, ids

    def get_reference(self, spec: dict) -> MPAPIResponse:
        """
        Look instance for policy IDs and return reference
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
                    rule = self.get_rule_by_id(rule_id=struct)
                    if rule:
                        return [{"id": struct, "kind": "policy_rule", "name": rule.get("name"),
                                 "policy_id": spec.get("policyId")}]
                return

        out_list = []
        for key, value in spec.items():
            inst = lookup_in_key(value)
            if inst:
                out_list += inst
        out_list = build_originals(out_list)
        return MPAPIResponse(state=True, message=out_list)

    def __load_list(self) -> MPAPIResponse:
        """
        Load policy list
        """
        self.logger.debug("Trying to load policies")
        # Load policies list
        response = app.API_MP.get(app.API_MP.url_policy)
        if not response.state:
            self.logger.error("Policy list load failed: {}".format(response.message))
            return response
        policies_list = response.message.json()
        # Getting rule IDs for policies
        for item in policies_list:
            response = app.API_MP.get(app.API_MP.url_policy_rules.format(item.get("policyId")))
            if not response.state:
                self.logger.error("Policy rules load failed: {}".format(response.message))
                return response
            policy_rules_list = response.message.json()
            item["rules_count"] = len(policy_rules_list)
            item["rule_ids"] = []
            item["rule_names"] = []
            for rule in policy_rules_list:
                item["rule_ids"].append(rule.get("id"))
                item["rule_names"].append(rule.get("name"))
        self.logger.debug("Policy list load succeeded")
        return MPAPIResponse(state=True, message=policies_list)
