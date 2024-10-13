import logging
import re
import time
import datetime

from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter
from rich.progress import Progress, TaskID
from rich.prompt import Prompt
from rich import print as rich_print

import app
from app.app import EVENTS
from app.core.func import fnmatch_ext, console_clear_up, get_keys_from_dict, get_string_from_fmt, getch
from app.mp.api import MPAPIResponse
from app.mp.func import (func_select_list_item,
                         func_get_list_by_pattern_with_childs)


class iface_MP_Group:  # noqa
    def __init__(self, load=True):
        """
        Interface for asset groups
        """
        self.logger = logging.getLogger("mp.asset.iface_group")
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
        Get asset group information
        :param pattern: string
        :param lst: list of groups
        :param dct: group dict
        :return: group information list
        """
        groups_list = None
        # If pattern
        if pattern:
            self.logger.debug("Trying to get group info for pattern: {}".format(pattern))
            groups_list = func_get_list_by_pattern_with_childs(self.list, pattern.lower())
            if groups_list:
                self.logger.debug("Found {} groups".format(len(groups_list)))
                if len(groups_list) > 1:
                    groups_list = [func_select_list_item(groups_list)]
                    if groups_list == [False] or groups_list == [None]:
                        self.logger.error("No group found")
                        return MPAPIResponse(state=False, message="No group found")
            else:
                self.logger.error("No group found")
                return MPAPIResponse(state=False, message="No group found")
        # If list
        if lst:
            groups_list = lst
        # If dict
        if dct:
            groups_list = [dct]
        if groups_list:
            with Progress() as progress:
                count = self.__get_count(groups_list)
                task = progress.add_task("Getting groups info...", total=count)
                group_info = self.__get_info(groups_list, progress, task)
                if group_info.state:
                    group_info = group_info.message
                else:
                    return group_info
            console_clear_up(skip_line=True)
            if len(group_info) == 0:
                return MPAPIResponse(state=False, message="No groups found")
            return MPAPIResponse(state=True, message=group_info)
        else:
            return MPAPIResponse(state=False, message="No groups found")

    def create(self, raw_spec: dict, disarm=True) -> MPAPIResponse:
        """
        Create asset group from specification
        :param raw_spec: specification structure
        :param disarm: run in test mode
        """
        self.logger.debug("Trying to create group from specification")
        # Reload group list
        response = self.__load_list()
        if not response.state:
            EVENTS.push(status="Fail", action="Create", instance="Group",
                        name=raw_spec["name"], instance_id=raw_spec["id"],
                        details="MP Task asset group API initialization failed")
            return response
        self.list = response.message
        root_id = self.get_root_id()
        response = self.__create_from_spec(raw_spec, root_id, disarm)
        return response

    def delete(self, group_id: str, disarm=True) -> MPAPIResponse:
        """
        Delete asset group
        :param group_id: string ID
        :param disarm: run in test mode
        """
        self.logger.debug("Trying to delete group {}".format(group_id))
        print("Trying to delete group {}".format(group_id))
        if not app.app.GLOBAL_DISARM and not disarm:
            op_request = app.API_MP.post(app.API_MP.url_asset_group_remove,
                                         data={"groupIds": [group_id]})
        else:
            print("Success - disarmed")
            return MPAPIResponse(state=True, message="Success - disarmed")
        if not op_request.state:
            EVENTS.push(status="Fail", action="Delete", instance="Group",
                        name="N/A", instance_id=group_id,
                        details=op_request.message)
            self.logger.error("Asset group API response failed. Can`t delete")
            self.logger.error(op_request.message)
            return op_request
        retries = 0
        while True:
            retries += 1
            if retries == 2:
                print("Slow API responsiveness")
            if retries == 10:
                EVENTS.push(status="Fail", action="Delete", instance="Group",
                            name="N/A", instance_id=group_id,
                            details="API can`t process deletion request (no response)")
                return MPAPIResponse(state=False,
                                     message="API can`t process deletion request (no response)")
            op_id = op_request.message.json()
            completion = app.API_MP.get(app.API_MP.url_asset_group_operations.format(op_id.get("operationId")))
            if not completion.state:
                try:
                    time.sleep(5)
                except KeyboardInterrupt:
                    return MPAPIResponse(state=False, message="Operation interrupted")
                continue
            else:
                EVENTS.checkout()
                return MPAPIResponse()

    def get_group_picker(self, prompt_string: str) -> MPAPIResponse:
        """
        Group selection dialog with autocompletion
        :param prompt_string: prompt for dialog
        :return: asset group item
        """
        # Build plain group list based on hierarchy
        groups_name, groups_hierarchy, groups_ids = self.__get_plain_hierarchy()
        groups_completer = WordCompleter(groups_hierarchy, sentence=True)
        while True:
            try:
                group_input = prompt(prompt_string, completer=groups_completer, complete_while_typing=True)
            except KeyboardInterrupt:
                return MPAPIResponse(state=False, message="Operation interrupted")
            if group_input == "":
                return MPAPIResponse(state=False, message="Skip group enter")
            if group_input == "?":
                print("Available groups:")
                print(get_string_from_fmt(groups_hierarchy, fmt="yaml"))
                continue
            if "*" in group_input:
                print("Available groups:")
                for item in groups_hierarchy:
                    if fnmatch_ext(item, groups_hierarchy):
                        print("- {}".format(item))
                continue
            for idx in range(0, len(groups_hierarchy)):
                if groups_hierarchy[idx] == group_input:
                    return MPAPIResponse(state=True, message={"name": groups_name[idx],
                                                              "hierarchy": " \ ".join(["Root", groups_hierarchy[idx]]),
                                                              # noqa
                                                              "id": groups_ids[idx]})
            print("Wrong group")

    def get_by_id(self, group_id: str, group_list=None) -> dict | None:
        """
        Get asset group by ID
        :param group_id: string with id
        :param group_list: internally used
        :return: asset group item
        """
        if not group_list:
            group_list = self.list
        for item in group_list:
            if item.get("id") == group_id:
                return item
            else:
                if item.get("children"):
                    child_groups = self.get_by_id(group_id, item.get("children"))
                    if child_groups:
                        return child_groups
        return

    def get_by_name(self, name: str, group_list=None) -> dict | None:
        """
        Get asset group by name
        :param name: string with name
        :param group_list: internally used
        :return: asset group item
        """
        if not group_list:
            group_list = self.list
        for item in group_list:
            if item.get("name") == name:
                return item
            else:
                if item.get("children"):
                    child_groups = self.get_by_name(name, item.get("children"))
                    if child_groups:
                        return child_groups
        return

    def get_by_hierarchy(self, hierarchy: list, groups=None) -> dict | None:
        """
        Get group by tree hierarchy.
        :param hierarchy: tree hierarchy structure
        :param groups: for recursion on childs
        :return: asset group item
        """
        if not groups:
            groups = self.list
        for item in groups:
            if item.get("tree_hierarchy"):
                if item.get("tree_hierarchy") == hierarchy:
                    return item
                else:
                    if item.get("children"):
                        child_groups = self.get_by_hierarchy(hierarchy, item.get("children"))
                        if child_groups:
                            return child_groups
            else:
                if item.get("children"):
                    child_groups = self.get_by_hierarchy(hierarchy, item.get("children"))
                    if child_groups:
                        return child_groups
        return

    def get_by_pattern(self, pattern: str, lst=None) -> list | None:
        """
        Get group by name or ID
        :param pattern: string with name or ID
        :param lst: used for child recursion
        :return: asset group item
        """
        id_pattern = re.compile("[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+")
        out_list = []
        if not lst:
            lst = self.list
        # If pattern is ID
        if id_pattern.match(pattern):
            for item in lst:
                if item.get("id") == pattern:
                    out_list.append(item)
                if item.get("children"):
                    child_list = self.get_by_pattern(pattern=pattern, lst=item.get("children"))
                    if child_list:
                        out_list += child_list
        else:
            for item in lst:
                if fnmatch_ext(item.get("name").lower(), pattern.lower()):
                    out_list.append(item)
                if item.get("children"):
                    child_list = self.get_by_pattern(pattern=pattern, lst=item.get("children"))
                    if child_list:
                        out_list += child_list
        if len(out_list) == 0:
            return
        else:
            return out_list

    def get_by_name_from_parent_root(self, name: str, parent_id: str) -> dict | None:
        """
        Get group from defined root level.
        :param name: string
        :param parent_id: Root level group ID
        :return: asset group item
        """
        parent_group = self.get_by_id(parent_id)
        for item in parent_group.get("children"):
            if item.get("name") == name:
                return item
        return

    def get_root_id(self) -> str | None:
        """
        Get root group
        :return: root group ID
        """
        for item in self.list:
            if item.get("name") == "Root":
                return item.get("id")
        return

    def get_hierarchy(self, group_id: str, group_list=None) -> list | None:
        """
        Calculate asset group hierarchy in group tree
        :param group_id: string with ID
        :param group_list: used for recursion
        :return: hierarchy list
        """
        if not group_list:
            group_list = self.list
        for item in group_list:
            hierarchy_tmp = [item["name"]]
            if item.get("id") == group_id:
                return hierarchy_tmp
            if item.get("children"):
                child_hierarchy = self.get_hierarchy(group_id=group_id, group_list=item.get("children"))
                if child_hierarchy:
                    hierarchy_tmp += child_hierarchy
                    return hierarchy_tmp
        return

    def reload(self):
        """
        Reload instance group list
        """
        self.list = self.__load_list()

    @staticmethod
    def remove_childs(group_list: list) -> list:
        """
        Get list of asset groups without child groups
        :param group_list: list of groups with potential childs
        :return: list of groups without childs
        """
        out_list = []
        for item in group_list:
            if item.get("name") == "Root":
                continue
            parent_is_present = False
            for itm in group_list:
                if itm.get("id") == item.get("parentId") and itm.get("name") != "Root":
                    parent_is_present = True
            if not parent_is_present and item.get("id") != "00000000-0000-0000-0000-000000000003":
                out_list.append(item)
        return out_list

    def get_reference(self, spec: dict) -> MPAPIResponse:
        """
        Look instance for asset group IDs and return reference
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
                if re.match(id_pattern, struct):
                    hierarchy = self.get_hierarchy(group_id=struct)
                    if hierarchy and struct != spec.get("id"):
                        return [{"id": struct, "kind": "group", "hierarchy": hierarchy}]
                return

        out_list = []
        for key, value in spec.items():
            inst = lookup_in_key(value)
            if inst:
                out_list += inst
        out_list = build_originals(out_list)
        return MPAPIResponse(state=True, message=out_list)

    def __create_group(self, spec: dict, parent_id: str, disarm: bool) -> MPAPIResponse:
        """
        Create asset group
        :param spec: specification structure
        :param parent_id: parent group ID
        :param disarm: run in test mode
        """
        from app.mp.mp.iface_mp import ID_refs
        # Check group existed on parent group level
        exist = self.get_by_name_from_parent_root(name=spec.get("name"), parent_id=parent_id)
        if exist:
            EVENTS.push(status="Fail", action="Create", instance="Group",
                        name=spec.get("name"), instance_id=spec.get("id"),
                        details="Group {} exist. Can`t create".format(spec.get("name")))
            self.logger.error("Group {} exist. Can`t create".format(spec.get("name")))
            return MPAPIResponse(state=False,
                                 message="Group {} exist. Can`t create".format(spec.get("name")))
        name = spec.get("name")
        try:
            id_refs = ID_refs(["user"])
        except KeyboardInterrupt:
            return MPAPIResponse(state=False, message="Operation interrupted")
        except BaseException as err:
            self.logger.error("Failed to initialize reference APIs: {}".format(err))
            return MPAPIResponse(state=False, message="Failed to initialize reference APIs: {}".format(err))
        spec = id_refs.replace(spec)
        if not spec.state:
            EVENTS.push(status="Fail", action="Create", instance="Group",
                        name=name, instance_id="N/A",
                        details="Failed to resolve reference IDs")
            return spec
        else:
            spec = spec.message
            spec["parentId"] = parent_id
        if not app.app.GLOBAL_DISARM and not disarm:
            rich_print("[bright_black]Submit processing request for group {}".format(spec.get("name")))
            op_request = app.API_MP.post(app.API_MP.url_asset_group_processing, spec)
        else:
            print("Success - disarmed")
            return MPAPIResponse(state=True, message="Success - disarmed")
        if not op_request.state:
            if op_request.message == "Operation interrupted":
                return MPAPIResponse(state=False, message="Operation interrupted")
            EVENTS.push(status="Fail", action="Create", instance="Group",
                        name=spec.get("name"), instance_id=spec.get("id"),
                        details=op_request.message)
            self.logger.error("Asset group API response failed. Can`t create")
            self.logger.error(op_request.message)
            return op_request
        retries = 0
        rich_print("[bright_black]Await processing for group {}".format(spec.get("name")))
        while True:
            retries += 1
            if retries == 5:
                rich_print("[grey50]-- Slow API responsiveness --")
            if retries == 20:
                EVENTS.push(status="Fail", action="Create", instance="Group",
                            name=spec.get("name"), instance_id=spec.get("id"),
                            details="API can`t process creation request (no response)")
                c = ""
                try:
                    rich_print("[yellow]API not processed creation request after 20 retries. "
                               "Would you like to try again? [y/n]:\n", end="", flush=True)
                    while not c:
                        c = getch().lower()
                except KeyboardInterrupt:
                    return MPAPIResponse(state=False, message="Operation interrupted")
                match c:
                    case "y":
                        rich_print("[bright_black]Retrying...")
                        retries = 0
                    case _:
                        return MPAPIResponse(state=False,
                                             message="API can`t process creation request (no response)")
            op_id = op_request.message.json()
            completion = app.API_MP.get(app.API_MP.url_asset_group_operations.format(op_id.get("operationId")))
            if not completion.state:
                try:
                    time.sleep(3)
                except KeyboardInterrupt:
                    return MPAPIResponse(state=False, message="Operation interrupted")
                continue
            if completion.message == 201:
                return MPAPIResponse(state=True, message="201")
            if completion.state:
                break
        self.logger.debug("Group {} created".format(spec.get("name")))
        return MPAPIResponse(state=True, message="Group {} created".format(spec.get("name")))

    def __create_from_spec(self, raw_spec: dict, root_id: str, disarm: bool, parent_id=None) -> MPAPIResponse:
        """
        Create asset group from specification
        :param raw_spec: specification structure
        :param root_id: root group ID
        :param disarm: run in test mode
        :param parent_id: used in recursion
        """
        if raw_spec.get("name") == "Root":
            return MPAPIResponse(state=False, message="Group is root group. Skip")
        # If parent is defined
        if parent_id:
            response = self.__create_group(spec=raw_spec, parent_id=parent_id, disarm=disarm)
            return response
        # Check if Parent is Root group
        if raw_spec["cli-mixin"].get("parentName") == "Root":
            response = self.__create_from_spec(raw_spec, root_id, disarm,
                                               parent_id="00000000-0000-0000-0000-000000000002")
            return response
        else:
            # Resolve Parent
            parent_hierarchy = raw_spec["cli-mixin"]["hierarchy"][:-1]
            parent_group = self.get_by_hierarchy(parent_hierarchy)
            if not parent_group:
                EVENTS.push(status="Fail", action="Create", instance="Group",
                            name=raw_spec.get("name"), instance_id=raw_spec.get("id"),
                            details="Unable to resolve parent group: {}".format(parent_hierarchy))
                return MPAPIResponse(state=False,
                                     message="Unable to resolve parent group: {}".format(parent_hierarchy))
            response = self.__create_from_spec(raw_spec, root_id, disarm, parent_group.get("id"))
            return response

    def __get_plain_hierarchy(self, lst=None) -> [list, list, list]:
        """
        Get plain lists with groups hierarchy
        :param lst: used for recursion
        :return: lists for names, hierarchy and IDs
        """
        out_names = []
        out_hierarchy = []
        out_ids = []
        if not lst:
            lst = self.list
        for item in lst:
            out_hierarchy.append(" \ ".join(item["tree_hierarchy"]))  # noqa
            out_ids.append(item.get("id"))
            out_names.append(item.get("name"))
            if len(item["children"]) > 0:
                child_names, child_hierarchy, child_ids = self.__get_plain_hierarchy(lst=item.get("children"))
                if child_hierarchy:
                    out_hierarchy += child_hierarchy
                    out_ids += child_ids
                    out_names += child_names
        return out_names, out_hierarchy, out_ids

    def __get_info(self, lst: list, progress: Progress, task: TaskID) -> MPAPIResponse:
        """
        Get asset group information
        :param lst: group items
        :param progress: progress bar object
        :param task: progress bar task object
        :return: list with groups info
        """
        from app.mp.mp.iface_mp import ID_refs
        out_list = []
        try:
            id_refs = ID_refs(["group", "query", "user"])
        except KeyboardInterrupt:
            return MPAPIResponse(state=False, message="Operation interrupted")
        except BaseException as err:
            self.logger.error("Failed to initialize reference APIs: {}".format(err))
            return MPAPIResponse(state=False, message="Failed to initialize reference APIs: {}".format(err))
        for item in lst:
            progress.update(task, advance=1)
            info = app.API_MP.get(app.API_MP.url_asset_group_instance.format(item.get("id")))
            if info.state:
                info = info.message.json()
                list_info = self.get_by_id(group_id=info.get("id"))
                parent_list_info = self.get_by_id(group_id=info.get("parentId"))
                refs = id_refs.get_references(info)
                if not refs.state:
                    return refs
                info["cli-mixin"] = {
                    "mixin_ref_version": app.MIXIN_REF_VERSION,
                    "kind": "group",
                    "timestamp": str(datetime.datetime.now()),
                    "product": app.API_MP.product,
                    "references_id": refs.message
                }
                if info.get("name") != "Root":
                    info["cli-mixin"]["parentName"] = parent_list_info.get("name")
                info["cli-mixin"]["hierarchy"] = list_info.get("tree_hierarchy")
                out_list.append(info)
                if len(list_info["children"]) > 0:
                    child_list = self.__get_info(lst=list_info.get("children"), progress=progress, task=task)
                    if child_list.state:
                        out_list += child_list.message
            else:
                if "core.assetsGroups.groupNotExists.error" in info.message:
                    EVENTS.push(action="Resolve", status="Fail",
                                instance="Asset Group",
                                name="N/A", instance_id=item.get("id"),
                                details="Unable to get info for asset group with ID {}. Asset Group not found."
                                .format(item.get("id")))
                    continue
                return info
        return MPAPIResponse(state=True, message=out_list)

    def __get_count(self, lst: list) -> int:
        """
        Get asset groups count in tree
        :param lst: groups list
        """
        count = 0
        for item in lst:
            count += 1
            if item.get("children"):
                child_count = self.__get_count(item.get("children"))
                count += child_count
        return count

    # Load groups list
    def __load_list(self) -> MPAPIResponse:
        """
        Get asset group list
        """

        def refine(group_api: iface_MP_Group, full_list: list, gr_list: list) -> list:
            out_list = []
            for item in gr_list:
                item["tree_hierarchy"] = group_api.get_hierarchy(group_id=item.get("id"), group_list=full_list)
                if item.get("children"):
                    item["children"] = refine(group_api=group_api, full_list=full_list,
                                              gr_list=item.get("children"))
                out_list.append(item)
            return out_list

        self.logger.debug("Trying to load groups list")
        response = app.API_MP.get(app.API_MP.url_asset_group_hierarchy)
        if not response.state:
            self.logger.error("Groups list load failed: {}".format(response.message))
            return response
        self.logger.debug("Groups list load succeeded")
        group_list = response.message.json()
        refined_list = refine(group_api=self, full_list=group_list, gr_list=group_list)
        return MPAPIResponse(state=True, message=refined_list)

    @staticmethod
    def reduce_info(data: dict | list) -> dict | list:
        """
        Group info reducer
        """
        if type(data) == list:
            output = []
            for item in data:
                output.append(
                    get_keys_from_dict(item,
                                       ["id", "name", "parentName", "description", "predicate", "groupType"]))
        else:
            output = get_keys_from_dict(data,
                                        ["id", "name", "parentName", "description", "predicate", "groupType"])
        return output

    def reduce_list(self, data: dict | list) -> dict | list:
        """
        Asset group list reducer
        :param data: groups list
        """
        output = {}
        if type(data) == dict:
            output["name"] = data.get("name")
            output["type"] = data.get("groupType")
            output["id"] = data.get("id")
            if len(data["children"]) > 0:
                output["__child"] = self.reduce_list(data.get("children"))
        if type(data) == list:
            output = []
            for item in data:
                if len(item["children"]) == 0:
                    output.append({
                        "name": item.get("name"),
                        "type": item.get("groupType"),
                        "id": item.get("id")
                    })
                else:
                    output.append({
                        "name": item.get("name"),
                        "type": item.get("groupType"),
                        "id": item.get("id"),
                        "__child": self.reduce_list(item.get("children"))
                    })
        return output
