import logging
import re
import time
import datetime

from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter
from rich.progress import Progress, TaskID

import app
from app.app import EVENTS
from app.core.prompt import input_prompt
from app.core.func import fnmatch_ext, console_clear_up, get_keys_from_dict, get_string_from_fmt
from app.mp.api import MPAPIResponse
from app.mp.func import (func_select_list_item,
                         func_get_list_by_pattern_with_childs)


class iface_MP_EventFilter:  # noqa
    def __init__(self, load=True):
        """
        Interface for event filters
        """
        self.logger = logging.getLogger("mp.event.iface_filter")
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

    def info(self, user_only: bool, pattern=None, lst=None, dct=None) -> MPAPIResponse:
        """
        Get event filter information
        :param user_only: if True, get only custom filters
        :param pattern: string
        :param lst: filters list
        :param dct: filters dict
        """
        filter_list = None
        if pattern:
            self.logger.debug("Trying to get filter info for pattern: {}".format(pattern))
            filter_list = self.get_from_list_by_pattern_with_childs(self.list, pattern.lower(), user_only)
            if filter_list:
                self.logger.debug("Found {} event filters".format(len(filter_list)))
                if len(filter_list) > 1:
                    filter_list = [self.select_list_item(filter_list)]
                    if filter_list == [False] or filter_list == [None]:
                        self.logger.error("No filters found")
                        return MPAPIResponse(state=False, message="No filters found")
            else:
                self.logger.error("No filters found")
                return MPAPIResponse(state=False, message="No filters found")
        # If list
        if lst:
            filter_list = lst
        # If dict
        if dct:
            filter_list = [dct]
        if filter_list:
            with Progress() as progress:
                count = self.__get_count(filter_list, user_only)
                task = progress.add_task("Getting event filters info...", total=count)
                filter_info = self.__get_info(filter_list, progress, task, user_only)
                if filter_info.state:
                    query_info = filter_info.message
                else:
                    return filter_info
            console_clear_up(skip_line=True)
            if len(query_info) == 0:
                self.logger.error("No filters found")
                return MPAPIResponse(state=False, message="No filters found")
            return MPAPIResponse(state=True, message=query_info)
        else:
            self.logger.error("No filters found")
            return MPAPIResponse(state=False, message="No filters found")

    def create(self, raw_spec: dict, disarm=True) -> MPAPIResponse:
        """
        Create event filter from spec
        :param raw_spec: specification structure
        :param disarm: run in test mode
        """
        self.logger.debug("Trying to create event filter from specification")
        # Reload filters list
        response = self.__load_list()
        if not response.state:
            EVENTS.push(status="Fail", action="Create", instance="Event Filter",
                        name=raw_spec["name"], instance_id="N/A",
                        details="MP event filter API initialization failed: {}".format(response.message))
            return response
        self.list = response.message
        response = self.__create_from_spec(raw_spec, disarm)
        return response

    def delete(self, filter_id: str, is_folder=False, disarm=True) -> MPAPIResponse:
        """
        Delete event filter
        :param filter_id: string ID
        :param is_folder: flag for type
        :param disarm: run in test mode
        """
        self.logger.debug("Trying to delete event filter {}".format(filter_id))
        print("Trying to delete event filter {}".format(filter_id))
        if not app.app.GLOBAL_DISARM and not disarm:
            if not is_folder:
                response = app.API_MP.delete(app.API_MP.url_event_filter_instance.format(filter_id),
                                             data={})
            else:
                response = app.API_MP.delete(app.API_MP.url_event_filter_folder_instance.format(filter_id),
                                             data={})
        else:
            print("Success - disarmed")
            return MPAPIResponse(state=True, message="Success - disarmed")
        if not response.state:
            EVENTS.push(status="Fail", action="Delete", instance="Event filter",
                        name="N/A", instance_id=filter_id,
                        details=response.message)
            self.logger.error("Event filters API response failed. Can`t delete")
            self.logger.error(response.message)
            return response
        self.logger.debug("Event filter {} successfully deleted".format(filter_id))
        return MPAPIResponse(state=True, message="Event filter {} successfully deleted".format(filter_id))

    def get_by_pattern(self, pattern: str, lst=None) -> list | None:
        """
        Get filter by name or ID
        :param pattern: string with name or ID
        :param lst: used for recursion
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
                if fnmatch_ext(item.get("name", "").lower(), pattern.lower()):
                    out_list.append(item)
                if item.get("children"):
                    child_list = self.get_by_pattern(pattern=pattern, lst=item.get("children"))
                    if child_list:
                        out_list += child_list
        if len(out_list) == 0:
            return
        else:
            return out_list

    def get_by_id(self, filter_id: str, filter_list=None) -> dict | None:
        """
        Get events filter by ID
        :param filter_id: string ID
        :param filter_list: used for recursion
        """
        if not filter_list:
            filter_list = self.list
        for item in filter_list:
            if item.get("id") == filter_id:
                return item
            else:
                if item.get("children"):
                    child_queries = self.get_by_id(filter_id, item.get("children"))
                    if child_queries:
                        return child_queries
        return

    def get_by_name_from_parent_root(self, name: str, parent_id: str) -> dict | None:
        """
        Get filter from defined root level
        :param name: string
        :param parent_id: Root level filter ID
        """
        parent_filter = self.get_by_id(parent_id)
        for item in parent_filter.get("children"):
            if item.get("name") == name:
                return item
        return

    def get_from_list_by_pattern_with_childs(self, lst: list, pattern: str, user_only: bool) -> list | None:
        """
        Get filters plain list by pattern
        :param lst: filters list
        :param pattern: string
        :param user_only: flag - get only user objects
        """
        id_pattern = re.compile("[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+")
        out_list = []
        # If pattern is ID
        if id_pattern.match(pattern):
            for item in lst:
                if (user_only and item.get("meta").get("source") != "user" and
                        item.get("meta").get("source") != "shared"):
                    continue
                if item.get("id") == pattern:
                    out_list.append(item)
                if item.get("children"):
                    child_list = self.get_from_list_by_pattern_with_childs(item.get("children"), pattern, user_only)
                    if child_list:
                        out_list += child_list
        else:
            for item in lst:
                if (user_only and item.get("meta").get("source") != "user" and
                        item.get("meta").get("source") != "shared"):
                    continue
                if fnmatch_ext(item.get("name", "").lower(), pattern.lower()):
                    out_list.append(item)
                if item.get("children"):
                    child_list = self.get_from_list_by_pattern_with_childs(item.get("children"), pattern, user_only)
                    if child_list:
                        out_list += child_list
        if len(out_list) == 0:
            return
        else:
            return out_list

    def get_hierarchy(self, filter_id: str, filter_list=None) -> list | None:
        """
        Calculate event filter hierarchy in filter tree
        :param filter_id: string with ID
        :param filter_list: user for recursion
        """
        if not filter_list:
            filter_list = self.list
        for item in filter_list:
            hierarchy_tmp = [item["name"]]
            if item.get("id") == filter_id:
                return hierarchy_tmp
            if item.get("children"):
                child_hierarchy = self.get_hierarchy(filter_id=filter_id, filter_list=item.get("children"))
                if child_hierarchy:
                    hierarchy_tmp += child_hierarchy
                    return hierarchy_tmp
        return

    def get_by_hierarchy(self, hierarchy: list, filters=None) -> dict | None:
        """
        Get filter by tree hierarchy
        :param hierarchy: tree hierarch structure
        :param filters: used for recursion
        """
        if not filters:
            filters = self.list
        for item in filters:
            if "tree_hierarchy" in item:
                if item.get("tree_hierarchy") == hierarchy:
                    return item
                else:
                    if item.get("children"):
                        child_filters = self.get_by_hierarchy(hierarchy, item.get("children"))
                        if child_filters:
                            return child_filters
            else:
                if item.get("children"):
                    child_filters = self.get_by_hierarchy(hierarchy, item.get("children"))
                    if child_filters:
                        return child_filters
        return

    def remove_builtin(self, lst: list) -> list:
        """
        Remove built-in filters from list
        :param lst: source list
        """
        output = []
        for item in lst:
            if item.get("meta").get("source") == "user" or item.get("meta").get("source") == "shared":
                output.append(item)
                continue
            if item.get("children"):
                child_items = self.remove_builtin(item.get("children"))
                output += child_items
        return output

    @staticmethod
    def remove_childs(filter_list: list) -> list:
        """
        Get list of event filters without child queries
        :param filter_list: list of filters
        """
        out_list = []
        for item in filter_list:
            if len(item["cli-mixin"]["hierarchy"]) == 1:
                continue
            parent_is_present = False
            for itm in filter_list:
                if len(item["cli-mixin"]["hierarchy"]) == 1:
                    continue
                if item.get("parentId"):
                    if itm.get("id") == item.get("parentId"):
                        parent_is_present = True
                if item.get("folderId"):
                    if itm.get("id") == item.get("folderId"):
                        parent_is_present = True
            if not parent_is_present:
                out_list.append(item)
        return out_list

    def reload(self):
        """
        Reload filters list
        """
        self.list = self.__load_list()

    @staticmethod
    def select_list_item(lst: list, woids=False) -> dict | None:
        """
        Select item from list
        :param lst: source list
        :param woids: do not display ID
        :return: list item
        """
        print("Found {} items:".format(len(lst)))
        for index, item in enumerate(lst):
            if not woids:
                print("{}. {} ({})".format(index + 1, item.get("name"), item.get("id")))
            else:
                print("{}. {}".format(index + 1, item.get("name")))
        try:
            select = input_prompt("Please select (ENTER for quit): ")
        except KeyboardInterrupt:
            return
        if not select.isdigit():
            return
        if int(select) < 1 or int(select) > len(lst):
            return
        return lst[int(select) - 1]

    def get_event_filter_picker(self, prompt_string: str) -> MPAPIResponse:
        """
        Event filter selection dialog with autocompletion
        :param prompt_string: prompt for dialog
        """
        filter_name, filter_hierarchy, filter_ids = self.__get_plain_hierarchy()
        filter_completer = WordCompleter(filter_hierarchy, sentence=True)
        while True:
            try:
                filter_input = prompt(prompt_string, completer=filter_completer, complete_while_typing=True)
            except KeyboardInterrupt:
                return MPAPIResponse(state=False, message="Operation interrupted")
            if filter_input == "":
                return MPAPIResponse(state=False, message="Skip filter enter")
            if filter_input == "?":
                print("Available filters:")
                print(get_string_from_fmt(filter_hierarchy, fmt="yaml"))
                continue
            if "*" in filter_input:
                print("Available filters:")
                for item in filter_hierarchy:
                    if fnmatch_ext(item, filter_hierarchy):
                        print("- {}".format(item))
                continue
            for idx in range(0, len(filter_hierarchy)):
                print(filter_hierarchy[idx])
                print(filter_input)
                if filter_hierarchy[idx] == filter_input:
                    return MPAPIResponse(state=True, message={"name": filter_name[idx],
                                                              "hierarchy": " \ ".join(["Root", filter_hierarchy[idx]]),
                                                              # noqa
                                                              "id": filter_ids[idx]})
            print("Wrong query")

    def get_reference(self, spec: dict) -> MPAPIResponse:
        """
        Look instance for event filter IDs and return reference
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
                    hierarchy = self.get_hierarchy(filter_id=struct)
                    if hierarchy and struct != spec.get("id"):
                        return [{"id": struct, "kind": "event_filter", "hierarchy": hierarchy}]
                return

        out_list = []
        for key, value in spec.items():
            inst = lookup_in_key(value)
            if inst:
                out_list += inst
        out_list = build_originals(out_list)
        return MPAPIResponse(state=True, message=out_list)

    def __get_plain_hierarchy(self, lst=None) -> [list, list, list]:
        """
        Get plain lists with filters hierarchy
        :param lst: used for recursion
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
            if item.get("children"):
                if len(item["children"]) > 0:
                    child_names, child_hierarchy, child_ids = self.__get_plain_hierarchy(lst=item.get("children"))
                    if child_hierarchy:
                        out_hierarchy += child_hierarchy
                        out_ids += child_ids
                        out_names += child_names
        return out_names, out_hierarchy, out_ids

    def __create_folder(self, spec: dict, parent_id: str, disarm: bool) -> MPAPIResponse:
        """
        Create event filters folder
        :param spec: specification structure
        :param parent_id: parent query ID
        :param disarm: run in test mode
        """
        # Check folder is existed on parent level
        exist = self.get_by_name_from_parent_root(name=spec.get("name"), parent_id=parent_id)
        if exist:
            self.logger.error("Event filters folder {} exist. Can`t create".format(spec.get("name")))
            return MPAPIResponse(state=False,
                                 message="Event filters folder {} exist. Can`t create".format(spec.get("name")))
        spec["parentId"] = parent_id
        if not app.app.GLOBAL_DISARM and not disarm:
            response = app.API_MP.post(app.API_MP.url_event_filter_folders, spec)
        else:
            print("Success - disarmed")
            return MPAPIResponse(state=True, message="Success - disarmed")
        if not response.state:
            return response
        self.logger.debug("Event filters folder {} successfully created".format(response.message.json().get("id")))
        return MPAPIResponse(state=True, message="Event filters folder {} created".format(spec.get("name")))

    def __create_filter(self, spec: dict, parent_id: str, disarm: bool) -> MPAPIResponse:
        """
        Create filter
        :param spec: specification structure
        :param parent_id: parent filter ID
        :param disarm: run in test mode
        """
        # Check filter is existed on parent level
        exist = self.get_by_name_from_parent_root(name=spec.get("name"), parent_id=parent_id)
        if exist:
            self.logger.error("Event filter {} exist. Can`t create".format(spec.get("name")))
            return MPAPIResponse(state=False,
                                 message="Event filter {} exist. Can`t create".format(spec.get("name")))
        spec["folderId"] = parent_id
        if not app.app.GLOBAL_DISARM and not disarm:
            response = app.API_MP.post(app.API_MP.url_event_filter, spec)
        else:
            print("Success - disarmed")
            return MPAPIResponse(state=True, message="Success - disarmed")
        if not response.state:
            return response
        self.logger.debug("Event filter {} successfully created".format(response.message.json().get("id")))
        return MPAPIResponse(state=True, message="Event filter {} created".format(spec.get("name")))

    def __create_from_spec(self, raw_spec: dict, disarm: bool) -> MPAPIResponse:
        """
        Create filter from specification
        :param raw_spec: specification structure
        :param disarm: run in test mode
        """
        if raw_spec.get("source") == "system":
            return MPAPIResponse(state=False,
                                 message="Filter {} is built-in filter. Skip".format(raw_spec.get("name")))
        if len(raw_spec["cli-mixin"]["hierarchy"]) == 1:
            return MPAPIResponse(state=False,
                                 message="Filter {} is top root. Skip".format(raw_spec.get("name")))
        parent_hierarchy = raw_spec["cli-mixin"]["hierarchy"][:-1]
        parent = self.get_by_hierarchy(hierarchy=parent_hierarchy)
        if not parent:
            EVENTS.push(status="Fail", action="Create", instance="Event filter",
                        name=raw_spec.get("name"), instance_id="N/A",
                        details="Unable to resolve parent folder: {}".format(parent_hierarchy))
            return MPAPIResponse(state=False,
                                 message="Unable to resolve parent folder: {}".format(parent_hierarchy))
        if raw_spec["isFolder"]:
            response = self.__create_folder(raw_spec, parent.get("id"), disarm)
        else:
            response = self.__create_filter(raw_spec, parent.get("id"), disarm)
        return response

    def __get_info(self, lst: list, progress: Progress, task: TaskID, user_only: bool) -> MPAPIResponse:
        """
        Get filter information
        :param lst: filters list
        :param progress: progress object
        :param task: progress task object
        :param user_only: get only custom filters
        """
        from app.mp.mp.iface_mp import ID_refs
        out_list = []
        try:
            id_refs = ID_refs(["group", "query"])
        except KeyboardInterrupt:
            return MPAPIResponse(state=False, message="Operation interrupted")
        except BaseException as err:
            self.logger.error("Failed to initialize reference APIs: {}".format(err))
            return MPAPIResponse(state=False, message="Failed to initialize reference APIs: {}".format(err))
        for item in lst:
            progress.update(task, advance=1)
            # Getting queue info from list
            list_info = self.get_by_id(filter_id=item.get("id"))
            if not list_info:
                EVENTS.push(action="Resolve", status="Fail",
                            instance="Event filter",
                            name="N/A", instance_id=item.get("id"),
                            details="Unable to get info for event filter with ID {}. Event filter not found."
                            .format(item.get("id")))
                continue
            if item.get("meta").get("source") != "user" and item.get("meta").get("source") != "shared" and user_only:
                continue
            # If instance is folder
            if list_info.get("type") == "folder_node":
                filter_info = {
                    "id": list_info.get("id"),
                    "name": list_info.get("name"),
                    "permissions": list_info.get("permissions"),
                    "type": list_info.get("type"),
                    "isFolder": True,
                    "meta": list_info.get("meta"),
                    "cli-mixin": {
                        "mixin_ref_version": app.MIXIN_REF_VERSION,
                        "kind": "event_filter",
                        "timestamp": str(datetime.datetime.now()),
                        "product": app.API_MP.product,
                        "hierarchy": list_info.get("tree_hierarchy")
                    }
                }
                # REFS
                out_list.append(filter_info)
            else:
                filter_info = app.API_MP.get(app.API_MP.url_event_filter_instance.format(item.get("id")))
                if filter_info.state:
                    filter_info = filter_info.message.json()
                    # REFS
                    filter_info["isFolder"] = False
                    filter_info["cli-mixin"] = {
                        "mixin_ref_version": app.MIXIN_REF_VERSION,
                        "kind": "event_filter",
                        "timestamp": str(datetime.datetime.now()),
                        "product": app.API_MP.product,
                        "hierarchy": list_info.get("tree_hierarchy")
                    }
                    out_list.append(filter_info)
                else:
                    return filter_info
            if list_info.get("children"):
                child_list = self.__get_info(lst=list_info.get("children"), progress=progress, task=task,
                                             user_only=user_only)
                if child_list.state:
                    out_list += child_list.message
        return MPAPIResponse(state=True, message=out_list)

    def __get_count(self, lst: list, user_only: bool) -> int:
        """
        Get filters count
        :param lst: filters list
        :param user_only: get only custom filters
        """
        count = 0
        for item in lst:
            # Check filter exist
            list_info = self.get_by_id(filter_id=item.get("id"))
            if not list_info:
                EVENTS.push(action="Resolve", status="Fail",
                            instance="Event filter",
                            name="N/A", instance_id=item.get("id"),
                            details="Unable to get info for event filter with ID {}. Event filter not found."
                            .format(item.get("id")))
                continue
            if (item.get("meta").get("source") == "user" or item.get("meta").get("source") == "shared") and user_only:
                count += 1
            elif not user_only:
                count += 1
            if item.get("children"):
                child_count = self.__get_count(item.get("children"), user_only)
                count += child_count
        return count

    def __load_list(self) -> MPAPIResponse:
        """
        Get event filters list
        """

        def refine(full_list: list, filter_list: list) -> list:
            out_list = []
            for item in filter_list:
                item["tree_hierarchy"] = self.get_hierarchy(filter_id=item.get("id"), filter_list=full_list)
                if item.get("children"):
                    item["children"] = refine(full_list=full_list, filter_list=item.get("children"))
                out_list.append(item)
            return out_list

        self.logger.debug("Trying to load filters list")
        response = app.API_MP.get(app.API_MP.url_event_filter_hierarchy)
        if not response.state:
            self.logger.error("Event filters list load failed: {}".format(response.message))
            return response
        self.logger.debug("Filters list load succeeded")
        filters_list = response.message.json().get("roots")
        refined_list = refine(full_list=filters_list, filter_list=filters_list)
        return MPAPIResponse(state=True, message=refined_list)

    @staticmethod
    def reduce_info(data: dict | list) -> dict | list:
        """
        Event filter info reducer
        """
        if type(data) == list:
            output = []
            for item in data:
                output.append(
                    get_keys_from_dict(item,
                                       ["id", "name", "isRemoved", "source", "pdqlQuery"]))
        else:
            output = get_keys_from_dict(data,
                                        ["id", "name", "isRemoved", "source", "pdqlQuery"])
        return output

    def reduce_list(self, data: dict | list) -> dict | list:
        """
        Filters list reducer
        """
        output = {}
        if type(data) == dict:
            output["name"] = data.get("name")
            output["type"] = data.get("meta").get("source")
            output["id"] = data.get("id")
            if data.get("children"):
                output["__child"] = self.reduce_list(data.get("children"))
        if type(data) == list:
            output = []
            for item in data:
                if not item.get("children"):
                    output.append({
                        "name": item.get("name"),
                        "type": item.get("meta").get("source"),
                        "id": item.get("id")
                    })
                else:
                    output.append({
                        "name": item.get("name"),
                        "type": item.get("meta").get("source"),
                        "id": item.get("id"),
                        "__child": self.reduce_list(item.get("children"))
                    })
        return output
