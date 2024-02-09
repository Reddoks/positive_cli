import logging
import re
import datetime

from rich.progress import Progress, TaskID

import app
from app.app import EVENTS
from app.core.func import fnmatch_ext, console_clear_up, get_keys_from_dict, get_string_from_fmt
from app.core.prompt import input_prompt
from app.mp.api import MPAPIResponse
from app.mp.func import (func_apply_mixin)

from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter

class iface_MP_AssetQuery:  # noqa
    def __init__(self, load=True):
        """
        CLI API for Asset Queries
        """
        self.logger = logging.getLogger("mp.asset.iface_query")
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
        Get asset query information
        :param user_only: if True, get only custom queries
        :param pattern: string
        :param lst: queries list
        :param dct: queries dict
        :return: group information
        """
        query_list = None
        if pattern:
            self.logger.debug("Trying to get query info for pattern: {}".format(pattern))
            query_list = self.get_from_list_by_pattern_with_childs(self.list, pattern.lower(), user_only)
            if query_list:
                self.logger.debug("Found {} queries".format(len(query_list)))
                if len(query_list) > 1:
                    query_list = [self.select_list_item(query_list)]
                    if query_list == [False] or query_list == [None]:
                        self.logger.error("No queries found")
                        return MPAPIResponse(state=False, message="No queries found")
            else:
                self.logger.error("No queries found")
                return MPAPIResponse(state=False, message="No queries found")
        # If list
        if lst:
            query_list = lst
        # If dict
        if dct:
            query_list = [dct]
        if query_list:
            with Progress() as progress:
                count = self.__get_count(query_list, user_only)
                task = progress.add_task("Getting asset queries info...", total=count)
                query_info = self.__get_info(query_list, progress, task, user_only)
                if query_info.state:
                    query_info = query_info.message
                else:
                    return query_info
            console_clear_up(skip_line=True)
            if len(query_info) == 0:
                self.logger.error("No queries found")
                return MPAPIResponse(state=False, message="No queries found")
            #query_info = func_apply_mixin(query_info, "query")
            return MPAPIResponse(state=True, message=query_info)
        else:
            self.logger.error("No queries found")
            return MPAPIResponse(state=False, message="No queries found")

    def create(self, raw_spec: dict, disarm=True) -> MPAPIResponse:
        """
        Create asset query from specification
        :param raw_spec: specification structure
        :param disarm: run in test mode
        :return:
        """
        self.logger.debug("Trying to create asset query from specification")
        # Reload group list
        response = self.__load_list()
        if not response.state:
            EVENTS.push(status="Fail", action="Create", instance="Query",
                        name=raw_spec["displayName"], instance_id="N/A",
                        details="MP Task asset query API initialization failed: {}".format(response.message))
            return response
        self.list = response.message
        response = self.__create_from_spec(raw_spec, disarm)
        return response

    def delete(self, query_id: str, is_folder=False, disarm=True) -> MPAPIResponse:
        """
        Delete asset query
        :param query_id: string ID
        :param is_folder: flag for type
        :param disarm: run in test mode
        """
        self.logger.debug("Trying to delete query {}".format(query_id))
        print("Trying to delete query {}".format(query_id))
        if not app.app.GLOBAL_DISARM and not disarm:
            if not is_folder:
                response = app.API_MP.delete(app.API_MP.url_asset_query + '/queries/{}'.format(query_id),
                                             data={})
            else:
                response = app.API_MP.delete(app.API_MP.url_asset_query + '/folders/queries/{}'.format(query_id),
                                             data={})
        else:
            print("Success - disarmed")
            return MPAPIResponse(state=True, message="Success - disarmed")
        if not response.state:
            EVENTS.push(status="Fail", action="Delete", instance="Asset queue",
                        name="N/A", instance_id=query_id,
                        details=response.message)
            self.logger.error("Asset query API response failed. Can`t delete")
            self.logger.error(response.message)
            return response
        self.logger.debug("Asset query {} successfully deleted".format(query_id))
        return MPAPIResponse(state=True, message="Asset query {} successfully deleted".format(query_id))

    def get_query_picker(self, prompt_string: str) -> MPAPIResponse:
        """
        Query selection dialog with autocompletion
        :param prompt_string: prompt for dialog
        """
        query_name, query_hierarchy, query_ids = self.__get_plain_hierarchy()
        query_completer = WordCompleter(query_hierarchy, sentence=True)
        while True:
            try:
                query_input = prompt(prompt_string, completer=query_completer, complete_while_typing=True)
            except KeyboardInterrupt:
                return MPAPIResponse(state=False, message="Operation interrupted")
            if query_input == "":
                return MPAPIResponse(state=False, message="Skip group enter")
            if query_input == "?":
                print("Available queries:")
                print(get_string_from_fmt(query_hierarchy, fmt="yaml"))
                continue
            if "*" in query_input:
                print("Available queries:")
                for item in query_hierarchy:
                    if fnmatch_ext(item, query_hierarchy):
                        print("- {}".format(item))
                continue
            for idx in range(0, len(query_hierarchy)):
                print(query_hierarchy[idx])
                print(query_input)
                if query_hierarchy[idx] == query_input:
                    return MPAPIResponse(state=True, message={"name": query_name[idx],
                                                              "hierarchy": " \ ".join(["Root", query_hierarchy[idx]]),
                                                              # noqa
                                                              "id": query_ids[idx]})
            print("Wrong query")

    def get_by_id(self, query_id: str, query_list=None) -> dict | None:
        """
        Get query by ID
        :param query_id: string ID
        :param query_list: used for recursion
        :return: query structure
        """
        if not query_list:
            query_list = self.list
        for item in query_list:
            if item.get("id") == query_id:
                return item
            else:
                if item.get("children"):
                    child_queries = self.get_by_id(query_id, item.get("children"))
                    if child_queries:
                        return child_queries
        return

    def get_by_hierarchy(self, hierarchy: list, queries=None) -> dict | None:
        """
        Get query by tree hierarchy
        :param hierarchy: tree hierarchy structure
        :param queries: used for recursion
        :return: asset query item
        """
        if not queries:
            queries = self.list
        for item in queries:
            if "tree_hierarchy" in item:
                if item.get("tree_hierarchy") == hierarchy:
                    return item
                else:
                    if item.get("children"):
                        child_queries = self.get_by_hierarchy(hierarchy, item.get("children"))
                        if child_queries:
                            return child_queries
            else:
                if item.get("children"):
                    child_queries = self.get_by_hierarchy(hierarchy, item.get("children"))
                    if child_queries:
                        return child_queries
        return

    @staticmethod
    def get_selection_pdql(sel_id: str) -> dict | None:
        """
        Get selection PDQL by ID
        :param sel_id: string ID
        :return: PDQL string
        """
        selection_info = app.API_MP.get(app.API_MP.url_asset_query + '/selections/{}'.format(sel_id))
        if selection_info.state:
            return selection_info.message.json().get("pdql")

    @staticmethod
    def get_filter_pdql(fil_id: str) -> dict | None:
        """
        Get filter PDQL by ID
        :param fil_id: string ID
        :return: PDQL string
        """
        filter_info = app.API_MP.get(app.API_MP.url_asset_query + '/filters/{}'.format(fil_id))
        if filter_info.state:
            return filter_info.message.json().get("pdql")

    def get_by_name_from_parent_root(self, name: str, parent_id: str) -> dict | None:
        """
        Get query from defined root level
        :param name: string
        :param parent_id: Root level query ID
        :return: asset query item
        """
        parent_query = self.get_by_id(parent_id)
        for item in parent_query.get("children"):
            if item.get("displayName") == name:
                return item
        return

    def get_by_pattern(self, pattern: str, lst=None) -> list | None:
        """
        Get query by name or ID
        :param pattern: string with name or ID
        :param lst: used for recursion
        :return: asset query item
        """
        id_pattern1 = re.compile("([A-Za-z0-9]+(-[A-Za-z0-9]+)+)_root")
        id_pattern2 = re.compile("[A-Za-z0-9]+")
        out_list = []
        if not lst:
            lst = self.list
        # If pattern is ID
        if id_pattern1.match(pattern) or (id_pattern2.match(pattern) and len(pattern) == 32):
            for item in lst:
                if item.get("id") == pattern:
                    out_list.append(item)
                if item.get("children"):
                    child_list = self.get_by_pattern(pattern=pattern, lst=item.get("children"))
                    if child_list:
                        out_list += child_list
        else:
            for item in lst:
                if fnmatch_ext(item.get("displayName", "").lower(), pattern.lower()):
                    out_list.append(item)
                if item.get("children"):
                    child_list = self.get_by_pattern(pattern=pattern, lst=item.get("children"))
                    if child_list:
                        out_list += child_list
        if len(out_list) == 0:
            return
        else:
            return out_list

    def get_from_list_by_pattern_with_childs(self, lst: list, pattern: str, user_only: bool) -> list | None:
        """
        Get queries plain list by pattern
        :param lst: queries list
        :param pattern: string
        :param user_only: flag - get only user objects
        :return: query list
        """
        id_pattern1 = re.compile("([A-Za-z0-9]+(-[A-Za-z0-9]+)+)_root")
        id_pattern2 = re.compile("[A-Za-z0-9]+")
        out_list = []
        # If pattern is ID
        if id_pattern1.match(pattern) or (id_pattern2.match(pattern) and len(pattern) == 32):
            for item in lst:
                if user_only and item.get("type") != "user" and item.get("type") != "common":
                    continue
                if item.get("id") == pattern:
                    out_list.append(item)
                if item.get("children"):
                    child_list = self.get_from_list_by_pattern_with_childs(item.get("children"), pattern, user_only)
                    if child_list:
                        out_list += child_list
        else:
            for item in lst:
                if user_only and item.get("type") != "user" and item.get("type") != "common":
                    continue
                if fnmatch_ext(item.get("displayName", "").lower(), pattern.lower()):
                    out_list.append(item)
                if item.get("children"):
                    child_list = self.get_from_list_by_pattern_with_childs(item.get("children"), pattern, user_only)
                    if child_list:
                        out_list += child_list
        if len(out_list) == 0:
            return
        else:
            return out_list

    def get_hierarchy(self, query_id: str, query_list=None) -> list | None:
        """
        Calculate asset query hierarchy in query tree
        :param query_id:
        :param query_list:
        """
        if not query_list:
            query_list = self.list
        for item in query_list:
            hierarchy_tmp = [item["displayName"]]
            if item.get("id") == query_id:
                return hierarchy_tmp
            if item.get("children"):
                child_hierarchy = self.get_hierarchy(query_id=query_id, query_list=item.get("children"))
                if child_hierarchy:
                    hierarchy_tmp += child_hierarchy
                    return hierarchy_tmp
        return

    @staticmethod
    def remove_childs(group_list: list) -> list:
        """
        Get list of asset queries without child queries
        :param group_list: list of queries with childs
        :return: list of queries without childs
        """
        out_list = []
        for item in group_list:
            # Deprecation block
            if "tree_hierarchy" in item:
                if len(item["tree_hierarchy"]) == 1:
                    continue
            else:
                if len(item["cli-mixin"]["hierarchy"]) == 1:
                    continue
            # End deprecation
            parent_is_present = False
            for itm in group_list:
                # Deprecation block
                if "tree_hierarchy" in item:
                    if len(itm["tree_hierarchy"]) == 1:
                        continue
                else:
                    if len(item["cli-mixin"]["hierarchy"]) == 1:
                        continue
                # End deprecation
                if item.get("parentId"):
                    if itm.get("id") == item.get("parentId"):
                        parent_is_present = True
                if item.get("folderId"):
                    if itm.get("id") == item.get("folderId"):
                        parent_is_present = True
            if not parent_is_present:
                out_list.append(item)
        return out_list

    def remove_builtin(self, lst: list) -> list:
        """
        Remove built-in queries from list
        :param lst: source list
        """
        output = []
        for item in lst:
            if item.get("type") == "user" or item.get("type") == "common":
                output.append(item)
                continue
            if item.get("children"):
                child_items = self.remove_builtin(item.get("children"))
                output += child_items
        return output

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
                print("{}. {} ({})".format(index + 1, item.get("displayName"), item.get("id")))
            else:
                print("{}. {}".format(index + 1, item.get("displayName")))
        try:
            select = input_prompt("Please select (ENTER for quit): ")
        except KeyboardInterrupt:
            return
        if not select.isdigit():
            return
        if int(select) < 1 or int(select) > len(lst):
            return
        return lst[int(select) - 1]

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
                id_pattern1 = re.compile("([A-Za-z0-9]+(-[A-Za-z0-9]+)+)_root")
                id_pattern2 = re.compile("[A-Za-z0-9]+")
                if re.match(id_pattern1, struct) or re.match(id_pattern2, struct):
                    hierarchy = self.get_hierarchy(query_id=struct)
                    if hierarchy and struct != spec.get("id"):
                        return [{"id": struct, "kind": "query", "hierarchy": hierarchy}]
                return

        out_list = []
        for key, value in spec.items():
            inst = lookup_in_key(value)
            if inst:
                out_list += inst
        out_list = build_originals(out_list)
        return MPAPIResponse(state=True, message=out_list)

    def reload(self):
        """
        Reload query list
        """
        self.list = self.__load_list()

    def __create_folder(self, spec: dict, parent_id: str, disarm: bool) -> MPAPIResponse:
        """
        Create query folder
        :param spec: specification structure
        :param parent_id: parent query ID
        :param disarm: run in test mode
        """
        # Check folder is existed on parent level
        exist = self.get_by_name_from_parent_root(name=spec.get("displayName"), parent_id=parent_id)
        if exist:
            self.logger.error("Query folder {} exist. Can`t create".format(spec.get("displayName")))
            return MPAPIResponse(state=False,
                                 message="Query folder {} exist. Can`t create".format(spec.get("displayName")))
        spec["parentId"] = parent_id
        if not app.app.GLOBAL_DISARM and not disarm:
            response = app.API_MP.post(app.API_MP.url_asset_query + '/folders/queries', spec)
        else:
            print("Success - disarmed")
            return MPAPIResponse(state=True, message="Success - disarmed")
        if not response.state:
            return response
        self.logger.debug("Asset query folder {} successfully created".format(response.message.json().get("id")))
        return MPAPIResponse(state=True, message="Asset query folder {} created".format(spec.get("displayName")))

    def __create_query(self, spec: dict, parent_id: str, disarm: bool) -> MPAPIResponse:
        """
        Create query
        :param spec: specification structure
        :param parent_id: parent query ID
        :param disarm: run in test mode
        """
        # Check query is existed on parent level
        exist = self.get_by_name_from_parent_root(name=spec.get("displayName"), parent_id=parent_id)
        if exist:
            self.logger.error("Query {} exist. Can`t create".format(spec.get("displayName")))
            return MPAPIResponse(state=False,
                                 message="Query {} exist. Can`t create".format(spec.get("displayName")))
        spec["folderId"] = parent_id
        if not app.app.GLOBAL_DISARM and not disarm:
            response = app.API_MP.post(app.API_MP.url_asset_query + '/queries', spec)
        else:
            print("Success - disarmed")
            return MPAPIResponse(state=True, message="Success - disarmed")
        if not response.state:
            return response
        self.logger.debug("Asset query {} successfully created".format(response.message.json().get("id")))
        return MPAPIResponse(state=True, message="Asset query {} created".format(spec.get("displayName")))

    def __create_from_spec(self, raw_spec: dict, disarm: bool) -> MPAPIResponse:
        """
        Create query from specification
        :param raw_spec: specification structure
        :param disarm: run in test mode
        """
        if raw_spec.get("type") == "standard":
            return MPAPIResponse(state=False,
                                 message="Query {} is built-in query. Skip".format(raw_spec.get("displayName")))
        # Deprecation block
        # Support old-styled specifications (will be deprecated)
        if "tree_hierarchy" in raw_spec:
            if len(raw_spec["tree_hierarchy"]) == 1:
                return MPAPIResponse(state=False,
                                     message="Query {} is top root. Skip".format(raw_spec.get("displayName")))
            parent_hierarchy = raw_spec["tree_hierarchy"][:-1]
        else:
            if len(raw_spec["cli-mixin"]["hierarchy"]) == 1:
                return MPAPIResponse(state=False,
                                     message="Query {} is top root. Skip".format(raw_spec.get("displayName")))
            parent_hierarchy = raw_spec["cli-mixin"]["hierarchy"][:-1]
        # End deprecation block
        parent = self.get_by_hierarchy(hierarchy=parent_hierarchy)
        if not parent:
            EVENTS.push(status="Fail", action="Create", instance="Query folder",
                        name=raw_spec.get("displayName"), instance_id="N/A",
                        details="Unable to resolve parent folder: {}".format(parent_hierarchy))
            return MPAPIResponse(state=False,
                                 message="Unable to resolve parent folder: {}".format(parent_hierarchy))
        if raw_spec["isFolder"]:
            response = self.__create_folder(raw_spec, parent.get("id"), disarm)
        else:
            response = self.__create_query(raw_spec, parent.get("id"), disarm)
        return response

    def __get_plain_hierarchy(self, lst=None) -> [list, list, list]:
        """
        Get plain lists with queries hierarchy
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
            out_names.append(item.get("displayName"))
            if item.get("children"):
                if len(item["children"]) > 0:
                    child_names, child_hierarchy, child_ids = self.__get_plain_hierarchy(lst=item.get("children"))
                    if child_hierarchy:
                        out_hierarchy += child_hierarchy
                        out_ids += child_ids
                        out_names += child_names
        return out_names, out_hierarchy, out_ids

    def __get_info(self, lst: list, progress: Progress, task: TaskID, user_only: bool) -> MPAPIResponse:
        """
        Get query information
        :param lst: query list
        :param progress: progress object
        :param task: progress task object
        :param user_only: get only custom queries
        :return: query item
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
            list_info = self.get_by_id(query_id=item.get("id"))
            if user_only and list_info.get("type") != "user" and list_info.get("type") != "common":
                continue
            # If instance is folder
            if list_info["isFolder"]:
                query_info = {
                    "id": list_info.get("id"),
                    "displayName": list_info.get("displayName"),
                    "parentId": list_info.get("parentId"),
                    "type": list_info.get("type"),
                    "isFolder": True,
                    "cli-mixin": {
                        "mixin_ref_version": app.MIXIN_REF_VERSION,
                        "kind": "query",
                        "timestamp": str(datetime.datetime.now()),
                        "product": app.API_MP.product,
                        "hierarchy": list_info.get("tree_hierarchy")
                    }
                }
                refs = id_refs.get_references(query_info)
                if not refs.state:
                    return refs
                query_info["cli-mixin"]["references_id"] = refs.message
                out_list.append(query_info)
            else:
                query_info = app.API_MP.get(app.API_MP.url_asset_query_instance.format(item.get("id")))
                if query_info.state:
                    query_info = query_info.message.json()
                    #if query_info.get("parentId"):
                    #    parent_list_info = self.get_by_id(query_id=query_info.get("parentId"))
                    #else:
                    #    parent_list_info = None
                    #if parent_list_info:
                    #    query_info["parentName"] = parent_list_info.get("displayName")
                    #query_info["tree_hierarchy"] = list_info.get("tree_hierarchy")
                    query_info["isFolder"] = False
                    refs = id_refs.get_references(query_info)
                    if not refs.state:
                        return refs
                    query_info["cli-mixin"] = {
                        "mixin_ref_version": app.MIXIN_REF_VERSION,
                        "kind": "query",
                        "timestamp": str(datetime.datetime.now()),
                        "product": app.API_MP.product,
                        "hierarchy": list_info.get("tree_hierarchy"),
                        "references_id": refs.message
                    }
                    # If user or common - resolve selection and filter
                    if list_info.get("type") == "user" or list_info.get("type") == "common":
                        if query_info.get("filterId"):
                            filter_pdql = self.get_filter_pdql(query_info.get("filterId"))
                            if not filter_pdql:
                                EVENTS.push(status="Fail", action="Resolve", instance="Filter",
                                            name="N/A", instance_id=query_info.get("filterId"),
                                            details="Unable to resolve filter "
                                                    "for query: {}".format(query_info.get("displayName")))
                            else:
                                query_info["filterId"] = None
                                query_info["filterPdql"] = filter_pdql
                        if query_info.get("selectionId"):
                            selection_pdql = self.get_selection_pdql(query_info.get("selectionId"))
                            if not selection_pdql:
                                EVENTS.push(status="Fail", action="Resolve", instance="Selection",
                                            name="N/A", instance_id=query_info.get["selectionId"],
                                            details="Unable to resolve selection"
                                                    " for query: {}".format(query_info.get("displayName")))
                            else:
                                query_info["selectionId"] = None
                                query_info["selectionPdql"] = selection_pdql
                    out_list.append(query_info)
                else:
                    return query_info
            if list_info.get("children"):
                child_list = self.__get_info(lst=list_info.get("children"), progress=progress, task=task,
                                             user_only=user_only)
                if child_list.state:
                    out_list += child_list.message
        return MPAPIResponse(state=True, message=out_list)

    def __get_count(self, lst: list, user_only: bool) -> int:
        """
        Get queries count
        :param lst: queries list
        :param user_only: get only custom queries
        :return: number
        """
        count = 0
        for item in lst:
            if (item.get("type") == "user" or item.get("type") == "common") and user_only:
                count += 1
            elif not user_only:
                count += 1
            if item.get("children"):
                child_count = self.__get_count(item.get("children"), user_only)
                count += child_count
        return count

    def __load_list(self) -> MPAPIResponse:
        """
        Load queries list
        """

        def refine(query_api: iface_MP_AssetQuery, full_list: list, qry_list: list) -> list:
            out_list = []
            for item in qry_list:
                item["tree_hierarchy"] = query_api.get_hierarchy(query_id=item.get("id"), query_list=full_list)
                if item.get("children"):
                    item["children"] = refine(query_api=query_api, full_list=full_list,
                                              qry_list=item.get("children"))
                out_list.append(item)
            return out_list

        self.logger.debug("Trying to load queries list")
        response = app.API_MP.get(app.API_MP.url_asset_query_folders_queries)
        if not response.state:
            self.logger.error("Queries list load failed: {}".format(response.message))
            return response
        self.logger.debug("Queries list load succeeded")
        queries_list = response.message.json().get("nodes")
        refined_list = refine(query_api=self, full_list=queries_list, qry_list=queries_list)
        return MPAPIResponse(state=True, message=refined_list)

    @staticmethod
    def reduce_info(data: dict | list) -> dict | list:
        """
        Queries info reducer
        """
        if type(data) == list:
            output = []
            for item in data:
                output.append(
                    get_keys_from_dict(item,
                                       ["id", "displayName", "filterPdql", "selectionPdql", "inInvalid", "type"]))
        else:
            output = get_keys_from_dict(data,
                                        ["id", "displayName", "filterPdql", "selectionPdql", "inInvalid", "type"])
        return output

    def reduce_list(self, data: dict | list) -> dict | list:
        """
        Queries list reducer
        """
        output = {}
        if type(data) == dict:
            output["name"] = data.get("displayName")
            output["type"] = data.get("type")
            output["id"] = data.get("id")
            if data.get("children"):
                output["__child"] = self.reduce_list(data.get("children"))
        if type(data) == list:
            output = []
            for item in data:
                if not item.get("children"):
                    output.append({
                        "name": item.get("displayName"),
                        "type": item.get("type"),
                        "id": item.get("id")
                    })
                else:
                    output.append({
                        "name": item.get("displayName"),
                        "type": item.get("type"),
                        "id": item.get("id"),
                        "__child": self.reduce_list(item.get("children"))
                    })
        return output
