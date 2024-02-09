import logging
import re

from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter

import app
from app.core.func import fnmatch_ext, get_string_from_fmt
from app.mp.api import MPAPIResponse


class iface_MP_Site:  # noqa
    def __init__(self, load=True):
        """
        Interface for sites
        :param load: if false - do not load user list
        """
        self.logger = logging.getLogger("mp.iface_site")
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

    def get_site_picker(self, prompt_string: str) -> MPAPIResponse:
        """
        Site selection dialog with autocompletion
        :param prompt_string: prompt for dialog
        """
        # Build plain site list based on hierarchy
        sites_name, sites_hierarchy, sites_ids = self.__get_plain_hierarchy()
        sites_completer = WordCompleter(sites_hierarchy, sentence=True)
        while True:
            try:
                site_input = prompt(prompt_string, completer=sites_completer, complete_while_typing=True)
            except KeyboardInterrupt:
                return MPAPIResponse(state=False, message="Operation interrupted")
            if site_input == "":
                return MPAPIResponse(state=False, message="Skip site enter")
            if site_input == "?":
                print("Available sites:")
                print(get_string_from_fmt(sites_hierarchy, fmt="yaml"))
                continue
            if "*" in site_input:
                print("Available sites:")
                for item in sites_hierarchy:
                    if fnmatch_ext(item, sites_hierarchy):
                        print("- {}".format(item))
                continue
            for idx in range(0, len(sites_hierarchy)):
                if sites_hierarchy[idx] == site_input:
                    return MPAPIResponse(state=True, message={"name": sites_name[idx],
                                                              "hierarchy": " \ ".join(sites_hierarchy[idx]),
                                                              # noqa
                                                              "id": sites_ids[idx]})
            print("Wrong group")

    def get_by_id(self, site_id: str, site_list=None) -> dict | None:
        """
        Get site by ID
        :param site_id: string ID
        :param site_list: used for recursion
        """
        if not site_list:
            site_list = self.list
        for item in site_list:
            if item.get("id") == site_id:
                return item
            else:
                if item.get("children"):
                    child_sites = self.get_by_id(site_id, item.get("children"))
                    if child_sites:
                        return child_sites
        return

    def get_by_pattern(self, pattern: str, lst=None) -> list | None:
        """
        Get site by name or ID
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

    def get_by_hierarchy(self, hierarchy: list, sites=None) -> dict | None:
        """
        Get site by tree hierarchy
        :param hierarchy: tree hierarchy structure
        :param sites: used for recursion
        """
        if not sites:
            sites = self.list
        for item in sites:
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

    def get_hierarchy(self, site_id: str, sites_list=None) -> list | None:
        """
        Calculate asset query hierarchy in query tree
        :param site_id:
        :param sites_list:
        """
        if not sites_list:
            sites_list = self.list
        for item in sites_list:
            hierarchy_tmp = [item["name"]]
            if item.get("id") == site_id:
                return hierarchy_tmp
            if item.get("children"):
                child_hierarchy = self.get_hierarchy(site_id=site_id, sites_list=item.get("children"))
                if child_hierarchy:
                    hierarchy_tmp += child_hierarchy
                    return hierarchy_tmp
        return

    def __get_plain_hierarchy(self, lst=None) -> [list, list, list]:
        """
        Get plain lists with sites hierarchy
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

    def get_reference(self, spec: dict) -> MPAPIResponse:
        """
        Look instance for site IDs and return reference
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
                    hierarchy = self.get_hierarchy(site_id=struct)
                    if hierarchy and struct != spec.get("id"):
                        return [{"id": struct, "kind": "site", "hierarchy": hierarchy}]
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
        Load sites hierarchy
        """

        def refine(site_api, full_list: list, site_list: list) -> list:
            out_list = []
            for item in site_list:
                item["tree_hierarchy"] = self.get_hierarchy(site_id=item.get("id"), sites_list=full_list)
                if item.get("children"):
                    item["children"] = refine(site_api=site_api, full_list=full_list,
                                              site_list=item.get("children"))
                out_list.append(item)
            return out_list

        self.logger.debug("Trying to load sites hierarchy")
        # Load templates list
        response = app.API_MP.get(app.API_MP.url_site)
        if not response.state:
            self.logger.error("Sites hierarchy load failed: {}".format(response.message))
            return response
        self.logger.debug("Sites hierarchy load succeeded")
        sites_list = response.message.json()
        refined_list = refine(site_api=self, full_list=[sites_list], site_list=[sites_list])
        return MPAPIResponse(state=True, message=refined_list)
