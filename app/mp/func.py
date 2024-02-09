import datetime
import re

import app
from app.core.func import fnmatch_ext
from app.core.prompt import input_prompt
from rich import print as rich_print


def func_get_id_from_data(data: str | dict | list) -> str | None:
    """
    Get ID string from data
    :param data: data structure
    :return: ID string
    """
    id_pattern = re.compile("[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+")
    data_id = None
    if isinstance(data, str):
        data_id = data
    elif isinstance(data, list) and len(data) > 1:
        if "id" not in data[0]:
            return
        # Look if list contains specs with id and name - then prompt to select. Otherwise, select first
        if "name" in data[0]:
            lst_sel = func_select_list_item(data)
            data_id = lst_sel.get("id")
        else:
            data_id = data[0].get("id")
    elif isinstance(data, list) and len(data) == 1:
        data_id = data[0].get("id")
    elif isinstance(data, dict):
        if "id" in data:
            data_id = data.get("id")
    if not id_pattern.match(data_id):
        return
    return data_id


def func_get_list_ids_from_list(lst: list, out_lst=None) -> list | None:
    """
    Get list of IDs from list
    :param lst: list structure
    :param out_lst: for recursion
    :return: list of IDs
    """
    if out_lst:
        out_list = out_lst
    else:
        out_list = []
    for item in lst:
        if "id" in item:
            out_list.append(item.get("id"))
            if "children" in item:
                if len(item.get("children")) > 0:
                    child_list = func_get_list_ids_from_list(item.get("children"), out_list)
                    if len(child_list) > 0:
                        out_list += child_list
        else:
            continue
    if len(out_list) == 0:
        return
    else:
        return out_list


def func_check_is_id(pattern: str) -> bool:
    """
    Check string is ID
    :param pattern: string
    :return: bool result
    """
    id_pattern = re.compile("[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+")
    if id_pattern.match(pattern):
        return True
    return False


def func_get_list_by_pattern(lst: list, pattern: str) -> list | None:
    """
    Get list element by ID or name
    :param lst: source list
    :param pattern: ID or name string
    :return: list item
    """
    id_pattern = re.compile("[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+")
    out_list = []
    # If pattern is ID
    if id_pattern.match(pattern):
        for item in lst:
            if item.get("id") == pattern:
                out_list.append(item)
    else:
        for item in lst:
            if fnmatch_ext(item.get("name").lower(), pattern.lower()):
                out_list.append(item)
    if len(out_list) == 0:
        return
    else:
        return out_list


def func_get_list_by_pattern_with_childs(lst: list, pattern: str) -> list | None:
    """
    Get list elements with childs by pattern
    :param lst: source list
    :param pattern: string
    :return: list of elements
    """
    id_pattern = re.compile("[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+")
    out_list = []
    # If pattern is ID
    if id_pattern.match(pattern):
        for item in lst:
            if item.get("id") == pattern:
                out_list.append(item)
            if len(item.get("children")) > 0:
                child_list = func_get_list_by_pattern_with_childs(item.get("children"), pattern)
                if child_list:
                    out_list += child_list
    else:
        for item in lst:
            if fnmatch_ext(item.get("name").lower(), pattern.lower()):
                out_list.append(item)
            if len(item.get("children")) > 0:
                child_list = func_get_list_by_pattern_with_childs(item.get("children"), pattern)
                if child_list:
                    out_list += child_list
    if len(out_list) == 0:
        return
    else:
        return out_list


def func_select_list_item(lst: list, namefield=None, woids=False) -> dict | None:
    """
    Select item from list
    :param lst: source list
    :param namefield: field to use as name
    :param woids: without IDs
    :return: selected item
    """
    if not namefield:
        namefield = "name"
    print("Found {} items:".format(len(lst)))
    for index, item in enumerate(lst):
        if not woids:
            print("{}. {} ({})".format(index + 1, item[namefield], item.get("id")))
        else:
            print("{}. {}".format(index + 1, item[namefield]))
    try:
        select = input_prompt("Please select (ENTER for quit): ")
    except KeyboardInterrupt:
        return
    if not select.isdigit():
        return
    if int(select) < 1 or int(select) > len(lst):
        return
    return lst[int(select) - 1]


def func_check_dict_keys(dct: dict, lst: list) -> (bool, str):
    """
    Check list of keys present in dict
    :param dct: target dict
    :param lst: key list
    :return: bool, problem item
    """
    for item in lst:
        if item not in dct:
            return False, item
    return True, "OK"


def func_apply_mixin(data: dict | list, kind: str, params=None) -> dict | list:
    """
    Apply mixin to dict
    :param data: source dict
    :param kind: mixin kind
    :param params: optional params
    :return: out dict
    """
    if not params:
        params = {}
    out_data = data
    if isinstance(data, dict):
        out_data["cli-mixin"] = {
            "mixin_ref_version": app.MIXIN_REF_VERSION,
            "kind": kind,
            "timestamp": str(datetime.datetime.now()),
            "product": app.API_MP.product
        }
        out_data["cli-mixin"] = {**out_data["cli-mixin"], **params}
    if isinstance(data, list):
        for item in out_data:
            item["cli-mixin"] = {
                "mixin_ref_version": app.MIXIN_REF_VERSION,
                "kind": kind,
                "timestamp": str(datetime.datetime.now()),
                "product": app.API_MP.product
            }
            item["cli-mixin"] = {**item["cli-mixin"], **params}
    return out_data


def func_check_mixin(data: dict | list, kind: str, quiet=False, params=None) -> bool:
    """
    Check mixin kind
    :param data: source dict or list of dicts
    :param kind: target kind
    :param quiet: run quiet
    :param params: optional params
    :return: bool
    """
    if not params:
        params = {}
    if isinstance(data, dict):
        if "cli-mixin" not in data:
            if not quiet:
                rich_print("[red]Wrong specification, expecting: {}".format(kind))
                return False
        if data["cli-mixin"].get("mixin_ref_version") != app.MIXIN_REF_VERSION:
            if not quiet:
                rich_print("[red]Wrong cli mixin reference version in "
                           "specification: {}, expecting: {}"
                           .format(data["cli-mixin"]["mixin_ref_version"], app.MIXIN_REF_VERSION))
                return False
        if data["cli-mixin"].get("kind") != kind:
            if not quiet:
                rich_print("[red]Wrong specification kind: {}, expecting: {}"
                           .format(data["cli-mixin"]["kind"], kind))
                return False
        for key, value in params:
            if data["cli-mixin"][key] != value:
                rich_print("Wrong specification mixin parameter: {}={}, expecting: {}"
                           .format(key, data["cli-mixin"][key], value))
                return False
    if isinstance(data, list):
        for item in data:
            if "cli-mixin" not in item:
                if not quiet:
                    rich_print("[red]Wrong specification, expecting: {}".format(kind))
                    return False
            if item["cli-mixin"].get("mixin_ref_version") != app.MIXIN_REF_VERSION:
                if not quiet:
                    rich_print("[red]Wrong cli mixin reference version in "
                               "specification: {}, expecting: {}"
                               .format(item["cli-mixin"]["mixin_ref_version"], app.MIXIN_REF_VERSION))
                    return False
            if item["cli-mixin"].get("kind") != kind:
                if not quiet:
                    rich_print("[red]Wrong specification kind: {}, expecting: {}"
                               .format(item["cli-mixin"]["kind"], kind))
                    return False
            for key, value in params.items():
                if item["cli-mixin"][key] != value:
                    rich_print("Wrong specification mixin parameter: {}={}, expecting: {}"
                               .format(key, item["cli-mixin"][key], value))
                    return False
    return True
