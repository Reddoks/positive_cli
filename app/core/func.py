import copy
import csv
import fnmatch
import io
import json
import logging
import os
import re
import sys

from rich.console import Console
from rich.table import Table
from rich.tree import Tree
from rich import print as rich_print
from yaml import dump


try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper
Dumper.ignore_aliases = lambda *args: True


def fmt_std_output(command_context) -> None:
    """
    Standard console output with format
    """
    from app.core.command import BlockContextData
    from app.app import EVENTS
    # If None
    if not command_context or (not command_context.context_data and not command_context.state_msg):
        return
    # If failed status
    if not command_context.state:
        output = "[red]{}".format(command_context.state_msg)
        rich_print(output)
        EVENTS.checkout()
        return
    elif not command_context.context_data:
        output = command_context.state_msg
    else:
        # Process BlockContext
        if isinstance(command_context.context_data, BlockContextData):
            # count = command_context.context_data.count()
            block = command_context.context_data.block(offset=0, limit=15)
            output = get_string_from_fmt(data=block, fmt=command_context.data_fmt,
                                         transform=command_context.data_transform,
                                         is_transform_list=command_context.data_islist_transform,
                                         force_transform=command_context.force_transform,
                                         table_transform=command_context.table_transform)
            print(output)
            return
        output = get_string_from_fmt(data=command_context.context_data, fmt=command_context.data_fmt,
                                     transform=command_context.data_transform,
                                     is_transform_list=command_context.data_islist_transform,
                                     force_transform=command_context.force_transform,
                                     table_transform=command_context.table_transform)
    print(output)


def paged_std_output(command_context) -> None:
    """
    Paged console output with format
    """
    # If None
    if not command_context or (not command_context.context_data and not command_context.state_msg):
        return
    if not command_context.state:
        output = command_context.state_msg
    else:
        output = get_string_from_fmt(data=command_context.context_data, fmt=command_context.data_fmt,
                                     transform=command_context.data_transform,
                                     is_transform_list=command_context.data_islist_transform,
                                     table_transform=command_context.table_transform)
    num_lines = os.get_terminal_size().lines - 1
    for index, line in enumerate(output.split('\n')):
        if index % num_lines == 0 and index:
            try:
                input_key = input("\nHit ENTER to continue press q to quit: ")
                if input_key.lower() == 'q':
                    return
                console_clear_up(skip_line=True)
                console_clear_up(only_up=True)
            except KeyboardInterrupt:
                console_clear_up()
                return
            print(line.rstrip())
        else:
            if line:
                print(line.rstrip())


def search_in_object(obj: list | dict | str, pattern: any, kind="plain", typ="value") -> list | dict | str | None:
    """
    Search in objects
    :param obj: can be list/dict/string structure
    :param pattern: search pattern according to fnmatch: name*, *name*, ...
    :param kind: plain (normal structures) or tree (nested structures)
    :param typ: value or key
    :return: structure
    """
    output = []
    if kind == "tree":
        if typ == "value":
            return find_in_tree(obj, pattern)
        else:
            return find_in_tree_keys(obj, pattern)
    if typ == "value":
        # If obj is list
        if isinstance(obj, list):
            return find_in_list(obj, pattern)
        # If obj is dict
        if isinstance(obj, dict):
            # Look in dict keys:
            return find_in_dict(obj, pattern)
    else:
        # If obj is list
        if isinstance(obj, list):
            return find_in_list_keys(obj, pattern)
        # If obj is dict
        if isinstance(obj, dict):
            # Look in dict keys:
            return find_in_dict_keys(obj, pattern)
    if isinstance(obj, str):
        string_split = obj.split('\n')
        output = []
        for item in string_split:
            if fnmatch_ext(str(item).lower(), str(pattern).lower()):
                output.append(item)
        return output
    if fnmatch_ext(str(obj).lower(), str(pattern).lower()):
        return obj
    return output


def find_in_dict(data: dict | list, pattern: any) -> dict | list | None:
    """
    Recursive search in dict
    :param data: dict structure
    :param pattern: pattern string
    :return: structure
    """
    for key, value in data.items():
        if isinstance(value, dict):
            in_child = find_in_dict(value, pattern)
            if in_child:
                return data
        if isinstance(value, list):
            in_child = find_in_list(value, pattern)
            if in_child:
                if len(in_child) > 0:
                    return data
        if fnmatch_ext(str(value).lower(), str(pattern).lower()):
            return data


def find_in_dict_keys(data: dict | list, pattern: str) -> dict | list | None:
    """
    Recursive search in dict keys
    :param data: dict structure
    :param pattern: pattern string
    :return: structure
    """
    output = []
    for key, value in data.items():
        if isinstance(value, dict):
            in_child = find_in_dict_keys(value, pattern)
            if in_child:
                output += in_child
        if isinstance(value, list):
            in_child = find_in_list_keys(value, pattern)
            if in_child:
                output += in_child
        if fnmatch_ext(str(key).lower(), pattern.lower()):
            output.append(value)
            break
    return output


def find_in_list(data: list, pattern: any) -> list | None:
    """
    Recursive search in list
    :param data: list structure
    :param pattern: pattern string
    :return: structure
    """
    output = []
    for item in data:
        # If list item is dict
        if isinstance(item, dict):
            for key, value in item.items():
                if isinstance(value, dict):
                    in_child = find_in_dict(value, pattern)
                    if in_child:
                        output.append(item)
                        break
                if isinstance(value, list):
                    in_child = find_in_list(value, pattern)
                    if in_child:
                        output.append(item)
                        break
                if fnmatch_ext(str(value).lower(), str(pattern).lower()):
                    output.append(item)
                    break
        # if list item is list
        if isinstance(item, list):
            in_child = find_in_list(item, pattern)
            if in_child:
                output.append(item)
        # If list item is something else
        if fnmatch_ext(str(item).lower(), str(pattern).lower()):
            output.append(item)
    return output


def find_in_list_keys(data: dict | list, pattern: str) -> list | None:
    """
    Recursive search in list keys
    :param data: list structure
    :param pattern: pattern string
    :return: structure
    """
    output = []
    for item in data:
        # If list item is dict
        if isinstance(item, dict):
            in_child = find_in_dict_keys(item, pattern)
            if in_child:
                output += in_child
        # if list item is list
        if isinstance(item, list):
            in_child = find_in_list_keys(item, pattern)
            if in_child:
                output += in_child
        # If list item is something else
        if fnmatch_ext(str(item).lower(), pattern.lower()):
            output.append(item)
    return output


def find_in_tree(data: dict | list, pattern: any) -> list | None:
    """
    Recursive search in tree
    :param data: data structure
    :param pattern: pattern string
    :return: structure
    """
    output = []
    if isinstance(data, dict):
        # Look in all key except children
        in_parent = False
        for key, value in data.items():
            if key != "children" and key != "treePath" and fnmatch_ext(str(value).lower(), str(pattern).lower()):
                output.append(data)
                in_parent = True
                break
        # Look in children
        if data.get("children"):
            if len(data.get("children")) > 0 and not in_parent:
                child_out = find_in_tree(data.get("children"), pattern)
                output += child_out
    if isinstance(data, list):
        for item in data:
            in_parent = False
            # Look in all key except children
            for key, value in item.items():
                if key != "children" and key != "treePath" and fnmatch_ext(str(value).lower(), str(pattern).lower()):
                    output.append(item)
                    in_parent = True
                    break
            # Look in children
            if item.get("children"):
                if len(item.get("children")) > 0 and not in_parent:
                    child_out = find_in_tree(item.get("children"), pattern)
                    output += child_out
    return output


def find_in_tree_keys(data: dict | list, pattern: str) -> list | None:
    """
    Recursive search in tree keys
    :param data: tree structure
    :param pattern: pattern string
    :return: structure
    """
    output = []
    if isinstance(data, dict):
        for key, value in data.items():
            if key != "children" and fnmatch_ext(key.lower(), pattern.lower()):
                output.append(value)
            if key == "children":
                child_result = find_in_tree_keys(data["children"], pattern)
                if child_result:
                    output += child_result
        return output
    if isinstance(data, list):
        for item in data:
            for key, value in item.items():
                if key != "children" and key != "treePath" and fnmatch_ext(key.lower(), pattern.lower()):
                    output.append(value)
                if key == "children":
                    child_result = find_in_tree_keys(item["children"], pattern)
                    if child_result:
                        output += child_result
        return output
    if fnmatch_ext(str(data).lower(), pattern.lower()):
        output.append(data)
    return output


def get_tree_output(data: dict | list, tree: Tree) -> None:
    """
    Assemble tree object for output
    """
    if isinstance(data, dict):
        branch = tree.add("Name: {} Type: {} ({})".format(data.get("name"), data.get("type"), data.get("id")))
        if data.get("__child"):
            get_tree_output(data.get("__child"), branch)
    if isinstance(data, list):
        for item in data:
            get_tree_output(item, tree)


def get_string_from_fmt(data: dict | list, fmt: str, transform=None, is_transform_list=False, force_transform=False,
                        table_transform=False) -> str:
    """
    Get formatted string from data with format
    :param data: data structure
    :param fmt: format type: json/yaml/table/tree/csv
    :param transform: data transform function
    :param is_transform_list: list transform flag
    :param force_transform: force transform flag
    :param table_transform: transform when table only
    :return: string
    """
    output = ""
    data_tmp = copy.deepcopy(data)
    if transform and not table_transform:
        if is_transform_list:
            data_tmp = []
            for item in data:
                data_tmp.append(transform(item))
        else:
            data_tmp = transform(data_tmp)
    match fmt:
        case "tree":
            if not isinstance(data_tmp, dict) and not isinstance(data_tmp, list):
                return "Error format output: Wrong data type - expecting dict or list, got {}".format(type(data_tmp))
            tree = Tree("Tree:")
            get_tree_output(data_tmp, tree)
            console = Console(safe_box=True, legacy_windows=True, color_system="windows", force_terminal=True)
            with console.capture() as capture:
                console.print(tree)
            output = capture.get()
        case "table":
            if table_transform:
                if is_transform_list:
                    data_tmp = []
                    for item in data:
                        data_tmp.append(transform(item))
                else:
                    data_tmp = transform(data_tmp)
            if not isinstance(data_tmp, list):
                return "Error format output: Wrong data type - expecting list, got {}".format(type(data_tmp))
            if len(data_tmp) == 0:
                return "Data is empty"
            if not isinstance(data_tmp[0], dict):
                return ("Error format output: Wrong data type - expecting list of dicts, "
                        "got {} in list").format(type(data_tmp[0]))
            headers, rows = get_tabulate_from_dict(data_tmp)
            table = Table(safe_box=True, header_style="")
            for idx in range(0, len(headers)):
                table.add_column(headers[idx])
            for idx in range(0, len(rows)):
                for i in range(0, len(rows[idx])):
                    rows[idx][i] = str(rows[idx][i])
                table.add_row(*rows[idx])
            console = Console(safe_box=True, legacy_windows=True, color_system="windows", force_terminal=True)
            with console.capture() as capture:
                console.print(table)
            output = capture.get()
        case "json":
            try:
                if force_transform:
                    output = json.dumps(data_tmp, indent=2, ensure_ascii=False)
                else:
                    output = json.dumps(data, indent=2, ensure_ascii=False)
            except BaseException as err:
                return "Unable to parse JSON: {}".format(err)
        case "yaml":
            if not isinstance(data, list) and not isinstance(data, dict):
                return "Error format output: Wrong data type - expecting list or dict, got {}".format(type(data))
            if force_transform:
                output = dump(data_tmp, Dumper=Dumper, sort_keys=False, allow_unicode=True, default_flow_style=False)
            else:
                output = dump(data, Dumper=Dumper, sort_keys=False, allow_unicode=True, default_flow_style=False)
        case "csv":
            if not isinstance(data_tmp, list):
                return "Error format output: Wrong data type - expecting list, got {}".format(type(data_tmp))
            csv_out = io.StringIO()
            writer = csv.writer(csv_out, quoting=csv.QUOTE_NONNUMERIC)
            count = 0
            for item in data_tmp:
                if count == 0:
                    header = item.keys()
                    writer.writerow(header)
                    count += 1
                writer.writerow(item.values())
            output = csv_out.getvalue()
            output = output.replace('\r', '')
            # print(output)
        case "list":
            if not isinstance(data, list):
                return "Error format output: Wrong data type - expecting list, got {}".format(type(data))
            for item in data:
                output += str(item) + "\n"
        case "string":
            output = data
    return output


def get_tabulate_from_dict(dict_list: list, skip=None) -> [list, list]:
    """
    Get tabulated data from list of dicts
    :param dict_list: list of dicts
    :param skip: list columns to skip
    :return: headers list, rows list
    """
    def get_headers(source_list, sk=None):
        hdrs = []
        keys = []
        for itm in source_list:
            idxx = 0
            for ky, vl in itm.items():
                if idxx not in sk:
                    hd = ky.capitalize()
                    if hd not in hdrs:
                        hdrs.append(hd)
                        keys.append(ky)
        return hdrs, keys

    date_pattern = re.compile("[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:"  # noqa
                              "[0-9]{2}:[0-9]{2}(\.[0-9]+)?([Zz]|([\+-])([01]\d|2[0-3]):?([0-5]\d)?)?")  # noqa
    if not skip:
        skip = []
    out_list = []
    headers, headers_keys = get_headers(source_list=dict_list, sk=skip)
    for item in dict_list:
        row_list = []
        for key_item in headers_keys:
            if key_item in item:
                val = item[key_item]
                if isinstance(val, str):
                    if re.match(date_pattern, val):
                        val_split = val.split("T")
                        val = "{} {}".format(val_split[0], val_split[1].split(".")[0])
                row_list.append(val)
            else:
                row_list.append("None")
        out_list.append(row_list)
    return headers, out_list

def get_tabulate_from_dict_old(dict_list: list, skip=None) -> [list, list]:
    """
    Get tabulated data from list of dicts
    :param dict_list: list of dicts
    :param skip: list columns to skip
    :return: headers list, rows list
    """
    date_pattern = re.compile("[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:"  # noqa
                              "[0-9]{2}:[0-9]{2}(\.[0-9]+)?([Zz]|([\+-])([01]\d|2[0-3]):?([0-5]\d)?)?")  # noqa
    if not skip:
        skip = []
    out_list = []
    headers = []
    for item in dict_list:
        row_list = []
        idx = 0
        for key, value in item.items():
            if idx not in skip:
                head = key.capitalize()
                if head not in headers:
                    headers.append(head)
                if not value:
                    row_list.append("None")
                else:
                    val = value
                    if isinstance(val, str):
                        if re.match(date_pattern, value):
                            val_split = val.split("T")
                            val = "{} {}".format(val_split[0], val_split[1].split(".")[0])
                    row_list.append(val)
            idx += 1
        out_list.append(row_list)
    return headers, out_list


def deep_set(target: dict | list, path: str, value: any) -> dict | list:
    """
    Deep set value in structure
    :param target: target structure
    :param path: string with key path: name.nested.nested
    :param value: value to set
    :return: structure
    """
    out_target = target
    if isinstance(out_target, list):
        for idx in range(0, len(out_target)):
            out_target[idx] = deep_set(out_target[idx], path, value)
    if isinstance(out_target, dict):
        if "." in path:
            split = path.split(".", 1)
            if split[0] in out_target:
                out_target = deep_set(out_target[split[0]], split[1], value)
            else:
                out_target[split[0]] = {}
                out_target = deep_set(out_target[split[0]], split[1], value)
        else:
            out_target[path] = value
    return out_target


def deep_compare_dict(source_obj: dict | None, path: str, value: any, ignore_case=True, contains=False) -> bool:
    """
    Compare deep value in dict where key can be in quotes
    :param source_obj: dict object
    :param path: means key.nested.nested
    :param value: value to compare
    :param ignore_case: if true - ignore case
    :param contains: if false - strict equal
    :return: true or false
    """

    def get_ignore_case(obj: dict, key: str):
        for im, v in obj.items():
            if im.lower() == key.lower():
                return v

    def split_path(pth: str) -> list:
        in_quotes = False
        path_list = []
        val = ""
        for idx in range(0, len(pth)):
            if (pth[idx] == "'" or pth[idx] == '"') and not in_quotes:
                in_quotes = True
                continue
            if (pth[idx] == "'" or pth[idx] == '"') and in_quotes:
                in_quotes = False
                continue
            if pth[idx] == "." and not in_quotes:
                path_list.append(val)
                val = ""
                continue
            val += pth[idx]
        if len(val) > 0:
            path_list.append(val)
        return path_list

    if not isinstance(source_obj, dict):
        if value.lower() == "none" and source_obj is None:
            return True
        return False
    # Try to get value
    path_split = split_path(path)
    if path_split == 0:
        return False
    dict_value = get_ignore_case(source_obj, path_split[0])
    if dict_value:
        # Getting value in deep
        for i in range(1, len(path_split)):
            dict_value = get_ignore_case(dict_value, path_split[i])
            if not dict_value:
                dict_value = None
                break
    # If None
    if value.lower() == "none" and not dict_value:
        return True
    if not dict_value:
        return False
    if ignore_case:
        if contains:
            dict_value = str(dict_value)
            if re.search(value.lower(), str(dict_value.lower())):
                return True
        else:
            if value.lower() == str(dict_value).lower():
                return True
        return False
    else:
        if contains:
            dict_value =str(dict_value)
            if re.search(value, str(dict_value)):
                return True
        else:
            if value == str(dict_value):
                return True
        return False


def deep_compare_dict_old(source_obj: dict | None, path: str, value: str, ignore_case=True, contains=False) -> bool:
    """
    Compare deep value in dict
    :param source_obj: dict object
    :param path: means key.nested.nested
    :param value: value to compare
    :param ignore_case: if true - ignore case
    :param contains: if false - strict equal
    :return: true or false
    """
    if not isinstance(source_obj, dict):
        if value.lower() == "none" and source_obj is None:
            return True
        return False
    if "." in path:
        split = path.split(".", 1)
        if ignore_case:
            # Look in obj keys
            for item_key, item_value in source_obj.items():
                if item_key.lower() == split[0].lower():
                    out_val = deep_compare_dict(source_obj[item_key], split[1], value, ignore_case, contains)
                    return out_val
        else:
            for item_key, item_value in source_obj.items():
                if item_key == split[0]:
                    out_val = deep_compare_dict(source_obj[item_key], split[1], value, ignore_case, contains)
                    return out_val
    else:
        if ignore_case:
            for item_key, item_value in source_obj.items():
                if item_key.lower() == path.lower():
                    if contains:
                        if source_obj[item_key]:
                            if value.lower() in str(source_obj[item_key].lower()):
                                return True
                    else:
                        if source_obj[item_key] is None and value.lower() == "none":
                            return True
                        if str(source_obj[item_key]).lower() == value.lower():
                            return True
        else:
            for item_key, item_value in source_obj.items():
                if item_key == path:
                    if contains:
                        if re.search(str(source_obj[item_key]), value):
                            return True
                    else:
                        if source_obj[item_key] is None and value == "None":
                            return True
                        if str(source_obj[item_key]) == value:
                            return True
    return False


def deep_get(source: dict | list | str, path: str) -> dict | list | str | None:
    """
    Get value by path
    :param source: structure
    :param path: means key.nested.nested
    :return: value
    """
    def get_ignore_case(obj: dict, key: str):
        for im, v in obj.items():
            if im.lower() == key.lower():
                return v

    def split_path(pth: str) -> list:
        in_quotes = False
        path_list = []
        val = ""
        for idx in range(0, len(pth)):
            if (pth[idx] == "'" or pth[idx] == '"') and not in_quotes:
                in_quotes = True
                continue
            if (pth[idx] == "'" or pth[idx] == '"') and in_quotes:
                in_quotes = False
                continue
            if pth[idx] == "." and not in_quotes:
                path_list.append(val)
                val = ""
                continue
            val += pth[idx]
        if len(val) > 0:
            path_list.append(val)
        return path_list

    out = None
    if isinstance(source, list):
        out = []
        for item in source:
            res = deep_get(item, path)
            if res:
                out.append(res)
        if len(out) == 0:
            out = None
    if isinstance(source, dict):
        # Try to get value
        path_split = split_path(path)
        if path_split == 0:
            return
        dict_value = get_ignore_case(source, path_split[0])
        if dict_value:
            # Getting value in deep
            for i in range(1, len(path_split)):
                dict_value = get_ignore_case(dict_value, path_split[i])
                if not dict_value:
                    dict_value = None
                    break
            out = dict_value
    if isinstance(source, str):
        out = source
    return out


def deep_get_old(source: dict | list | str, path: str) -> dict | list | str:
    """
    Get value by path
    :param source: structure
    :param path: means key.nested.nested
    :return: value
    """
    out = None
    if isinstance(source, list):
        out = []
        for item in source:
            res = deep_get(item, path)
            if res:
                out.append(res)
        if len(out) == 0:
            out = None
    if isinstance(source, dict):
        if "." in path:
            split = path.split(".", 1)
            if split[0] in source:
                out = deep_get(source[split[0]], split[1])
            else:
                out = None
        else:
            if path in source:
                out = source[path]
            else:
                out = None
    if isinstance(source, str):
        out = source
    return out


def get_fmt_data(data: str | dict | list | int) -> [str, str | dict | list | int]:
    """
    Get data format
    :param data: data structure
    :return: data type, data
    """
    logger = logging.getLogger("core.func")
    if isinstance(data, str):
        # Looking for json:
        try:
            json_string = json.loads(data)
        except BaseException as err:
            logger.debug("Fail when JSON parse: {}".format(err))
            json_string = None
        if json_string:
            return "json", json_string
    if isinstance(data, str):
        return "string", data
    if isinstance(data, dict):
        return "json", data
    if isinstance(data, list):
        return "list", data
    if isinstance(data, int):
        return "json", data


def get_keys_from_dict(dct: dict, keys: list) -> dict:
    """
    Get dict of specific keys
    :param dct: source dict
    :param keys: list of keys
    :return: dict
    """
    out_dict = {}
    for item in keys:
        if "#" in item:
            itm_split = item.split("#")
            out_dict[itm_split[1]] = deep_get(dct, itm_split[0])
        else:
            out_dict[item] = deep_get(dct, item)
    return out_dict


# Only in pipe validator
def validate_pipe(_command, context) -> bool:
    """
    Validation check that context is piped
    """
    if not context.is_piped and context.tail_string != "--help" and context.tail_string != "help":
        rich_print("[yellow]Can be used only with piped context")
        return False
    return True


def fnmatch_ext(value: str, pattern: str) -> bool:
    """
    Extended fnmatch with special symbols
    :param value: value to compare
    :param pattern: pattern to compare
    :return: true or false
    """
    modified_value = value.replace('"', "")
    modified_value = modified_value.replace("[", "#").replace("]", "#").lower()
    modified_pattern = pattern.replace("[", "#").replace("]", "#").lower()
    return fnmatch.fnmatch(modified_value, modified_pattern)


def get_file_list_by_pattern(path_pattern: str) -> list | None:
    """
    Get file list for pattern
    :param path_pattern: filename pattern
    :return: list of files
    """
    logger = logging.getLogger("core.func")
    # Try to split path:
    try:
        path, name = os.path.split(path_pattern)
    except BaseException as err:
        print("Exp on split path")
        logger.debug("Exception on split path: {}".format(err))
        return
    if not path:
        path = os.getcwd()
    # Try to get files by pattern
    target_files = []
    try:
        for file_name in os.listdir(path):
            if os.path.isfile(os.path.join(path, file_name)):
                if fnmatch.fnmatch(file_name, name):
                    target_files.append(os.path.join(path, file_name))
    except BaseException as err:
        logger.debug("Exception file walk: {}".format(err))
        return
    if len(target_files) == 0:
        return
    else:
        return target_files


# Clear previous line in console
def console_clear_up(only_up=False, skip_line=False) -> None:
    """
    Clean last line in console
    :param only_up: only move cursor up to one line
    :param skip_line: skip insert new line
    """
    sys.stdout.write('\x1b[1A')
    if not only_up:
        sys.stdout.write('\x1b[2K')
        if not skip_line:
            print("\r")


class LogicValidation:
    """
    Class to check expressions string with logical operators
    """

    def __init__(self, source_str: str):
        err, self.logic = self.__get_logic(source_str)
        if err:
            raise Exception(self.logic)

    def validate(self, source_item: dict, logic=None) -> bool:
        """
        Validate dict item
        :param source_item: dict to validate
        :param logic: used for recursion
        """
        from app.core.command import get_var
        if not logic:
            logic = self.logic
        primary_result = True
        alternative_result = False
        primary_once = False
        alternative_once = False
        # Get primary logic result
        for im in logic["primary"]:
            # If expression
            if im.get("kind") == "expression":
                if im.get("operator") == "==":
                    value = im["value"]
                    if im["value"][0] == "$":
                        value = get_var(im["value"])
                    if str(value).lower() != "null":
                        # result = deep_compare_dict(source_item, im.get("property"), str(value))
                        result = deep_compare_dict(source_item, im.get("property"), str(value))
                    else:
                        result = deep_get(source_item, im.get("property"))
                        if result:
                            result = None
                        else:
                            result = True
                    if not result:
                        primary_result = False
                    else:
                        primary_once = True
                if im.get("operator") == "!=":
                    value = im["value"]
                    if im["value"][0] == "$":
                        value = get_var(im["value"])
                    if str(value).lower() != "null":
                        # result = deep_compare_dict(source_item, im.get("property"), str(value))
                        result = deep_compare_dict(source_item, im.get("property"), str(value))
                    else:
                        result = deep_get(source_item, im.get("property"))
                        if not result:
                            result = True
                        else:
                            result = None
                    if result:
                        primary_result = False
                    else:
                        primary_once = True
                if im.get("operator") == "~=":
                    value = im["value"]
                    if im["value"][0] == "$":
                        value = get_var(im["value"])
                    # result = deep_compare_dict(source_item, im.get("property"), str(value), contains=True)
                    result = deep_compare_dict(source_item, im.get("property"), str(value), contains=True)
                    if not result:
                        primary_result = False
                    else:
                        primary_once = True
            # If nested logic
            if im.get("kind") == "nested":
                nested_verdict = self.validate(source_item, logic=im.get("logic"))
                if not nested_verdict:
                    primary_result = False
                else:
                    primary_once = True
        for itm in logic["alternative"]:
            # If expression
            if itm.get("kind") == "expression":
                if itm.get("operator") == "==":
                    value = itm["value"]
                    if itm["value"][0] == "$":
                        value = get_var(itm["value"])
                    # result = deep_compare_dict(source_item, itm.get("property"), str(value))
                    result = deep_compare_dict(source_item, itm.get("property"), str(value))
                    if not result:
                        alternative_result = False
                    else:
                        alternative_once = True
                        alternative_result = True
                if itm.get("operator") == "!=":
                    value = itm["value"]
                    if itm["value"][0] == "$":
                        value = get_var(itm["value"])
                    # result = deep_compare_dict(source_item, itm.get("property"), str(value))
                    result = deep_compare_dict(source_item, itm.get("property"), str(value))
                    if result:
                        alternative_result = False
                    else:
                        alternative_once = True
                        alternative_result = True
                if itm.get("operator") == "~=":
                    value = itm["value"]
                    if itm["value"][0] == "$":
                        value = get_var(itm["value"])
                    # result = deep_compare_dict(source_item, itm.get("property"), str(value), contains=True)
                    result = deep_compare_dict(source_item, itm.get("property"), str(value), contains=True)
                    if not result:
                        alternative_result = False
                    else:
                        alternative_once = True
                        alternative_result = True
            # If nested logic
            if itm.get("kind") == "nested":
                nested_verdict = self.validate(source_item, logic=itm.get("logic"))
                if not nested_verdict:
                    alternative_result = False
                else:
                    alternative_once = True
                    alternative_result = True
        if (alternative_result and alternative_once) or (primary_result and primary_once):
            return True
        else:
            return False

    def __get_logic(self, source_str: str) -> [bool, dict | str]:
        """
        Build logic dict with primary and alternative list
        """
        unbracket_str, bracket_tokens = self.__get_brackets_tokens(source_str)
        linear_logic = self.__get_linear_logic(unbracket_str)
        logic = {
            "primary": [],
            "alternative": []
        }
        is_primary = True
        is_alternative = False
        for item in linear_logic:
            # If logical
            if item.lower() == "and":
                continue
            if item.lower() == "or":
                is_primary = False
                is_alternative = True
                continue
            # If item is bracket token
            if item[0] == "^":
                token = item.replace("^", "")
                if not token.isdigit():
                    return True, "Failed to resolve bracket token"
                token = int(token)
                bracket_expr = bracket_tokens[token]
                err, nested_logic = self.__get_logic(bracket_expr)
                if err:
                    return True, nested_logic
                if is_primary:
                    logic["primary"].append({
                        "kind": "nested",
                        "logic": nested_logic
                    })
                if is_alternative:
                    logic["alternative"].append({
                        "kind": "nested",
                        "logic": nested_logic
                    })
                continue
            # If expression
            prop = None
            operation = None
            value = None
            if "==" in item:
                operation = "=="
                item_split = item.split("==")
                if len(item_split) < 2:
                    return True, "Failed to build expression from: {}".format(item)
                prop = item_split[0]
                value = item_split[1]
            if "!=" in item:
                operation = "!="
                item_split = item.split("!=")
                if len(item_split) < 2:
                    continue
                prop = item_split[0]
                value = item_split[1]
            if "~=" in item:
                operation = "~="
                item_split = item.split("~=")
                if len(item_split) < 2:
                    continue
                prop = item_split[0]
                value = item_split[1]
            if not prop or not operation or not value:
                return True, "Failed to build expression from: {}".format(item)
            # If value in quotes, remove quotes
            if isinstance(value, str):
                if value[0] == "'" or value[-1:] == "'":
                    value = value[1:-1]
                if value[0] == '"' or value[-1:] == '"':
                    value = value[1:-1]
            if is_primary:
                logic["primary"].append({
                    "kind": "expression",
                    "operator": operation,
                    "property": prop,
                    "value": value
                })
            if is_alternative:
                logic["alternative"].append({
                    "kind": "expression",
                    "operator": operation,
                    "property": prop,
                    "value": value
                })
        return False, logic

    @staticmethod
    def __get_linear_logic(source_str: str) -> list:
        """
        Split string to parts with expressions and logical operators
        :param source_str: string
        """
        logic = []
        in_expression = False
        expression = ""
        in_quotes = False
        src_lower = source_str.lower()
        idx = 0
        while idx < len(source_str):
            # If logical
            if idx < len(source_str) - 3:
                if (src_lower[idx] == "a" and src_lower[idx + 1] == "n"
                        and src_lower[idx + 2] == "d" and not in_expression and not in_quotes):
                    logic.append("and")
                    idx += 3
                    continue
                if src_lower[idx] == "o" and src_lower[idx + 1] == "r" and not in_expression and not in_quotes:
                    logic.append("or")
                    idx += 2
                    continue
            # Not in expression yet, begin new expression
            if source_str[idx] != " " and not in_expression:
                in_expression = True
                expression = source_str[idx]
                idx += 1
                continue
            # Handle quoted expression - ignore content
            if source_str[idx] == "'" or source_str[idx] == '"':
                if not in_quotes:
                    in_quotes = True
                    expression += source_str[idx]
                    idx += 1
                    continue
                else:
                    in_quotes = False
                    expression += source_str[idx]
                    idx += 1
                    continue
            if in_quotes:
                expression += source_str[idx]
                idx += 1
                continue
            # End of expression
            if source_str[idx] == " " and in_expression:
                logic.append(expression)
                expression = ""
                in_expression = False
                idx += 1
                continue
            expression += source_str[idx]
            idx += 1
        if in_expression:
            logic.append(expression)
        return logic

    @staticmethod
    def __get_brackets_tokens(source_str: str) -> [str, list]:
        """
        Look string for expression in brackets and replace it to tokens with refs
        :param source_str: string
        """
        tokens = []
        out_string = ""
        token_num = 0
        in_brackets = False
        bracket_expression = ""
        nested_brackets = 0
        for idx in range(0, len(source_str)):
            # If new bracket expression begins
            if source_str[idx] == "(" and not in_brackets:
                in_brackets = True
                out_string += "^" + str(token_num)
                token_num += 1
                bracket_expression = ""
                continue
            # If new bracket expression but we are already in expression
            if source_str[idx] == "(" and in_brackets:
                nested_brackets += 1
                bracket_expression += source_str[idx]
                continue
            # If close brackets and we have nested
            if source_str[idx] == ")" and nested_brackets > 0:
                nested_brackets -= 1
                bracket_expression += source_str[idx]
                continue
            # If close brackets and no nested - bracket expression end
            if source_str[idx] == ")" and nested_brackets == 0:
                tokens.append(bracket_expression)
                in_brackets = False
                continue
            # If in brackets
            if in_brackets:
                bracket_expression += source_str[idx]
                continue
            out_string += source_str[idx]
        return out_string, tokens
