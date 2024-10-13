import logging
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


class iface_MP_Template:  # noqa
    def __init__(self, load=True):
        """
        Interface for templates
        :param load: if false - do not load template list
        """
        self.logger = logging.getLogger("mp.iface_template")
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

    def info(self, pattern=None, lst=None, dct=None, user_only=False) -> MPAPIResponse:
        """
        Get template information
        :param pattern: string
        :param lst: template list
        :param dct: template dict
        :param user_only: only non-system templates
        """
        from app.mp.mp.iface_mp import ID_refs

        def rebuild_user_only(temp_list: list) -> list | None:
            out_lst = []
            for itm in temp_list:
                if not itm.get("system"):
                    out_lst.append(itm)
            if len(out_lst) == 0:
                return
            return out_lst

        template_list = None
        if pattern:
            template_list = self.get_by_pattern(pattern)
            if template_list:
                if len(template_list) > 1:
                    template_list = [func_select_list_item(template_list)]
                    if template_list == [False] or template_list == [None]:
                        return MPAPIResponse(state=False, message="No template found")
            else:
                return MPAPIResponse(state=False, message="No template found")
        if dct:
            template_list = [dct]
        if lst:
            template_list = lst
        if template_list:
            if user_only:
                template_list = rebuild_user_only(template_list)
                if not template_list:
                    return MPAPIResponse(state=False, message="No template found")
            out_list = []
            if len(template_list) > 5:
                rich_print("[yellow]It can get some time")
            try:
                id_refs = ID_refs(["group", "query", "event_filter"])
            except KeyboardInterrupt:
                return MPAPIResponse(state=False, message="Operation interrupted")
            except BaseException as err:
                self.logger.error("Failed to initialize reference APIs: {}".format(err))
                return MPAPIResponse(state=False, message="Failed to initialize reference APIs: {}".format(err))
            with Progress() as progress:
                task = progress.add_task("Getting template information...", total=len(template_list))
                for item in template_list:
                    progress.update(task, advance=1)
                    info = self.__get_info(item.get("id"))
                    if not info.state and info.message == "Operation interrupted":
                        return MPAPIResponse(state=False, message="Operation interrupted")
                    if info.state:
                        info = info.message
                        refs = id_refs.get_references(info)
                        if not refs.state:
                            return refs
                        info["cli-mixin"] = {
                            "mixin_ref_version": app.MIXIN_REF_VERSION,
                            "kind": "template",
                            "timestamp": str(datetime.datetime.now()),
                            "product": app.API_MP.product,
                            "references_id": refs.message
                        }
                        out_list.append(info)
                    else:
                        self.logger.error("Template {} not found".format(item.get("id")))
                        return MPAPIResponse(state=False, message="Template {} not found".format(item.get("id")))
            console_clear_up(skip_line=True)
            if len(out_list) == 0:
                return MPAPIResponse(state=False, message="No template found")
            return MPAPIResponse(state=True, message=out_list)
        else:
            return MPAPIResponse(state=False, message="No template found")

    def create(self, source_spec: dict, disarm=True) -> MPAPIResponse:
        """
        Create template for MaxPatrol user from spec
        :param source_spec: specification structure
        :param disarm: run in test mode
        """
        from app.mp.mp.iface_mp import ID_refs
        # Reload template list
        response = self.__load_list()
        if not response.state:
            EVENTS.push(status="Fail", action="Create", instance="Template",
                        name=source_spec.get("name"), instance_id=source_spec.get("id"),
                        details=response.message)
            return response
        self.list = response.message
        # Prepare specification
        print("Trying to create template: {}... ".format(source_spec.get("name")))
        exist = self.get_by_name(source_spec.get("name"))
        if exist:
            EVENTS.push(status="Fail", action="Create", instance="Template",
                        name=source_spec.get("name"), instance_id=source_spec.get("id"),
                        details="Template {} exist. Can`t create".format(source_spec.get("name")))
            return MPAPIResponse(state=False, message="Template {} exist. Can`t create".format(source_spec.get("name")))
        self.logger.debug("Template {} not exist".format(source_spec.get("name")))
        try:
            id_refs = ID_refs(["group", "query", "event_filter"])
        except KeyboardInterrupt:
            return MPAPIResponse(state=False, message="Operation interrupted")
        except BaseException as err:
            self.logger.error("Failed to initialize reference APIs: {}".format(err))
            return MPAPIResponse(state=False, message="Failed to initialize reference APIs: {}".format(err))
        out_spec = id_refs.replace(source_spec)
        if not out_spec.state:
            return out_spec
        out_spec = out_spec.message
        del out_spec["cli-mixin"]
        if not app.app.GLOBAL_DISARM and not disarm:
            self.logger.debug("Starting create process")
            response = app.API_MP.post(app.API_MP.url_template, out_spec)
            if not response.state:
                return response
            response = response.message.json()
            self.logger.debug("Template {} successfully created".format(out_spec.get("name")))
            return MPAPIResponse(state=True,
                                 message="Template {} successfully created with ID: "
                                         "{}".format(out_spec.get("name"), response))
        else:
            return MPAPIResponse(state=True, message="Success - disarmed")

    def delete(self, template_id: str, disarm=True) -> MPAPIResponse:
        """
        Delete template
        :param template_id: string
        :param disarm: run in test mode
        """
        self.logger.debug("Trying to delete template {}".format(template_id))
        if not app.app.GLOBAL_DISARM and not disarm:
            response = app.API_MP.delete(app.API_MP.url_template_instance.format(template_id), template_id)
        else:
            print("Success - disarmed")
            return MPAPIResponse(state=True, message="Success - disarmed")
        if not response.state:
            return response
        self.logger.debug("Template {} successfully deleted".format(template_id))
        return MPAPIResponse(state=True, message="Template {} successfully deleted".format(template_id))

    def get_template_picker(self, prompt_string: str) -> MPAPIResponse:
        """
        Template selection dialog with autocompletion
        :param prompt_string: prompt for dialog
        """
        template_names, template_ids = self.get_short_list()
        template_completer = WordCompleter(template_names, sentence=True)
        while True:
            try:
                template_input = prompt(prompt_string, completer=template_completer, complete_while_typing=True)
            except KeyboardInterrupt:
                return MPAPIResponse(state=False, message="Operation interrupted")
            if template_input == "":
                return MPAPIResponse(state=False, message="Skip template enter")
            if template_input == "?":
                print("Available templates:")
                print(get_string_from_fmt(template_names, fmt="yaml"))
                continue
            if "*" in template_input:
                print("Available templates:")
                for item in template_names:
                    if fnmatch_ext(item, template_input):
                        print("- {}".format(item))
                continue
            for idx in range(0, len(template_names)):
                if template_names[idx] == template_input:
                    return MPAPIResponse(state=True, message={"name": template_names[idx],
                                                              "id": template_ids[idx]})
            print("Wrong credential")

    def get_by_pattern(self, pattern: any) -> list | None:
        out_list = []
        if isinstance(pattern, str):
            if pattern.isdigit():
                for item in self.list:
                    if str(item.get("id")) == pattern:
                        out_list.append(item)
            else:
                for item in self.list:
                    if fnmatch_ext(item.get("name").lower(), str(pattern).lower()):
                        out_list.append(item)
        else:
            if isinstance(pattern, int):
                for item in self.list:
                    if item.get("id") == pattern:
                        out_list.append(item)
            for item in self.list:
                if fnmatch_ext(item.get("name").lower(), str(pattern).lower()):
                    out_list.append(item)
        if len(out_list) == 0:
            return
        else:
            return out_list

    def get_by_name(self, name: str) -> dict | None:
        """
        Get template by name
        :param name: string
        """
        self.logger.debug("Trying to get template for name: {}".format(name))
        for template in self.list:
            if template.get("name") == name:
                return template
        self.logger.debug("No template found")
        return

    def get_by_id(self, template_id: str) -> dict | None:
        """
        Get template by ID
        :param template_id: string
        """
        self.logger.debug("Trying to get template for ID: {}".format(template_id))
        for template in self.list:
            if template.get("id") == template_id:
                return template
        self.logger.debug("No template found")
        return

    def get_short_list(self) -> [list, list]:
        """
        Get template short lists
        :return: names list, ids list
        """
        names = []
        ids = []
        for item in self.list:
            names.append(item.get("name"))
            ids.append(item.get("id"))
        return names, ids

    @staticmethod
    def reduce_list(data: dict | list) -> dict | list:
        """
        Template list reducer
        """
        if isinstance(data, list):
            output = []
            for item in data:
                output.append(
                    get_keys_from_dict(item, ["id", "name", "type", "system", "source"]))
        else:
            output = get_keys_from_dict(data, ["id", "name", "type", "system", "source"])
        return output

    @staticmethod
    def reduce_info(data: dict | list) -> dict | list:
        """
        Template info reducer
        """
        if isinstance(data, list):
            output = []
            for item in data:
                output.append(
                    get_keys_from_dict(item, ["id", "name", "version", "type", "refreshCachingPolicy",
                                              "system", "source", "systemTemplateId"]))
        else:
            output = get_keys_from_dict(data, ["id", "name", "version", "type", "refreshCachingPolicy",
                                               "system", "source", "systemTemplateId"])
        return output

    def __get_info(self, template_id) -> MPAPIResponse:
        """
        Get template information
        :param template_id: string
        """
        self.logger.debug("Trying to load template info")
        response = app.API_MP.get(app.API_MP.url_template_instance.format(template_id))
        if not response.state:
            self.logger.error("Template information load failed: {}".format(response.message))
            return response
        self.logger.debug("Template information load succeeded")
        return MPAPIResponse(state=True, message=response.message.json())

    def __load_list(self) -> MPAPIResponse:
        """
        Load template list
        """
        self.logger.debug("Trying to load templates")
        # Load templates list
        response = app.API_MP.get(app.API_MP.url_template)
        if not response.state:
            self.logger.error("Template list load failed: {}".format(response.message))
            return response
        self.logger.debug("Template list load succeeded")
        return MPAPIResponse(state=True, message=response.message.json().get("items"))
