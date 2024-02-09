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
from app.mp.user import iface_MP_User


class iface_MP_Dashboard:  # noqa
    def __init__(self, load=True):
        """
        Interface for dashboards
        :param load: if false - do not load dashboard list
        """
        self.logger = logging.getLogger("mp.iface_dashboard")
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
        Get dashboard information
        :param pattern: string
        :param lst: template list
        :param dct: template dict
        """
        from app.mp.mp.iface_mp import ID_refs

        dashboard_list = None
        if pattern:
            dashboard_list = self.get_by_pattern(pattern)
            if dashboard_list:
                if len(dashboard_list) > 1:
                    dashboard_list = [func_select_list_item(dashboard_list)]
                    if dashboard_list == [False] or dashboard_list == [None]:
                        return MPAPIResponse(state=False, message="No dashboard found")
            else:
                return MPAPIResponse(state=False, message="No dashboard found")
        if dct:
            dashboard_list = [dct]
        if lst:
            dashboard_list = lst
        if dashboard_list:
            out_list = []
            if len(dashboard_list) > 5:
                rich_print("[yellow]It can get some time")
            try:
                id_refs = ID_refs(["group", "query", "user"])
            except KeyboardInterrupt:
                return MPAPIResponse(state=False, message="Operation interrupted")
            except BaseException as err:
                self.logger.error("Failed to initialize reference APIs: {}".format(err))
                return MPAPIResponse(state=False, message="Failed to initialize reference APIs: {}".format(err))
            with Progress() as progress:
                task = progress.add_task("Getting dashboard information...", total=len(dashboard_list))
                for item in dashboard_list:
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
                            "kind": "dashboard",
                            "timestamp": str(datetime.datetime.now()),
                            "product": app.API_MP.product,
                            "references_id": refs.message
                        }
                        out_list.append(info)
                    else:
                        self.logger.error("Dashboard {} not found".format(item.get("id")))
                        return MPAPIResponse(state=False, message="Dashboard {} not found".format(item.get("id")))
            console_clear_up(skip_line=True)
            if len(out_list) == 0:
                return MPAPIResponse(state=False, message="No dashboard found")
            return MPAPIResponse(state=True, message=out_list)
        else:
            return MPAPIResponse(state=False, message="No dashboard found")

    def create(self, source_spec: dict, disarm=True) -> MPAPIResponse:
        """
        Create dashboard for MaxPatrol user from spec
        :param source_spec: specification structure
        :param disarm: run in test mode
        """
        from app.mp.mp.iface_mp import ID_refs
        # Reload dashboards list
        response = self.__load_list()
        if not response.state:
            EVENTS.push(status="Fail", action="Create", instance="Dashboard",
                        name=source_spec.get("name"), instance_id=source_spec.get("id"),
                        details=response.message)
            return response
        self.list = response.message
        # Prepare specification
        print("Trying to create dashboard: {}... ".format(source_spec.get("name")))
        exist = self.get_by_name(source_spec.get("name"))
        if exist:
            EVENTS.push(status="Fail", action="Create", instance="Dashboard",
                        name=source_spec.get("name"), instance_id=source_spec.get("id"),
                        details="Dashboard {} exist. Can`t create".format(source_spec.get("name")))
            return MPAPIResponse(state=False,
                                 message="Dashboard {} exist. Can`t create".format(source_spec.get("name")))
        self.logger.debug("Dashboard {} not exist".format(source_spec.get("name")))
        try:
            id_refs = ID_refs(["group", "query", "user"])
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
            print("Create dashboard... ", end="")
            response = app.API_MP.post(app.API_MP.url_dashboard, out_spec)
            if not response.state:
                return response
            response = response.message.json()
            dashboard_id = response.get("id")
            rich_print("[green]OK")
            print("Create dashboard widgets... ", end="")
            for item in source_spec.get("widgets"):
                response = app.API_MP.post(app.API_MP.url_dashboard_instance_widgets.format(dashboard_id), item)
                if not response.state:
                    return response
            rich_print("[green]OK")
            self.logger.debug("Dashboard {} successfully created".format(out_spec.get("name")))
            return MPAPIResponse(state=True,
                                 message="Dashboard {} successfully created with ID: "
                                         "{}".format(out_spec.get("name"), dashboard_id))
        else:
            return MPAPIResponse(state=True, message="Success - disarmed")

    def delete(self, dashboard_id: str, disarm=True) -> MPAPIResponse:
        """
        Delete dashboard
        :param dashboard_id: string
        :param disarm: run in test mode
        """
        self.logger.debug("Trying to delete dashboard {}".format(dashboard_id))
        if not app.app.GLOBAL_DISARM and not disarm:
            response = app.API_MP.delete(app.API_MP.url_dashboard_instance.format(dashboard_id), dashboard_id)
        else:
            print("Success - disarmed")
            return MPAPIResponse(state=True, message="Success - disarmed")
        if not response.state:
            return response
        self.logger.debug("Dashboard {} successfully deleted".format(dashboard_id))
        return MPAPIResponse(state=True, message="Dashboard {} successfully deleted".format(dashboard_id))

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
        Get dashboard by name
        :param name: string
        """
        self.logger.debug("Trying to get dashboard for name: {}".format(name))
        for dashboard in self.list:
            if dashboard.get("name") == name:
                return dashboard
        self.logger.debug("No dashboard found")
        return

    def get_by_id(self, dashboard_id: str) -> dict | None:
        """
        Get dashboard by ID
        :param dashboard_id: string
        """
        self.logger.debug("Trying to get dashboard for ID: {}".format(dashboard_id))
        for dashboard in self.list:
            if dashboard.get("id") == dashboard_id:
                return dashboard
        self.logger.debug("No dashboard found")
        return

    @staticmethod
    def reduce_info(data: dict | list) -> dict | list:
        """
        Dashboard info reducer
        """
        try:
            iface_user = iface_MP_User()
        except KeyboardInterrupt:
            return []
        except BaseException as err:
            return [err]
        if isinstance(data, list):
            output = []
            for item in data:
                out_item = get_keys_from_dict(item, ["id", "version", "name", "description", "position"])
                if item.get("ownerId"):
                    out_item["owner"] = iface_user.get_by_id(item.get("ownerId")).get("name")
                out_item["widgets"] = len(item.get("widgets"))
                output.append(out_item)
        else:
            output = get_keys_from_dict(data, ["id", "version", "name", "description", "position"])
            if data.get("ownerId"):
                output["owner"] = iface_user.get_by_id(data.get("ownerId")).get("name")
            output["widgets"] = len(data.get("widgets"))
        return output

    def __get_info(self, dashboard_id) -> MPAPIResponse:
        """
        Get dashboard information
        :param dashboard_id: string
        """
        self.logger.debug("Trying to load dashboard info")
        response = app.API_MP.get(app.API_MP.url_dashboard_instance.format(dashboard_id))
        if not response.state:
            self.logger.error("Dashboard information load failed: {}".format(response.message))
            return response
        self.logger.debug("Dashboard information load succeeded")
        return MPAPIResponse(state=True, message=response.message.json())

    def __load_list(self) -> MPAPIResponse:
        """
        Load dashboard list
        """
        self.logger.debug("Trying to load dashboards")
        # Load templates list
        response = app.API_MP.get(app.API_MP.url_dashboard)
        if not response.state:
            self.logger.error("Dashboard list load failed: {}".format(response.message))
            return response
        self.logger.debug("Dashboard list load succeeded")
        return MPAPIResponse(state=True, message=response.message.json())
