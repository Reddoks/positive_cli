import logging
import copy
import datetime

from rich.progress import Progress
from rich import print as rich_print

import app
from app.app import EVENTS
from app.core.func import get_keys_from_dict, console_clear_up, fnmatch_ext
from app.mp.api import MPAPIResponse
from app.mp.func import (func_select_list_item,
                         func_get_list_ids_from_list)


class iface_MP_Report_Task:  # noqa
    def __init__(self, load=True):
        """
        Interface for report tasks
        :param load: if false - do not load report tasks list
        """
        self.logger = logging.getLogger("mp.iface_report")
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
        Get report task information
        :param pattern: string
        :param lst: report list
        :param dct: report dct
        """
        from app.mp.mp.iface_mp import ID_refs

        tasks_list = None
        # If pattern
        if pattern:
            tasks_list = self.get_by_pattern(pattern=pattern)
            if tasks_list:
                if len(tasks_list) > 1:
                    tasks_list = [func_select_list_item(tasks_list)]
                    if tasks_list == [False] or tasks_list == [None]:
                        return MPAPIResponse(state=False, message="No report found")
                tasks_list = func_get_list_ids_from_list(tasks_list)
            else:
                return MPAPIResponse(state=False, message="No report found")
        # If lst
        if lst:
            tasks_list = func_get_list_ids_from_list(lst)
        if dct:
            tasks_list = [dct]
        if tasks_list:
            out_list = []
            if len(tasks_list) > 5:
                rich_print("[yellow]It can get some time")
            try:
                id_refs = ID_refs(["group", "user", "query"])
            except KeyboardInterrupt:
                return MPAPIResponse(state=False, message="Operation interrupted")
            except BaseException as err:
                self.logger.error("Failed to initialize reference APIs: {}".format(err))
                return MPAPIResponse(state=False, message="Failed to initialize reference APIs: {}".format(err))
            with Progress() as progress:
                task = progress.add_task("Getting report tasks information...", total=len(tasks_list))
                for item in tasks_list:
                    progress.update(task, advance=1)
                    info = self.__get_info(item)
                    if not info.state and info.message == "Operation interrupted":
                        return MPAPIResponse(state=False, message="Operation interrupted")
                    if info.state:
                        info = info.message
                        blocks_mixin_reference = self.get_blocks(info)
                        if not blocks_mixin_reference.state:
                            return blocks_mixin_reference
                        info["block_references"] = blocks_mixin_reference.message
                        refs = id_refs.get_references(info)
                        if not refs.state:
                            return refs
                        block_refs = self.get_block_series_refs(blocks_mixin_reference.message)
                        if not block_refs.state:
                            return block_refs
                        refs = refs.message
                        refs += block_refs.message
                        info["cli-mixin"] = {
                            "mixin_ref_version": app.MIXIN_REF_VERSION,
                            "kind": "report_task",
                            "timestamp": str(datetime.datetime.now()),
                            "product": app.API_MP.product,
                            "references_id": refs
                        }
                        out_list.append(info)
            console_clear_up(skip_line=True)
            if len(out_list) == 0:
                return MPAPIResponse(state=False, message="No report task found")
            return MPAPIResponse(state=True, message=out_list)
        else:
            return MPAPIResponse(state=False, message="No report task found")

    def create(self, source_spec: dict, disarm=True) -> MPAPIResponse:
        """
        Create report task from spec
        :param source_spec: source spec
        :param disarm: run in test mode
        """
        from app.mp.mp.iface_mp import ID_refs
        self.logger.debug("Trying to create report task from specification")
        # Prepare specification
        print("Trying to create report task: {}... ".format(source_spec.get("name")))
        exist = self.get_by_name(name=source_spec.get("name"))
        if exist:
            EVENTS.push(status="Fail", action="Create", instance="Report Task",
                        name=source_spec.get("name"), instance_id="N/A",
                        details="Report task {} exist. Can`t create".format(source_spec.get("name")))
            return MPAPIResponse(state=False,
                                 message="Report task {} exist. Can`t create".format(source_spec.get("name")))
        self.logger.debug("Report task {} not exist".format(source_spec.get("name")))
        try:
            id_refs = ID_refs(["group", "user", "query"])
        except KeyboardInterrupt:
            return MPAPIResponse(state=False, message="Operation interrupted")
        except BaseException as err:
            self.logger.error("Failed to initialize reference APIs: {}".format(err))
            return MPAPIResponse(state=False, message="Failed to initialize reference APIs: {}".format(err))
        out_spec = id_refs.replace(source_spec)
        if not out_spec.state:
            EVENTS.push(status="Fail", action="Create", instance="Report Task",
                        name=source_spec.get("name"), instance_id="N/A",
                        details=out_spec.message)
            return out_spec
        out_spec = out_spec.message
        # Create report without blocks
        if out_spec.get("block_references"):
            blocks_ref = out_spec["block_references"]
            del out_spec["block_references"]
            out_spec["blocks"] = []
        else:
            blocks_ref = None
        del out_spec["cli-mixin"]
        if not app.app.GLOBAL_DISARM and not disarm:
            print("Create report task... ", end="")
            response = app.API_MP.post(app.API_MP.url_report, out_spec)
            if not response.state:
                rich_print("[red]FAIL")
                self.logger.error("Failed to create report task: {}".format(response.message))
                EVENTS.push(status="Fail", action="Create", instance="Report Task",
                            name=source_spec.get("name"), instance_id="N/A",
                            details=response.message)
                return response
            report_id = response.message.json()
            report_id = report_id.get("id")
            rich_print("[green]OK")
            print("Create blocks... ", end="")
            blocks = []
            for block_spec in blocks_ref:
                response = app.API_MP.post(app.API_MP.url_report_block.format(report_id), block_spec)
                if not response.state:
                    rich_print("[red]FAIL")
                    self.logger.error("Failed to create blocks for report task: {}".format(response.message))
                    EVENTS.push(status="Fail", action="Create", instance="Block",
                                name="N/A", instance_id="N/A",
                                details=response.message)
                    return response
                block_id = response.message.json()
                block_id = block_id.get("id")
                blocks.append({"id": block_id})
            rich_print("[green]OK")
            print("Update report task... ", end="")
            out_spec["blocks"] = blocks
            response = app.API_MP.put(app.API_MP.url_report_instance.format(report_id), out_spec)
            if not response.state:
                rich_print("[red]FAIL")
                self.logger.error("Failed to update report task: {}".format(response.message))
                EVENTS.push(status="Fail", action="Update", instance="Report Task",
                            name="N/A", instance_id=report_id,
                            details=response.message)
                return response
            rich_print("[green]OK")
            self.logger.debug("Report task {} successfully created".format(source_spec.get("name")))
            return MPAPIResponse(state=True,
                                 message="Report task {} successfully created".format(source_spec.get("name")))
        else:
            return MPAPIResponse(state=False, message="Success - disarmed")

    def delete(self, target_id: str, disarm=True) -> MPAPIResponse:
        """
        Delete report task
        :param target_id: template ID string
        :param disarm: run in test mode
        """
        self.logger.debug("Trying to delete report task {}".format(target_id))
        if not app.app.GLOBAL_DISARM and not disarm:
            response = app.API_MP.delete(app.API_MP.url_report_instance.format(target_id), target_id)
        else:
            print("Success - disarmed")
            return MPAPIResponse(state=True, message="Success - disarmed")
        if not response.state:
            return response
        self.logger.debug("Report task {} successfully deleted".format(target_id))
        return MPAPIResponse(state=True, message="Report task {} successfully deleted".format(target_id))

    def get_by_pattern(self, pattern: str) -> list | None:
        """
        Get task by name or ID
        :param pattern: string name or ID
        """
        out_list = []
        # Trying to get by ID
        task = self.get_by_id(task_id=str(pattern))
        if task:
            return [task]
        # Trying to get by name
        for item in self.list:
            if fnmatch_ext(item.get("name").lower(), str(pattern).lower()):
                out_list.append(item)
        if len(out_list) == 0:
            return
        else:
            return out_list

    def get_by_name(self, name: str) -> dict | None:
        """
        Get task by name
        :param name: string
        """
        self.logger.debug("Trying to get report task for name: {}".format(name))
        for task in self.list:
            if task.get("name") == name:
                return task
        self.logger.debug("No report task found")
        return

    def get_by_id(self, task_id: str) -> dict | None:
        """
        Get task by ID
        :param task_id: string
        """
        self.logger.debug("Trying to get report task for ID: {}".format(task_id))
        for task in self.list:
            if task.get("id") == task_id:
                return task
        self.logger.debug("No report task found")
        return

    def get_blocks(self, src_report: dict) -> MPAPIResponse:
        """
        Get blocks reference
        :param src_report: report structure
        """
        # Loading blocks information
        report_blocks_extended = []
        if src_report.get("blocks"):
            for item in src_report["blocks"]:
                block = self.__get_block_info(src_report.get("id"), item.get("id"))
                if not block.state:
                    return block
                report_blocks_extended.append(block.message)
        return MPAPIResponse(state=True, message=report_blocks_extended)

    @staticmethod
    def get_block_series_refs(block_list: list) -> MPAPIResponse:
        """
        Getting IDs in dataSeries and set it to ignore
        :param block_list: list
        """
        def build_originals(reference: list) -> list:
            out_lst = []
            for it in reference:
                is_present = False
                for im in out_lst:
                    if im.get("id") == it.get("id"):
                        is_present = True
                if not is_present:
                    out_lst.append(it)
            return out_lst
        block_refs = []
        for item in block_list:
            if item.get("widget"):
                if item["widget"].get("settings"):
                    if item["widget"]["settings"].get("dataSeries"):
                        for itm in item["widget"]["settings"]["dataSeries"]:
                            if itm.get("series"):
                                for i in itm["series"]:
                                    block_refs.append({
                                        "id": i.get("id"),
                                        "kind": "ignore"
                                    })
        block_refs = build_originals(block_refs)
        return MPAPIResponse(state=True, message=block_refs)

    def __get_block_info(self, report_id: str, block_id: str) -> MPAPIResponse:
        """
        Get report block information
        :param block_id: string
        """
        self.logger.debug("Trying to load block info: {}/{}".format(report_id, block_id))
        response = app.API_MP.get(app.API_MP.url_report_block_instance.format(report_id, block_id))
        if not response.state:
            self.logger.error("Block information load failed: {}/{}: {}".format(report_id, block_id,
                                                                                response.message))
            return response
        self.logger.debug("Block {}/{} information load succeeded".format(report_id, block_id))
        return MPAPIResponse(state=True, message=response.message.json())

    @staticmethod
    def reduce_info(data: dict | list) -> dict | list:
        """
        Report info reducer
        """
        if isinstance(data, list):
            output = []
            for item in data:
                output.append(
                    get_keys_from_dict(item, ["id", "name", "type", "description", "format", "lastRunAt",
                                              "lastIssueState", "author.name", "nextRunAt"]))
        else:
            output = get_keys_from_dict(data, ["id", "name", "type", "description", "format", "lastRunAt",
                                               "lastIssueState", "author.name", "nextRunAt"])
        return output

    @staticmethod
    def reduce_list(data: dict | list) -> dict | list:
        """
        Report tasks list reducer
        """
        if isinstance(data, list):
            output = []
            for item in data:
                output.append(
                    get_keys_from_dict(item, ["id", "name", "type", "scheduleState", "lastIssueState",
                                              "author.name", "createdAt"]))
        else:
            output = get_keys_from_dict(data, ["id", "name", "type", "scheduleState", "lastIssueState",
                                               "author.name", "createdAt"])
        return output

    def __get_info(self, task_id: str) -> MPAPIResponse:
        """
        Get report task information
        :param task_id: string
        """
        self.logger.debug("Trying to load report task info")
        response = app.API_MP.get(app.API_MP.url_report_instance.format(task_id))
        if not response.state:
            self.logger.error("Report task information load failed: {}".format(response.message))
            return response
        self.logger.debug("Report task information load succeeded")
        return MPAPIResponse(state=True, message=response.message.json())

    def __load_list(self) -> MPAPIResponse:
        """
        Load report tasks list
        """
        self.logger.debug("Trying to load report tasks")
        # Load tasks list
        response = app.API_MP.get(app.API_MP.url_report)
        if not response.state:
            self.logger.error("Report tasks list load failed: {}".format(response.message))
            return response
        self.logger.debug("Report tasks list load succeeded")
        return MPAPIResponse(state=True, message=response.message.json())
