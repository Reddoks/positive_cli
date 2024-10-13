import logging
import datetime

from rich.progress import Progress
from rich import print as rich_print

import app
from app.app import EVENTS
from app.core.func import console_clear_up, fnmatch_ext
from app.mp.api import MPAPIResponse
from app.mp.func import (func_select_list_item,
                         func_get_list_ids_from_list)


class iface_MP_Report_Template:  # noqa
    def __init__(self, load=True):
        """
        Interface for report templates
        :param load: if false - do not load report templates list
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
        Get report template information
        :param pattern: string
        :param lst: report list
        :param dct: report dct
        """
        from app.mp.mp.iface_mp import ID_refs
        response = app.API_MP.get(app.API_MP.url_report)
        if not response.state:
            self.logger.error("Report list load failed: {}".format(response.message))
            return response
        reports_list = response.message.json()
        if isinstance(reports_list, list):
            if len(reports_list) == 0:
                rich_print("[yellow]Unfortunately you need at least one any report task in system to resolve blocks")
                return MPAPIResponse(state=False, message="No report task present in system")
        template_list = None
        # If pattern
        if pattern:
            template_list = self.get_by_pattern(pattern=pattern)
            if template_list:
                if len(template_list) > 1:
                    template_list = [func_select_list_item(template_list)]
                    if template_list == [False] or template_list == [None]:
                        return MPAPIResponse(state=False, message="No report template found")
                template_list = func_get_list_ids_from_list(template_list)
            else:
                return MPAPIResponse(state=False, message="No report template found")
        # If lst
        if lst:
            template_list = func_get_list_ids_from_list(lst)
        if dct:
            template_list = [dct]
        if template_list:
            out_list = []
            if len(template_list) > 5:
                rich_print("[yellow]It can get some time")
            try:
                id_refs = ID_refs(["group", "user", "query", "event_filter"])
            except KeyboardInterrupt:
                return MPAPIResponse(state=False, message="Operation interrupted")
            except BaseException as err:
                self.logger.error("Failed to initialize reference APIs: {}".format(err))
                return MPAPIResponse(state=False, message="Failed to initialize reference APIs: {}".format(err))
            with Progress() as progress:
                task = progress.add_task("Getting report templates information...", total=len(template_list))
                for item in template_list:
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
                        info["cli-mixin"] = {
                            "mixin_ref_version": app.MIXIN_REF_VERSION,
                            "kind": "report_template",
                            "timestamp": str(datetime.datetime.now()),
                            "product": app.API_MP.product,
                            "references_id": refs.message
                        }
                        out_list.append(info)
            console_clear_up(skip_line=True)
            if len(out_list) == 0:
                return MPAPIResponse(state=False, message="No report template found")
            return MPAPIResponse(state=True, message=out_list)
        else:
            return MPAPIResponse(state=False, message="No report template found")

    def create(self, source_spec: dict, disarm=True) -> MPAPIResponse:
        """
        Create report template from spec
        :param source_spec: source spec
        :param disarm: run in test mode
        """
        from app.mp.mp.iface_mp import ID_refs
        self.logger.debug("Trying to create report template from specification")
        # Prepare specification
        print("Trying to create report template: {}... ".format(source_spec.get("name")))
        exist = self.get_by_name_in_folder(template_name=source_spec.get("name"), folder_id=source_spec.get("folderId"))
        if exist:
            EVENTS.push(status="Fail", action="Create", instance="Report Template",
                        name=source_spec.get("name"), instance_id="N/A",
                        details="Report template {} exist. Can`t create".format(source_spec.get("name")))
            return MPAPIResponse(state=False,
                                 message="Report template {} exist. Can`t create".format(source_spec.get("name")))
        self.logger.debug("Report template {} not exist".format(source_spec.get("name")))
        try:
            id_refs = ID_refs(["group", "user", "query", "event_filter"])
        except KeyboardInterrupt:
            return MPAPIResponse(state=False, message="Operation interrupted")
        except BaseException as err:
            self.logger.error("Failed to initialize reference APIs: {}".format(err))
            return MPAPIResponse(state=False, message="Failed to initialize reference APIs: {}".format(err))
        out_spec = id_refs.replace(source_spec)
        if not out_spec.state:
            EVENTS.push(status="Fail", action="Create", instance="Report Template",
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
            print("Create report... ", end="")
            original_name = out_spec["name"]
            out_spec["name"] = out_spec["name"] + "_template"
            response = app.API_MP.post(app.API_MP.url_report, out_spec)
            if not response.state:
                rich_print("[red]FAIL")
                self.logger.error("Failed to create report: {}".format(response.message))
                EVENTS.push(status="Fail", action="Create", instance="Report",
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
                    self.logger.error("Failed to create blocks for report: {}".format(response.message))
                    EVENTS.push(status="Fail", action="Create", instance="Block",
                                name="N/A", instance_id="N/A",
                                details=response.message)
                    return response
                block_id = response.message.json()
                block_id = block_id.get("id")
                blocks.append({"id": block_id})
            rich_print("[green]OK")
            print("Update report... ", end="")
            out_spec["blocks"] = blocks
            response = app.API_MP.put(app.API_MP.url_report_instance.format(report_id), out_spec)
            if not response.state:
                rich_print("[red]FAIL")
                self.logger.error("Failed to update report: {}".format(response.message))
                EVENTS.push(status="Fail", action="Update", instance="Report",
                            name="N/A", instance_id=report_id,
                            details=response.message)
                return response
            rich_print("[green]OK")
            print("Create report template... ", end="")
            response = app.API_MP.post(app.API_MP.url_report_template_create.format(report_id), {
                "name": original_name,
                "description": out_spec.get("description"),
                "folderId": out_spec.get("folderId")
            })
            if not response.state:
                rich_print("[red]FAIL")
                self.logger.error("Failed to create report template: {}".format(response.message))
                EVENTS.push(status="Fail", action="Create", instance="Report Template",
                            name=original_name, instance_id="N/A",
                            details=response.message)
                return response
            rich_print("[green]OK")
            print("Cleanup... ", end="")
            response = app.API_MP.delete(app.API_MP.url_report_instance.format(report_id), report_id)
            if not response.state:
                rich_print("[red]FAIL")
                self.logger.error("Failed to delete source report: {}".format(response.message))
                EVENTS.push(status="Fail", action="Delete", instance="Report",
                            name=out_spec.get("name"), instance_id="N/A",
                            details=response.message)
                return response
            rich_print("[green]OK")
            self.logger.debug("Report template {} successfully created".format(original_name))
            return MPAPIResponse(state=True,
                                 message="Report template {} successfully created".format(original_name))
        else:
            return MPAPIResponse(state=False, message="Success - disarmed")

    def delete(self, target_id: str, disarm=True) -> MPAPIResponse:
        """
        Delete report template
        :param target_id: template ID string
        :param disarm: run in test mode
        """
        self.logger.debug("Trying to delete report template {}".format(target_id))
        if not app.app.GLOBAL_DISARM and not disarm:
            response = app.API_MP.delete(app.API_MP.url_report_template_instance.format(target_id), target_id)
        else:
            print("Success - disarmed")
            return MPAPIResponse(state=True, message="Success - disarmed")
        if not response.state:
            return response
        self.logger.debug("Report template {} successfully deleted".format(target_id))
        return MPAPIResponse(state=True, message="Report template {} successfully deleted".format(target_id))

    def get_by_pattern(self, pattern: str) -> list | None:
        """
        Get template by name or ID
        :param pattern: string name or ID
        """
        out_list = []
        # Trying to get by ID
        template = self.get_by_id(template_id=str(pattern))
        if template:
            return [template]
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
        Get template by name
        :param name: string
        """
        self.logger.debug("Trying to get report template for name: {}".format(name))
        for template in self.list:
            if template.get("name") == name:
                return template
        self.logger.debug("No report template found")
        return

    def get_by_id(self, template_id: str) -> dict | None:
        """
        Get template by ID
        :param template_id: string
        """
        self.logger.debug("Trying to get report template for ID: {}".format(template_id))
        for template in self.list:
            if template.get("id") == template_id:
                return template
        self.logger.debug("No report template found")
        return

    def get_by_name_in_folder(self, template_name: str, folder_id: str) -> dict | None:
        """
        Get template by name
        :param template_name: string
        :param folder_id: string
        """
        self.logger.debug("Trying to get report template for name: {}".format(template_name))
        for template in self.list:
            if template.get("name") == template_name and folder_id == template.get("folderId"):
                return template
        self.logger.debug("No report template found")
        return

    @staticmethod
    def remove_builtin(lst: list) -> list:
        """
        Remove built-in templates from list
        :param lst: source list
        """
        output = []
        for item in lst:
            if not item.get("isSystem"):
                output.append(item)
        return output

    def get_blocks(self, src_report: dict) -> MPAPIResponse:
        """
        Get blocks reference
        :param src_report: report structure
        """
        # Loading blocks information
        report_blocks_extended = []
        # Look any exist report to use
        response = app.API_MP.get(app.API_MP.url_report)
        if not response.state:
            self.logger.error("Report list load failed: {}".format(response.message))
            return response
        reports_list = response.message.json()
        report_id = reports_list[0].get("id")
        if src_report.get("blocks"):
            for item in src_report["blocks"]:
                block = self.__get_block_info(report_id, item.get("id"))
                if not block.state:
                    return block
                report_blocks_extended.append(block.message)
        return MPAPIResponse(state=True, message=report_blocks_extended)

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

    def __get_info(self, template_id: str) -> MPAPIResponse:
        """
        Get report template information
        :param template_id: string
        """
        self.logger.debug("Trying to load report template info")
        response = app.API_MP.get(app.API_MP.url_report_template_instance.format(template_id))
        if not response.state:
            self.logger.error("Report template information load failed: {}".format(response.message))
            return response
        self.logger.debug("Report template information load succeeded")
        return MPAPIResponse(state=True, message=response.message.json())

    def __load_list(self) -> MPAPIResponse:
        """
        Load report templates list
        """
        self.logger.debug("Trying to load report templates")
        # Load templates list
        response = app.API_MP.get(app.API_MP.url_report_template)
        if not response.state:
            self.logger.error("Report templates list load failed: {}".format(response.message))
            return response
        self.logger.debug("Report templates list load succeeded")
        return MPAPIResponse(state=True, message=response.message.json())
