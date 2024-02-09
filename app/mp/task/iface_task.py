import copy
import logging
import datetime

from rich import print as rich_print
from rich.progress import Progress
from rich.prompt import Prompt

import app
from app.app import EVENTS
from app.core.func import get_keys_from_dict, get_string_from_fmt, deep_get, console_clear_up, fnmatch_ext
from app.mp.api import MPAPIResponse
from app.mp.func import (func_get_list_by_pattern, func_select_list_item)
from app.mp.aec.iface_aec import iface_MP_AEC
from app.mp.asset.iface_asset import iface_MP_Asset


class iface_MP_Task:  # noqa
    def __init__(self, load=True):
        """
        Interface for tasks
        :param load: if false - do not load task list
        """
        self.logger = logging.getLogger("mp.iface_task")
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
        # AEC resolve decision
        self.decision_aec = False

    def __load_list(self) -> MPAPIResponse:
        """
        Task list loader
        """
        self.logger.debug("Trying to load task list")
        response = app.API_MP.get(app.API_MP.url_task)
        if not response.state:
            self.logger.error("'Task list load failed: {}".format(response.message))
            return response
        self.logger.debug("Task list load succeeded")
        return MPAPIResponse(state=True, message=response.message.json())

    def get_by_name(self, name: str) -> dict | None:
        """
        Get task by name
        :param name: string
        :return: task structure
        """
        for item in self.list:
            if item.get("name") == name:
                return item
        return

    def get_by_id(self, task_id: str) -> dict | None:
        """
        Get task by ID
        :param task_id: string
        :return: task structure
        """
        for item in self.list:
            if item.get("id") == task_id:
                return item
        return

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

    def info(self, pattern=None, lst=None, dct=None, resolve_assets=False, not_resolve=False) -> MPAPIResponse:
        """
        Get task information
        :param pattern: task name or ID string
        :param lst: tasks list
        :param resolve_assets: resolve asset targets if present
        :param not_resolve: do not resolve IDs
        :param dct: tasks dct
        """
        from app.mp.mp.iface_mp import ID_refs

        task_list = None
        # If pattern
        if pattern:
            self.logger.debug("Trying to get task info for pattern: {}".format(pattern))
            task_list = self.get_by_pattern(pattern=pattern)
            if task_list:
                self.logger.debug("Found {} task(s)".format(len(task_list)))
                if len(task_list) > 1:
                    task_list = [func_select_list_item(task_list)]
                    if task_list == [False] or task_list == [None]:
                        return MPAPIResponse(state=False, message="No task found")
            else:
                self.logger.debug("No task found")
                return MPAPIResponse(state=False, message="No task found")
        # If dict
        if dct:
            task_list = [dct]
        # If lst
        if lst:
            task_list = lst
        if task_list:
            out_list = []
            tasks_with_asset_targets = []
            if len(task_list) > 5:
                rich_print("[yellow]It can get some time")
            try:
                id_refs = ID_refs(["credential", "profile", "dictionary", "group", "scope", "aec"])
            except KeyboardInterrupt:
                return MPAPIResponse(state=False, message="Operation interrupted")
            except BaseException as err:
                self.logger.error("Failed to initialize reference APIs: {}".format(err))
                return MPAPIResponse(state=False, message="Failed to initialize reference APIs: {}".format(err))
            with Progress() as progress:
                task = progress.add_task("Getting task information...", total=len(task_list))
                try:
                    iface_asset = iface_MP_Asset()
                except KeyboardInterrupt:
                    return MPAPIResponse(state=False, message="Operation interrupted")
                except BaseException as err:
                    return MPAPIResponse(state=False, message="Unable to init MP asset API: {}".format(err))
                for item in task_list:
                    asset_targets = False
                    asset_include = []
                    asset_exclude = []
                    assets_has_unresolved = False
                    progress.update(task, advance=1)
                    info = self.__get_info(item.get("id"))
                    if info.state:
                        info = info.message
                        # Resolve assets to IP/FQDN
                        # Look asset targets
                        if info.get("include"):
                            if info["include"].get("assets"):
                                if len(info["include"]["assets"]) > 0:
                                    # Asset target is present
                                    asset_targets = True
                                    if not not_resolve and resolve_assets:
                                        for asst in info["include"]["assets"]:
                                            asset_ip = iface_asset.get_asset_ip(asst.get("id"))
                                            if asset_ip.state:
                                                if not asset_ip.message:
                                                    asset_include.append({
                                                        "name": asst.get("name"),
                                                        "id": asst.get("id"),
                                                        "resolved_to": "not resolved"
                                                    })
                                                    assets_has_unresolved = True
                                                    continue
                                                asset_ip = asset_ip.message
                                                asset_include.append({
                                                    "name": asst.get("name"),
                                                    "id": asst.get("id"),
                                                    "resolved_to": asset_ip
                                                })
                                                info["include"]["targets"].append(asset_ip)
                                            else:
                                                asset_include.append({
                                                    "name": asst.get("name"),
                                                    "id": asst.get("id"),
                                                    "resolved_to": "not resolved"
                                                })
                                                assets_has_unresolved = True
                                        info["include"]["assets"] = []
                        if info.get("exclude"):
                            if info["exclude"].get("assets"):
                                if len(info["exclude"]["assets"]) > 0:
                                    # Asset target is present
                                    asset_targets = True
                                    if not not_resolve and resolve_assets:
                                        for asst in info["exclude"]["assets"]:
                                            asset_ip = iface_asset.get_asset_ip(asst.get("id"))
                                            if asset_ip.state:
                                                if not asset_ip.message:
                                                    asset_include.append({
                                                        "name": asst.get("name"),
                                                        "id": asst.get("id"),
                                                        "resolved_to": "not resolved"
                                                    })
                                                    assets_has_unresolved = True
                                                    continue
                                                asset_ip = asset_ip.message
                                                asset_exclude.append({
                                                    "name": asst.get("name"),
                                                    "id": asst.get("id"),
                                                    "resolved_to": asset_ip
                                                })
                                                info["exclude"]["targets"].append(asset_ip)
                                            else:
                                                asset_exclude.append({
                                                    "name": asst.get("name"),
                                                    "id": asst.get("id"),
                                                    "resolved_to": "not resolved"
                                                })
                                                assets_has_unresolved = True
                                        info["exclude"]["assets"] = []
                        # Apply mixin for task
                        info["cli-mixin"] = {
                            "mixin_ref_version": app.MIXIN_REF_VERSION,
                            "kind": "task",
                            "timestamp": str(datetime.datetime.now()),
                            "product": app.API_MP.product,
                            "resolved": not not_resolve,
                            "asset_targets": asset_targets,
                            "asset_targets_resolved": resolve_assets,
                            "asset_has_unresolved": assets_has_unresolved
                        }
                        if not not_resolve:
                            self.logger.debug("Resolve IDs for task {}".format(info.get("name")))
                            refs = id_refs.get_references(info)
                            info["cli-mixin"]["references_id"] = refs.message
                        if resolve_assets:
                            info["cli-mixin"]["asset_targets_info"] = {
                                "include": asset_include,
                                "exclude": asset_exclude
                            }
                        if asset_targets:
                            tasks_with_asset_targets.append(info.get("name"))
                        out_list.append(info)
                    else:
                        EVENTS.push(action="Find", status="Fail",
                                    instance="Task",
                                    name=item.get("name"), instance_id=item.get("id"),
                                    details="Not found")
                        return MPAPIResponse(state=False, message="Task {} not found".format(item.get("name")))
            console_clear_up(skip_line=True)
            if len(tasks_with_asset_targets) > 0:
                print("-----")
                rich_print("[yellow]Tasks with assets as targets:")
                print(get_string_from_fmt(tasks_with_asset_targets, "yaml"))
                if resolve_assets:
                    rich_print("[green]Asset targets resolved for tasks.")
                else:
                    rich_print("[yellow]Asset targets not resolved for tasks. It means that targets in task stay "
                               "original i.e. contains asset IDs. If you use export, when you will import this "
                               "specification relevant assets must present in system.")
            if len(out_list) == 0:
                return MPAPIResponse(state=False, message="Tasks not found")
            return MPAPIResponse(state=True, message=out_list)
        else:
            return MPAPIResponse(state=False, message="Tasks not found")

    def history(self, pattern=None, lst=None) -> MPAPIResponse:
        """
        Get task history
        :param pattern: string name or ID
        :param lst: list of tasks
        :return: history structure
        """
        # If pattern
        if pattern:
            self.logger.debug("Trying to get task history for pattern: {}".format(pattern))
            tasks_list = func_get_list_by_pattern(self.list, pattern.lower())
            if tasks_list:
                self.logger.debug("Found {} task(s)".format(len(tasks_list)))
                if len(tasks_list) > 1:
                    tasks_list = [func_select_list_item(tasks_list)]
                    if tasks_list == [False] or tasks_list == [None]:
                        return MPAPIResponse(state=False, message="No task found")
                response = self.__get_history(tasks_list[0]["id"])
                if response.state:
                    return MPAPIResponse(state=True, message=response.message)
                else:
                    return response
            else:
                self.logger.debug("No task found")
                return MPAPIResponse(state=False, message="No task found")
        elif lst:
            if len(lst) > 1:
                return MPAPIResponse(state=False, message="History for multiple task is not allowed")
            response = self.__get_history(lst[0]["id"])
            if response.state:
                return MPAPIResponse(state=True, message=response.message)
            else:
                return response
        else:
            self.logger.debug("Missing pattern or task data to get task history")
            return MPAPIResponse(state=False, message="Missing pattern or task data to get task history")

    # Create task
    def create(self, source_spec: dict, drop_aec: bool, disarm=True) -> MPAPIResponse:
        """
        Create task from specification
        :param source_spec: spec structure
        :param drop_aec: flag to drop_aec from source spec
        :param disarm: run in test mode
        """
        self.logger.debug("Trying to create task from specification")
        # Reload task list
        response = self.__load_list()
        if not response.state:
            EVENTS.push(status="Fail", action="Create", instance="Task",
                        name=source_spec.get("name"), instance_id="N/A",
                        details=response.message)
            return response
        self.list = response.message
        # Prepare specification
        print("Trying to create task: {}... ".format(source_spec.get("name")))
        out_spec = self.__prepare_spec_for_creation(source_spec, drop_aec=drop_aec)
        if not out_spec.state:
            return MPAPIResponse(state=False, message=out_spec.message)
        if not app.app.GLOBAL_DISARM and not disarm:
            self.logger.debug("Trying to request API for creation")
            response = app.API_MP.post(app.API_MP.url_task, out_spec.message)
            # If response was failed, but with aec tags in response means aec should be defined
            if "core.scanning.task.aec.not.specified.format.error" in response.message:
                rich_print("[red]Task {} can`t be with automatic AEC. It should be defined")
                try:
                    iface_aec = iface_MP_AEC()
                except KeyboardInterrupt:
                    return MPAPIResponse(state=False, message="Operation interrupted")
                except BaseException as err:
                    return MPAPIResponse(state=False, message="Failed to initialize AEC API: {}".format(err))
                if len(iface_aec.list) == 0:
                    return MPAPIResponse(state=False,
                                         message="No AEC available. Unable to create {}".format(
                                             out_spec.message.get("name")))
                aec_info = iface_aec.get_aec_picker("AEC name: ")
                if not aec_info.state:
                    return MPAPIResponse(state=False,
                                         message="No AEC available. Unable to create {}".format(
                                             out_spec.message.get("name")))
                modified = copy.deepcopy(out_spec.message)
                modified["agent"] = aec_info.message.get("id")
                response_second = app.API_MP.post(app.API_MP.url_task, modified)
                if response_second.state:
                    self.logger.debug("Task {} successfully created".format(response_second.message.json().get("id")))
                    return MPAPIResponse(state=True,
                                         message="MaxPatrol task created: {}".format(
                                             response_second.message.json().get("id")))
                else:
                    return response_second
            if not response.state:
                return response
            self.logger.debug("Task {} successfully created".format(response.message.json().get("id")))
            return MPAPIResponse(state=True,
                                 message="Task {} successfully created".format(response.message.json().get("id")))
        else:
            return MPAPIResponse(state=True, message="Success - disarmed")

    def update(self, source_spec: dict, drop_aec: bool, disarm=True) -> MPAPIResponse:
        """
        Update task from specification
        :param source_spec: spec structure
        :param drop_aec: flag to drop original AECs
        :param disarm: run in test mode
        """
        self.logger.debug("Trying to update task from specification")
        # Prepare specification for update
        print("Trying to update task: {}... ".format(source_spec.get("name")))
        out_info = self.__prepare_spec_for_update(source_spec, drop_aec=drop_aec)
        if not out_info.state:
            return MPAPIResponse(state=False, message=out_info.message)
        if not app.app.GLOBAL_DISARM and not disarm:
            self.logger.debug("Trying to request API for update")
            response = app.API_MP.put(app.API_MP.url_task_instance.format(out_info.message.get("id")),
                                      out_info.message.get("spec"))
            # If response was failed, but with aec tags in response means aec should be defined
            if "core.scanning.task.aec.not.specified.format.error" in response.message:
                rich_print("[red]Task {} can`t be with automatic AEC. It should be defined")
                try:
                    iface_aec = iface_MP_AEC()
                except KeyboardInterrupt:
                    return MPAPIResponse(state=False, message="Operation interrupted")
                except BaseException as err:
                    return MPAPIResponse(state=False, message="Failed to initialize AEC API: {}".format(err))
                if len(iface_aec.list) == 0:
                    return MPAPIResponse(state=False,
                                         message="No AEC available. Unable to create {}".format(
                                             out_info.message["spec"].get("name")))
                aec_info = iface_aec.get_aec_picker("AEC name: ")
                if not aec_info.state:
                    return MPAPIResponse(state=False,
                                         message="No AEC available. Unable to create {}".format(
                                             out_info.message["spec"].get("name")))
                modified = copy.deepcopy(out_info.message["spec"])
                modified["agent"] = aec_info.message.get("id")
                response_second = app.API_MP.put(app.API_MP.url_task + '/' + out_info.message["id"], modified)
                if response_second.state:
                    self.logger.debug("Task successfully updated")
                    return MPAPIResponse(state=True,
                                         message="MaxPatrol task {} updated".format(modified.get("name")))
                else:
                    return response_second
            if not response.state:
                return response
            self.logger.debug("Task {} successfully updated".format(out_info.message["spec"].get("name")))
            return MPAPIResponse(state=True,
                                 message="Task {} successfully updated".format(out_info.message["spec"].get("name")))
        else:
            return MPAPIResponse(state=True, message="Success - disarmed")

    def delete(self, data: str, disarm=True) -> MPAPIResponse:
        """
        Delete task
        :param data: string ID
        :param disarm: run in test mode
        """
        self.logger.debug("Trying to delete task {}".format(data))
        if not app.app.GLOBAL_DISARM and not disarm:
            response = app.API_MP.delete(app.API_MP.url_task_instance.format(data), data)
        else:
            print("Success - disarmed")
            return MPAPIResponse(state=True, message="Success - disarmed")
        if not response.state:
            return response
        self.logger.info("Task {} successfully deleted".format(data))
        return MPAPIResponse(state=True, message="Task {} successfully deleted".format(data))

    # Start task
    def start(self, data: str, disarm=True) -> MPAPIResponse:
        """
        Start task execution
        :param data: string ID
        :param disarm: run in test mode
        """
        self.logger.debug("Trying to start task {}".format(data))
        if not app.app.GLOBAL_DISARM and not disarm:
            response = app.API_MP.post(app.API_MP.url_task_instance_start.format(data), data)
        else:
            return MPAPIResponse(state=True, message="Success - disarmed")
        if not response.state:
            return response
        self.logger.debug("Task {} successfully started".format(data))
        return MPAPIResponse(state=True, message="Task {} successfully started".format(data))

    def stop(self, data: str, disarm=True) -> MPAPIResponse:
        """
        Stop task execution
        :param data: string ID
        :param disarm: run in test mode
        """
        self.logger.debug("Trying to stop task {}".format(data))
        if not app.app.GLOBAL_DISARM and not disarm:
            response = app.API_MP.post(app.API_MP.url_task_instance_stop.format(data), data)
        else:
            return MPAPIResponse(state=True, message="Success - disarmed")
        if not response.state:
            return response
        self.logger.debug("Task {} successfully stopped".format(data))
        return MPAPIResponse(state=True, message="Task {} successfully stopped".format(data))

    def suspend(self, data: str, disarm=True) -> MPAPIResponse:
        """
        Suspend task execution
        :param data: string ID
        :param disarm: run in test mode
        """
        self.logger.debug("Trying to suspend task {}".format(data))
        if not app.app.GLOBAL_DISARM and not disarm:
            response = app.API_MP.post(app.API_MP.url_task_instance_suspend.format(data), data)
        else:
            return MPAPIResponse(state=True, message="Success - disarmed")
        if not response.state:
            return response
        self.logger.debug("Task {} successfully suspended".format(data))
        return MPAPIResponse(state=True, message="Task {} successfully suspended".format(data))

    def __prepare_spec_for_update(self, source_spec: dict, drop_aec=False) -> MPAPIResponse:
        """
        Prepare specification for update request
        :param source_spec: spec structure
        :param drop_aec: drop original AECs
        :return: prepared spec
        """
        from app.mp.mp.iface_mp import ID_refs
        self.logger.debug("Build task specification for update. Task: {}".format(source_spec.get("name")))
        foreign = False
        out_spec = copy.deepcopy(source_spec)
        # Look task is exist: two ways - by ID and by Name
        # If spec exist by ID it means that spec was exported from current system
        exists = self.get_by_id(source_spec.get("id"))
        if not exists:
            foreign = True
            self.logger.debug("Specification is foreign")
        # Second chance - find by name
        exists = self.get_by_name(source_spec.get("name"))
        if not exists:
            EVENTS.push(status="Fail", action="Create", instance="Task",
                        name=source_spec.get("name"), instance_id=source_spec.get("id"),
                        details="Task not exist")
            return MPAPIResponse(state=False, message="Task {} not exist".format(source_spec.get("name")))
        # If specification is not foreign we can just normalize specification and send to update
        if not foreign:
            # If not foreign, but name is different may indicated mistake
            if source_spec.get("name") != exists.get("name"):
                rich_print("[yellow]Looks like you want to rename task or mistake here:")
                rich_print("{} -> {}".format(exists.get("name"), source_spec.get("name")))
                try:
                    decision = Prompt.ask("Continue? ", choices=["y", "n"], default="n")
                except KeyboardInterrupt:
                    return MPAPIResponse(state=False, message="Operation interrupted")
                if decision == "n":
                    return MPAPIResponse(state=False, message="Task update canceled")
            out_spec = self.__normalize_spec(out_spec)
            if drop_aec:
                del out_spec["agent"]
            del out_spec["cli-mixin"]
            self.logger.debug("Build specification complete")
            return MPAPIResponse(state=True, message={"spec": out_spec, "id": exists["id"]})
        else:
            # If foreign, specification should be resolved
            # Look specification resolved or not
            if not source_spec.get("cli-mixin", {}).get("resolved"):
                EVENTS.push(status="Fail", action="Create", instance="Task",
                            name=source_spec.get("name"), instance_id=source_spec.get("id"),
                            details="Specification with not resolved IDs. Use export without --ignore_resolve`")
                return MPAPIResponse(state=False,
                                     message="Specification for task {} with not "
                                             "resolved IDs. Use export without "
                                             "--ignore_resolve`".format(source_spec.get("name")))
            # Resolve properties
            try:
                id_refs = ID_refs(["credential", "profile", "dictionary", "group", "scope", "aec"])
            except KeyboardInterrupt:
                return MPAPIResponse(state=False, message="Operation interrupted")
            except BaseException as err:
                self.logger.error("Failed to initialize reference APIs: {}".format(err))
                return MPAPIResponse(state=False, message="Failed to initialize reference APIs: {}".format(err))
            out_spec = id_refs.replace(out_spec, drop_aec=drop_aec)
            if not out_spec.state:
                EVENTS.push(status="Fail", action="Create", instance="Task",
                            name=source_spec.get("name"), instance_id="N/A",
                            details="Failed to resolve reference IDs")
                return out_spec
            else:
                out_spec = out_spec.message
            # Normalize AEC
            if deep_get(source_spec, "agent.name"):
                if not deep_get(out_spec, "agent.id"):
                    del out_spec["agent"]
                else:
                    out_spec["agent"] = deep_get(out_spec, "agent.id")
            else:
                self.logger.debug("Task {} not has AEC defined".format(source_spec.get("name")))
                del out_spec["agent"]
            # Normalize Profile
            if deep_get(source_spec, "profile.name"):
                out_spec["profile"] = deep_get(out_spec, "profile.id")
            else:
                self.logger.debug("Task {} not has profile defined".format(source_spec.get("name")))
                EVENTS.push(status="Fail", action="Create", instance="Task",
                            name=source_spec.get("name"), instance_id=source_spec.get("id"),
                            details="Specification with not defined profile. Specification must contain profile")
                return MPAPIResponse(state=False,
                                     message="Task {} not has profile defined".format(source_spec.get("name")))
            # Normalize HostDiscovery
            if deep_get(out_spec, "hostDiscovery.enabled"):
                if out_spec["hostDiscovery"]["enabled"]:
                    if deep_get(out_spec, "hostDiscovery.profile"):
                        out_spec["hostDiscovery"]["profile"] = deep_get(out_spec, "hostDiscovery.profile.id")
            else:
                if "hostDiscovery" not in out_spec:
                    self.logger.debug("Task {} not has hostDiscovery defined".format(out_spec.get("name")))
                    EVENTS.push(status="Fail", action="Create", instance="Task",
                                name=out_spec.get("name"), instance_id=out_spec.get("id"),
                                details="Specification with not defined hostDiscovery. "
                                        "Specification must contain hostDiscovery")
                    return MPAPIResponse(state=False, message="Task {} not has hostDiscovery "
                                                              "defined".format(out_spec.get("name")))
            # Normalize Scope
            if deep_get(out_spec, "scope.name"):
                out_spec["scope"] = deep_get(out_spec, "scope.id")
            else:
                self.logger.debug("Task {} not has scope defined".format(out_spec.get("name")))
                EVENTS.push(status="Fail", action="Create", instance="Task",
                            name=out_spec.get("name"), instance_id=out_spec.get("id"),
                            details="Specification with not defined scope. "
                                    "Specification must contain scope")
                return MPAPIResponse(state=False, message="Task {} not has scope defined".format(out_spec.get("name")))
            # Look for unresolved assets
            if out_spec.get("cli-mixin", {}).get("asset_has_unresolved"):
                if out_spec["cli-mixin"]["asset_has_unresolved"]:
                    rich_print("[red]Looks like one or some asset targets was not "
                               "resolved in task: ", end="")
                    print(out_spec.get("name"))
                    try:
                        decision = Prompt.ask("Would you like to continue import task?",
                                              choices=["y", "n"], default="y")
                    except KeyboardInterrupt:
                        return MPAPIResponse(state=False, message="Operation interrupted")
                    if decision == "n":
                        EVENTS.push(status="Fail", action="Create", instance="Task",
                                    name=out_spec.get("name"), instance_id=out_spec.get("id"),
                                    details="Some asset targets not resolved for task {}".format(
                                        out_spec.get("name")))
                        return MPAPIResponse(state=False,
                                             message="Asset targets not resolved "
                                                     "for task {}".format(out_spec.get("name")))
            # Check credentials
            if "credentials" not in out_spec:
                self.logger.debug("Task {} not has credentials defined".format(out_spec.get("name")))
                EVENTS.push(status="Fail", action="Create", instance="Task",
                            name=out_spec.get("name"), instance_id=out_spec.get("id"),
                            details="Specification with not defined credentials. "
                                    "Specification must contain credentials")
                return MPAPIResponse(state=False, message="Task {} not has credentials".format(out_spec.get("name")))
            self.logger.debug("Build specification complete")
            return MPAPIResponse(state=True, message={"spec": out_spec, "id": exists.get("id")})

    def __prepare_spec_for_creation(self, source_spec: dict, drop_aec=False) -> MPAPIResponse:
        """
        Prepare specification for create request
        :param source_spec: spec structure
        :param drop_aec: drop original AECs
        :return: prepared spec
        """
        from app.mp.mp.iface_mp import ID_refs
        self.logger.debug("Build task specification for creation. Task: {}".format(source_spec.get("name")))
        out_spec = copy.deepcopy(source_spec)
        # Look task is exist
        exists = self.get_by_name(source_spec.get("name"))
        if exists:
            EVENTS.push(status="Fail", action="Create", instance="Task",
                        name=source_spec.get("name"), instance_id=source_spec.get("id"),
                        details="Task exist. Can`t create")
            return MPAPIResponse(state=False, message="Task {} exist. Can`t create".format(source_spec.get("name")))
        self.logger.debug("Task {} not exist".format(source_spec.get("name")))
        try:
            id_refs = ID_refs(["credential", "profile", "dictionary", "group", "scope", "aec"])
        except KeyboardInterrupt:
            return MPAPIResponse(state=False, message="Operation interrupted")
        except BaseException as err:
            self.logger.error("Failed to initialize reference APIs: {}".format(err))
            return MPAPIResponse(state=False, message="Failed to initialize reference APIs: {}".format(err))
        # Look specification resolved or not
        if not source_spec.get("cli-mixin", {}).get("resolved"):
            EVENTS.push(status="Fail", action="Create", instance="Task",
                        name=source_spec.get("name"), instance_id="N/A",
                        details="Specification with not resolved IDs. Use export without --ignore_resolve`")
            return MPAPIResponse(state=False,
                                 message="Specification for task {} with not "
                                         "resolved IDs. Use export without "
                                         "--ignore_resolve`".format(source_spec.get("name")))
        # Check asset targets
        if source_spec["cli-mixin"].get("asset_targets"):
            if not source_spec["cli-mixin"].get("asset_targets_resolved"):
                rich_print("[yellow]Original task contains asset instances in targets, but instances not resolved")
                rich_print("[yellow]If this specification foreign for this system, task creation may fail")
                rich_print("[bright_black]You can resolve asset targets using --resolve_assets on export")
            if (source_spec["cli-mixin"].get("asset_targets_resolved") and
                    source_spec["cli-mixin"].get("asset_has_unresolved")):
                rich_print("[yellow]Original task contains asset instances in targets, but some instances not resolved")
                rich_print("[yellow]It means that some targets will missing in imported task - you should check it")
        # Resolve properties
        out_spec = id_refs.replace(out_spec, drop_aec=drop_aec)
        if not out_spec.state:
            EVENTS.push(status="Fail", action="Create", instance="Task",
                        name=source_spec.get("name"), instance_id="N/A",
                        details="Failed to resolve reference IDs")
            return out_spec
        else:
            out_spec = out_spec.message
        # Normalize AEC
        if deep_get(out_spec, "agent.name"):
            if not deep_get(out_spec, "agent.id"):
                del out_spec["agent"]
            else:
                out_spec["agent"] = deep_get(out_spec, "agent.id")
        # Normalize Profile
        if deep_get(source_spec, "profile.name"):
            out_spec["profile"] = deep_get(out_spec, "profile.id")
        else:
            self.logger.debug("Task {} not has profile defined".format(source_spec.get("name")))
            EVENTS.push(status="Fail", action="Create", instance="Task",
                        name=source_spec.get("name"), instance_id="N/A",
                        details="Specification with not defined profile. Specification must contain profile")
            return MPAPIResponse(state=False, message="Task {} not has profile defined".format(source_spec.get("name")))
        # Normalize HostDiscovery
        if deep_get(out_spec, "hostDiscovery.enabled"):
            if out_spec["hostDiscovery"]["enabled"]:
                if deep_get(out_spec, "hostDiscovery.profile"):
                    out_spec["hostDiscovery"]["profile"] = deep_get(out_spec, "hostDiscovery.profile.id")
        else:
            if "hostDiscovery" not in out_spec:
                self.logger.debug("Task {} not has hostDiscovery defined".format(out_spec.get("name")))
                EVENTS.push(status="Fail", action="Create", instance="Task",
                            name=out_spec.get("name"), instance_id="N/A",
                            details="Specification with not defined hostDiscovery. "
                                    "Specification must contain hostDiscovery")
                return MPAPIResponse(state=False, message="Task {} not has hostDiscovery "
                                                          "defined".format(out_spec.get("name")))
        # Normalize Scope
        if deep_get(out_spec, "scope.name"):
            out_spec["scope"] = deep_get(out_spec, "scope.id")
        else:
            self.logger.debug("Task {} not has scope defined".format(out_spec.get("name")))
            EVENTS.push(status="Fail", action="Create", instance="Task",
                        name=out_spec.get("name"), instance_id="N/A",
                        details="Specification with not defined scope. "
                                "Specification must contain scope")
            return MPAPIResponse(state=False, message="Task {} not has scope defined".format(out_spec.get("name")))
        # Look for unresolved assets
        if out_spec.get("cli-mixin", {}).get("asset_has_unresolved"):
            if out_spec["cli-mixin"]["asset_has_unresolved"]:
                rich_print("[red]Looks like one or some asset targets was not "
                           "resolved in task: ", end="")
                print(out_spec.get("name"))
                try:
                    decision = Prompt.ask("Would you like to continue import task?",
                                          choices=["y", "n"], default="y")
                except KeyboardInterrupt:
                    return MPAPIResponse(state=False, message="Operation interrupted")
                if decision == "n":
                    EVENTS.push(status="Fail", action="Create", instance="Task",
                                name=out_spec.get("name"), instance_id="N/A",
                                details="Some asset targets not resolved for task {}".format(out_spec.get("name")))
                    return MPAPIResponse(state=False,
                                         message="Asset targets not resolved "
                                                 "for task {}".format(out_spec.get("name")))
        # Check credentials
        if "credentials" not in out_spec:
            self.logger.debug("Task {} not has credentials defined".format(out_spec.get("name")))
            EVENTS.push(status="Fail", action="Create", instance="Task",
                        name=out_spec.get("name"), instance_id="N/A",
                        details="Specification with not defined credentials. "
                                "Specification must contain credentials")
            return MPAPIResponse(state=False, message="Task {} not has credentials".format(out_spec.get("name")))
        self.logger.debug("Build task specification for task: {} success".format(out_spec.get("name")))
        del out_spec["cli-mixin"]
        return MPAPIResponse(state=True, message=out_spec)

    @staticmethod
    def __normalize_spec(source_spec: dict) -> dict:
        """
        Normalize spec for request
        :param source_spec: source spec
        :return: result spec
        """
        out_spec = copy.deepcopy(source_spec)
        if source_spec.get("agent"):
            if not source_spec["agent"]:
                del out_spec["agent"]
            else:
                out_spec["agent"] = source_spec["agent"].get("id")
        out_spec["scope"] = source_spec["scope"].get("id")
        out_spec["profile"] = source_spec["profile"].get("id")
        if deep_get(source_spec, "hostDiscovery.enabled"):
            if source_spec["hostDiscovery"]["enabled"]:
                out_spec["hostDiscovery"]["profile"] = source_spec["hostDiscovery"]["profile"]["id"]
        return out_spec

    def __get_history(self, task_id: str) -> MPAPIResponse:
        """
        Get task history
        :param task_id: string
        """
        # Getting history
        self.logger.info("Trying to get history for task " + task_id)
        response = app.API_MP.get(app.API_MP.url_task_history.format(task_id))
        if not response.state:
            self.logger.error("Failed request status: {}".format(response.message))
            return response
        return MPAPIResponse(state=True, message=response.message.json().get("items"))

    # Get task info by id
    def __get_info(self, task_id: str) -> MPAPIResponse:
        """
        Get task information
        :param task_id: string
        """
        self.logger.debug("Trying to load scanning task info")
        response = app.API_MP.get(app.API_MP.url_task_instance.format(task_id))
        if not response.state:
            self.logger.error("'Scanning task information load failed: {}".format(response.message))
            return response
        self.logger.debug("'Scanning task information load succeeded")
        return MPAPIResponse(state=True, message=response.message.json())

    @staticmethod
    def reduce_list(data: dict | list) -> dict | list:
        """
        Task list reducer
        """
        if isinstance(data, list):
            output = []
            for item in data:
                output.append(
                    get_keys_from_dict(item, ["status", "name", "agent.name", "profile.name", "lastRun",
                                              "lastRunErrorLevel"]))
        else:
            output = get_keys_from_dict(data, ["status", "name", "agent.name", "profile.name", "lastRun",
                                               "lastRunErrorLevel"])
        return output

    @staticmethod
    def reduce_info(data: dict | list) -> dict | list:
        """
        Task info reducer
        """
        if isinstance(data, list):
            output = []
            for item in data:
                agent = None
                module = None
                profile = None
                if item.get("agent"):
                    agent = item.get("agent").get("name")
                if item.get("module"):
                    module = item.get("module").get("name")
                if item.get("profile"):
                    module = item.get("profile").get("name")
                output.append({
                    "id": item.get("id"),
                    "name": item.get("name"),
                    "description": item.get("description"),
                    "agent.name": agent,
                    "module.name": module,
                    "profile.name": profile,
                    "overrides": item.get("overrides")
                })
        else:
            agent = None
            module = None
            profile = None
            if data.get("agent"):
                agent = data.get("agent").get("name")
            if data.get("module"):
                module = data.get("module").get("name")
            if data.get("profile"):
                module = data.get("profile").get("name")
            output = {
                    "id": data.get("id"),
                    "name": data.get("name"),
                    "description": data.get("description"),
                    "agent.name": agent,
                    "module.name": module,
                    "profile.name": profile,
                    "overrides": data.get("overrides")
                }
        return output

    @staticmethod
    def reduce_history(data: dict | list) -> dict | list:
        """
        Task history reducer
        """
        if isinstance(data, list):
            output = []
            for item in data:
                output.append(
                    get_keys_from_dict(item, ["status", "id", "startedAt", "finishedAt", "errorStatus"]))
        else:
            output = get_keys_from_dict(data, ["status", "id", "startedAt", "finishedAt", "errorStatus"])
        return output
