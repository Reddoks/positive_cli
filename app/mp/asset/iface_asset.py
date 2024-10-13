import time
import logging
import app
from app.mp.api import MPAPIResponse
from app.core import deep_get
from app.mp.iface_pdql import iface_MP_PDQL
from app.mp.asset.iface_asset_group import iface_MP_Group
from app.app import EVENTS
from app.mp.func import func_select_list_item
from rich.prompt import Prompt
from rich import print as rich_print


class iface_MP_Asset:  # noqa
    def __init__(self):
        """
        Interface for asset operations
        """
        self.logger = logging.getLogger("mp.iface_asset")

    def list(self, group_filter=None, asset_filter=None) -> MPAPIResponse:
        if group_filter == [None]:
            group_filter = None
        if asset_filter == [None]:
            asset_filter = None
        query = 'select(@Host, Host.IpAddress, Host.OsName, Host.@CreationTime, Host.@UpdateTime) | sort(@Host ASC)'
        self.logger.debug("Trying to get PDQL query: {}".format(query))
        try:
            request_object = iface_MP_PDQL(query, filter={"groupIDs": group_filter, "assetIDs": asset_filter})
        except BaseException as err:
            return MPAPIResponse(state=False,
                                 message="PDQL query failed: {}".format(err))
        if not request_object:
            self.logger.error("Error during PDQL request")
            return MPAPIResponse(state=False, message="Error during PDQL request")
        row_count = request_object.get_count().message
        self.logger.debug("PDQL request success - got {} records".format(row_count))
        rich_print("[bright_black]PDQL request success - got {} record(s)".format(row_count))
        return MPAPIResponse(state=True, message=request_object)

    def query(self, query=None, group_filter=None, asset_filter=None) -> MPAPIResponse:
        """
        Get asset query object
        If query string is empty, it will use
        "select(@Host, Host.@Id, host.IpAddress, Host.OsName, Host.@CreationTime, Host.@UpdateTime) | sort(@Host ASC)"
        :param query: string
        :param group_filter: Groups for query filter
        :param asset_filter: Assets for query filter
        """
        if not query:
            query = 'select(@Host, Host.IpAddress, Host.OsName, Host.@CreationTime, Host.@UpdateTime) | sort(@Host ASC)'
        self.logger.debug("Trying to get PDQL query: {}".format(query))
        rich_print("[bright_black]Trying to get PDQL query: {}".format(query))
        try:
            request_object = iface_MP_PDQL(query, filter={"groupIDs": group_filter, "assetIDs": asset_filter})
        except BaseException as err:
            return MPAPIResponse(state=False,
                                 message="PDQL query failed: {}".format(err))
        if not request_object:
            self.logger.error("Error during PDQL request")
            return MPAPIResponse(state=False, message="Error during PDQL request")
        row_count = request_object.get_count().message
        self.logger.debug("PDQL request success - got {} record(s)".format(row_count))
        rich_print("[bright_black]PDQL request success - got {} records".format(row_count))
        return MPAPIResponse(state=True, message=request_object)

    def delete(self, asset_id: str, disarm=True) -> MPAPIResponse:
        """
        Delete asset
        :param asset_id: string ID
        :param disarm: run in test mode
        """
        self.logger.debug("Trying to delete asset {}".format(asset_id))
        print("Trying to delete asset {}".format(asset_id))
        if not app.app.GLOBAL_DISARM and not disarm:
            op_request = app.API_MP.post(app.API_MP.url_asset_operations_remove, data={"assetsIds": [asset_id]})
        else:
            print("Success - disarmed")
            return MPAPIResponse(state=True, message="Success - disarmed")
        if not op_request.state:
            EVENTS.push(status="Fail", action="Delete", instance="Asset",
                        name="N/A", instance_id=asset_id,
                        details=op_request.message)
            self.logger.error("Asset API response failed. Can`t delete")
            self.logger.error(op_request.message)
            return op_request
        retries = 0
        while True:
            retries += 1
            if retries == 2:
                print("Slow API responsiveness")
            if retries == 10:
                EVENTS.push(status="Fail", action="Delete", instance="Asset",
                            name="N/A", instance_id=asset_id,
                            details="API can`t process deletion request (no response)")
                return MPAPIResponse(state=False,
                                     message="API can`t process deletion request (no response)")
            op_id = op_request.message.json()
            completion = app.API_MP.get(app.API_MP.url_asset_operations_remove_state.format(op_id.get("operationId")))
            if not completion.state:
                try:
                    time.sleep(5)
                except KeyboardInterrupt:
                    return MPAPIResponse(state=False, message="Operation interrupted")
                continue
            else:
                EVENTS.checkout()
                return MPAPIResponse()

    def member(self, asset_id: str) -> MPAPIResponse:
        """
        Get list of groups where asset is member
        """
        self.logger.debug("Trying to get groups for asset {}".format(asset_id))
        query = 'select(@Host, Host.@Id) | filter(Host.@Id = {})'.format(asset_id)
        self.logger.debug("Trying to get PDQL query: {}".format(query))
        try:
            request_object = iface_MP_PDQL(query, filter={"groupIDs": None, "assetIDs": None})
        except BaseException as err:
            return MPAPIResponse(state=False,
                                 message="PDQL query failed: {}".format(err))
        if not request_object:
            self.logger.error("Error during PDQL request")
            return MPAPIResponse(state=False, message="Error during PDQL request")
        row_count = request_object.get_count().message
        # Set selector
        response = app.API_MP.put(app.API_MP.url_pdql_selection_rows.format(request_object.token), data=[1])
        if not response.state:
            max_retries = 10
            super_retries = 2
            while max_retries > 0 and not response.state:
                response = app.API_MP.put(app.API_MP.url_pdql_selection_rows.format(request_object.token), data=[1])
                if not response.state:
                    max_retries -= 1
                    time.sleep(2)
                    # If failed, re-request PDQL
                    if super_retries > 0:
                        super_retries -= 1
                        max_retries = 5
                        try:
                            request_object = iface_MP_PDQL(query, filter={"groupIDs": None, "assetIDs": None})
                        except BaseException as err:
                            return MPAPIResponse(state=False,
                                                 message="PDQL query failed: {}".format(err))
                        if not request_object:
                            self.logger.error("Error during PDQL request")
                            return MPAPIResponse(state=False, message="Error during PDQL request")
            if not response.state:
                return response
        # Getting result
        response = app.API_MP.get(app.API_MP.url_asset_membership_groups.format(request_object.token))
        if not response.state:
            return response
        # Parse response
        id_list = []
        for itm in response.message.json():
            id_list.append({"id": itm.get("groupId")})
        # Getting group structure
        try:
            iface_group = iface_MP_Group()
        except KeyboardInterrupt:
            return MPAPIResponse(state=False, message="Operation interrupted")
        except BaseException as err:
            return MPAPIResponse(state=False, message="MP group API init failed: {}".format(err))
        out_list = []
        for itm in id_list:
            group_info = iface_group.get_by_id(group_id=itm.get("id"))
            if group_info:
                out_list.append(group_info)
        return MPAPIResponse(state=True, message=out_list)

    def get_scopes_list(self) -> MPAPIResponse:
        """
        Get list of infrastructure scopes
        :return: scopes list
        """
        self.logger.debug("Trying to load scopes list")
        response = app.API_MP.get(app.API_MP.url_asset_scope)
        if not response.state:
            self.logger.error("Scopes list load failed: {}".format(response.message))
            return response
        self.logger.debug("Scopes list load succeeded")
        return MPAPIResponse(state=True, message=response.message.json())

    def get_scope_by_name(self, name: str) -> MPAPIResponse:
        """
        Get infrastructure scope by name
        :param name: string
        :return: infrastructure scope
        """
        self.logger.debug("Trying to get scope {}".format(name))
        response = app.API_MP.get(app.API_MP.url_asset_scope)
        if not response.state:
            self.logger.error("Scopes list load failed: {}".format(response.message))
            return response
        for scope in response.message.json():
            if name == scope.get("name"):
                return MPAPIResponse(state=True, message=scope)
        return MPAPIResponse(state=False, message="Scope {} not found".format(name))

    def get_asset_state(self, asset_id: str) -> MPAPIResponse:
        """
        Get asset state information
        :param asset_id: string
        """
        self.logger.debug("Trying to get asset state")
        response = app.API_MP.get(app.API_MP.url_asset_state.format(asset_id))
        if not response.state:
            self.logger.error("Asset state load failed: {}".format(response.message))
            return MPAPIResponse(state=False, message="Asset state load failed: {}".format(response.message))
        asset_info = response.message.json()
        if len(asset_info) == 0:
            self.logger.error("Asset state load failed: {}".format(response.message))
            return MPAPIResponse(state=False, message="Asset state load failed: {}".format(response.message))
        return MPAPIResponse(state=True, message=asset_info[0])

    def get_asset_passport(self, asset_id: str) -> MPAPIResponse:
        """
        Get asset passport information
        :param asset_id: string
        :return: passport information
        """
        self.logger.debug("Trying to get asset passport")
        response = app.API_MP.get(app.API_MP.url_asset_passport + '/{}/passport'.format(asset_id))
        if not response.state:
            self.logger.error("Passport info load failed: {}".format(response.message))
            return MPAPIResponse(state=False, message="Passport info load failed: {}".format(response.message))
        self.logger.debug("Asset passport for {} load succeeded".format(asset_id))
        return MPAPIResponse(state=True, message=response.message.json())

    # Get Asset Configuration
    def get_asset_config(self, asset_id: str) -> MPAPIResponse:
        """
        Get asset configuration information
        :param asset_id: string
        :return: configuration information
        """
        self.logger.debug("Trying to get asset configuration")
        response = app.API_MP.get(app.API_MP.url_asset_config + '/{}'.format(asset_id))
        if not response.state:
            self.logger.error("Config info load failed: {}".format(response.message))
            return MPAPIResponse(state=False, message="Config info load failed: {}".format(response.message))
        self.logger.debug("Asset config for {} load succeeded".format(asset_id))
        return MPAPIResponse(state=True, message=response.message.json())

    def qsearch(self, search_str: str, group_filter=None, asset_filter=None) -> MPAPIResponse:
        """
        Get asset qsearch result
        :param search_str: string
        :param group_filter: Groups for query filter
        :param asset_filter: Assets for query filter
        """
        if group_filter == [None]:
            group_filter = None
        if asset_filter == [None]:
            asset_filter = None
        query = ('qsearch("{}") | select(@Host, Host.IpAddress, Host.OsName, '
                 'Host.@CreationTime, Host.@UpdateTime) | sort(@Host ASC)').format(search_str)
        self.logger.debug("Trying to get PDQL query: {}".format(query))
        try:
            request_object = iface_MP_PDQL(query, filter={"groupIDs": group_filter, "assetIDs": asset_filter})
        except BaseException as err:
            return MPAPIResponse(state=False,
                                 message="PDQL query failed: {}".format(err))
        if not request_object:
            self.logger.error("Error during PDQL request")
            return MPAPIResponse(state=False, message="Error during PDQL request")
        row_count = request_object.get_count().message
        self.logger.debug("PDQL request success - got {} record(s)".format(row_count))
        rich_print("[bright_black]Search request success - got {} records".format(row_count))
        return MPAPIResponse(state=True, message=request_object)

    # Get Asset bind IP address
    def get_asset_ip(self, asset_id: str) -> MPAPIResponse:
        """
        Get asset bind IP
        :param asset_id: string
        :return: IP address
        """
        asset = iface_MP_PDQL("filter(Host.@id = {}) | select(@Host, Host.Fqdn, Host.IpAddress)".format(asset_id))
        if asset:
            record = asset.get_response(limit=1)
            if record.state:
                if len(record.message) > 0:
                    address = record.message[0].get("Host.IpAddress")
                else:
                    self.logger.error("Unable to find asset with ID {} via PDQL query".format(asset_id))
                    EVENTS.push(action="Resolve", status="Fail",
                                instance="Asset",
                                name="N/A", instance_id=asset_id,
                                details="Unable to find asset with ID {} via PDQL query".format(asset_id))
                    return MPAPIResponse(state=False,
                                         message="Unable to find asset with ID {} via PDQL query".format(asset_id))
            else:
                self.logger.error("Failed to run PDQL query: {}".format(record.message))
                EVENTS.push(action="Resolve", status="Fail",
                            instance="Asset",
                            name="N/A", instance_id=asset_id,
                            details="Failed to run PDQL query: {}".format(record.message))
                return MPAPIResponse(state=False,
                                     message="Failed to run PDQL query: {}".format(record.message))
        else:
            self.logger.error("Failed to run PDQL query (can`t put query)")
            EVENTS.push(action="Resolve", status="Fail",
                        instance="Asset",
                        name="N/A", instance_id=asset_id,
                        details="Failed to run PDQL query (can`t put query)")
            return MPAPIResponse(state=False,
                                 message="Failed to run PDQL query (can`t put query)")
        return MPAPIResponse(state=True, message=address)

    # Get asset configuration snapshot
    def get_asset_snapshot(self, asset_id: str) -> MPAPIResponse:
        """
        Get asset configuration snapshot
        :param asset_id: string
        :return: configuration information
        """
        self.logger.debug("Trying to get asset configuration snapshot")
        response = app.API_MP.get(app.API_MP.url_asset_snapshot.format(asset_id))
        if not response.state:
            self.logger.error("Asset snapshot load failed: {}".format(response.message))
            return MPAPIResponse(state=False, message="Asset snapshot load failed: {}".format(response.message))
        if response.message.content == b'':
            self.logger.error("Asset not found or snapshot is empty for: {}".format(asset_id))
            return MPAPIResponse(state=False, message="Asset not found or snapshot is empty for: {}".format(asset_id))
        self.logger.debug("Asset snapshot for {} load succeeded".format(asset_id))
        response = response.message
        return MPAPIResponse(state=True, message=response.content)

    def get_asset_picker(self, prompt_string: str) -> MPAPIResponse:
        """
        Dialog for asset selection
        :param prompt_string: string displayed in prompt
        :return: asset information
        """

        def reduce_find(data):
            output = []
            for item in data:
                output.append({
                    "id": item.get("@Host", {}).get("id"),
                    "name": item.get("@Host", {}).get("name")
                })
            return output

        try:
            try:
                pattern = Prompt.ask(prompt_string)
            except KeyboardInterrupt:
                return MPAPIResponse(state=False, message="Operation interrupted")
            if pattern == "":
                return MPAPIResponse(state=False, message="User cancelled")
        except KeyboardInterrupt:
            return MPAPIResponse(state=False, message="User cancelled")
        pdql_query = 'qsearch("{}") | select(@Host, Host.OsName, host.IpAddress, Host.@Id)'.format(pattern)
        try:
            asset = iface_MP_PDQL(pdql_query)
            if not asset:
                self.logger.error("Failed to run PDQL query (can`t put query)")
                EVENTS.push(action="Find", status="Fail",
                            instance="Asset",
                            name=pattern, instance_id="N/A",
                            details="Failed to run PDQL query (can`t put query)")
                return MPAPIResponse(state=False,
                                     message="Failed to run PDQL query (can`t put query)")
            asset_count = asset.get_count().message
            if asset_count > 10:
                print("Too wide request. Response will be limited to 10")
            records = asset.get_response(limit=10)
            records = reduce_find(records.message)

            if len(records) > 1:
                record = func_select_list_item(records)
            else:
                record = records[0]
        except BaseException as err:
            self.logger.error("Failed to find asset: {}".format(err))
            return MPAPIResponse(state=False, message="Failed to find asset: {}".format(err))
        if len(record) == 0:
            self.logger.debug("No assets found")
            return MPAPIResponse(state=False, message="No assets found")
        else:
            return MPAPIResponse(state=True, message=record)

    @staticmethod
    def reduce_assets(data):
        """
        Standard asset list reducer
        :param data: assets structure
        """

        def reduce_asset(dt):
            output = {"@Host.id": dt.get("@Host", {}).get("id"), "@Host.name": dt.get("@Host", {}).get("name"),
                      "'Host.IpAddress'": dt.get("Host.IpAddress"),
                      "@Host.deviceType": dt.get("@Host", {}).get("deviceType"), "'Host.osName'": dt.get("Host.OsName"),
                      "'Host.@CreationTime'": dt.get("Host.@CreationTime"),
                      "'Host.@UpdateTime'": dt.get("Host.@UpdateTime")}
            return output

        out = None
        if isinstance(data, dict):
            out = reduce_asset(data)
        if isinstance(data, list):
            out = []
            for item in data:
                out.append(reduce_asset(item))
        return out

    @staticmethod
    def reduce_member(data):
        """
        Asset membership reducer
        :param data: membership structure
        """
        output = None
        if isinstance(data, list):
            output = []
            for item in data:
                out_item = {
                    "id": item.get("id"),
                    "groups": []
                }
                for itm in item.get("groups"):
                    out_item["groups"].append({
                        "id": itm.get("id"),
                        "name": itm.get("name"),
                        "path": itm.get("treePath")
                    })
                output.append(out_item)
        if isinstance(data,dict):
            out_item = {
                "id": data.get("id"),
                "groups": []
            }
            for itm in data.get("groups"):
                out_item["groups"].append({
                    "id": itm.get("id"),
                    "name": itm.get("name"),
                    "path": itm.get("treePath")
                })
            output = out_item
        return output

    @staticmethod
    def reduce_passport(data):
        """
        Asset passport reducer
        :param data: passport structure
        :return: reduced structure
        """
        output = {}
        if type(data) == dict:
            output["defaultAssetName"] = deep_get(data, "defaultAssetName")
            output["userAssetName"] = deep_get(data, "userAssetName")
            output["description"] = deep_get(data, "description")
            output["importance.value.value"] = deep_get(data, "importance.value.value")
            output["scanningIntervals.audit"] = {
                "upToDatePeriod.value": deep_get(data, "scanningIntervals.audit.upToDatePeriod.value"),
                "obsoletePeriod.value": deep_get(data, "scanningIntervals.audit.obsoletePeriod.value")
            },
            output["scanningIntervals.pentest"] = {
                "upToDatePeriod.value": deep_get(data, "scanningIntervals.pentest.upToDatePeriod.value"),
                "obsoletePeriod.value": deep_get(data, "scanningIntervals.pentest.obsoletePeriod.value")
            }
        if type(data) == list:
            output = []
            for item in data:
                output.append({
                    "defaultAssetName": deep_get(item, "defaultAssetName"),
                    "userAssetName": deep_get(item, "userAssetName"),
                    "description": deep_get(item, "description"),
                    "importance.value.value": deep_get(item, "importance.value.value"),
                    "scanningIntervals.audit": {
                        "upToDatePeriod.value": deep_get(data, "scanningIntervals.audit.upToDatePeriod.value"),
                        "obsoletePeriod.value": deep_get(data, "scanningIntervals.audit.obsoletePeriod.value")
                    },
                    "scanningIntervals.pentest": {
                        "upToDatePeriod.value": deep_get(data, "scanningIntervals.pentest.upToDatePeriod.value"),
                        "obsoletePeriod.value": deep_get(data, "scanningIntervals.pentest.obsoletePeriod.value")
                    }
                })
        return output
