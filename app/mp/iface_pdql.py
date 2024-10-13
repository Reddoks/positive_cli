import logging
import time

from rich import print as rich_print

import app
from app.mp.iface_api import MPAPIResponse


class iface_MP_PDQL:  # noqa
    def __init__(self, pdql_query, groupIDs=[], filter={"groupIDs": [], "assetIDs": []}, nested=True):  # noqa
        """
        Interface for PDQL
        :param pdql_query: PDQL query string
        :param groupIDs:list
        :param filter: asset filters
        :param nested: use nested
        """
        self.logger = logging.getLogger("[mp.iface_pdql]")
        self.pdql_query = pdql_query
        # Getting UTC Offset
        offset = int(time.localtime().tm_gmtoff / 60 / 60)
        offset_string = None
        if offset < 10:
            offset_string = "+0" + str(offset) + ":00"
        if 0 > offset > -10:
            offset_string = "-0" + str(abs(offset)) + ":00"
        if offset < -9:
            offset_string = "-" + str(abs(offset)) + ":00"
        if offset > 9:
            offset_string = "+" + str(abs(offset)) + ":00"
        self.pdql_request = {"pdql": self.pdql_query,
                             "selectedGroupIds": groupIDs,
                             "additionalFilterParameters": filter,
                             "includeNestedGroups": nested,
                             "utcOffset": offset_string}
        request = self.__request()
        if not request.state:
            raise Exception(request.message)
        self.token = request.message

    def __request(self) -> MPAPIResponse:
        """
        Execute PDQL request
        """
        self.logger.debug("Trying to create PDQL query request")
        self.logger.debug("Execute PDQL query: {}".format(self.pdql_query))
        response = app.API_MP.post(app.API_MP.url_pdql, data=self.pdql_request)
        if not response.state:
            rich_print("[red]Create PDQL request failed: {}".format(response.message))
            self.logger.error("Create PDQL request failed: {}".format(response.message))
            return response
        self.logger.debug("PDQL request succeeded")
        resp_json = response.message.json()
        if resp_json["isPotentiallySlow"]:
            rich_print("[yellow]PDQL: Potentially slow request")
        # Check token contains plus symbol
        token = resp_json.get("token")
        return MPAPIResponse(state=True, message=token)

    def get_count(self) -> MPAPIResponse:
        """
        Get PDQL response count
        """
        self.logger.debug("Trying to get PDQL response row count")
        response = app.API_MP.get(app.API_MP.url_pdql_count, do_retry=True, params={"pdqlToken": self.token})
        if not response.state:
            self.logger.error("'Count PDQL rows request failed: {}".format(response.message))
            return response
        resp_json = response.message.json()
        return MPAPIResponse(state=True, message=int(resp_json.get('rowCount')))

    def get_offset_list(self, offset: int, limit: int) -> MPAPIResponse:
        """
        Get part of PDQL response starting from offset
        :param offset: starting offset
        :param limit: limit number of rows
        """
        self.logger.debug("Trying to get PDQL offset list. Offset: {} Limit: {}".format(offset, limit))
        response = app.API_MP.get(app.API_MP.url_pdql_data,
                                  do_retry=True, params={"pdqlToken": self.token, "offset": offset, "limit": limit})
        if not response.state:
            self.logger.error("'PDQL offset list request failed: {}".format(response.message))
            return response
        resp_json = response.message.json()
        return MPAPIResponse(state=True, message=resp_json.get("records"))

    def get_offset_group_list(self, group_id: str, offset: int, limit: int) -> MPAPIResponse:
        """
        Get part of PDQL group selection from offset
        :param group_id: PDQL group ID
        :param offset: starting offset
        :param limit: limit number of rows
        """
        self.logger.debug("Trying to get PDQL group list. Group {} offset: {} Limit: {}".format(group_id,
                                                                                                offset, limit))
        # Clear group selection
        response = app.API_MP.put(app.API_MP.url_pdql_selection,
                                  data={"pdqlToken": self.token, "changeType": "ClearGroupSelectionCommand"})
        if not response.state:
            self.logger.error("'PDQL clear selection failed: {}".format(response.message))
            return response
        # Set group selection
        response = app.API_MP.put(app.API_MP.url_pdql_selection_groups,
                                  params={"pdqlToken": self.token}, data=[group_id])
        if not response.state:
            self.logger.error("'PDQL set selection failed: {}".format(response.message))
            return response
        # Get selection data
        response = app.API_MP.get(app.API_MP.url_pdql_selection_groups_data,
                                  do_retry=True, params={"pdqlToken": self.token, "offset": offset, "limit": limit})
        if not response.state:
            self.logger.error("'PDQL get selection data failed: {}".format(response.message))
            return response
        resp_json = response.message.json()
        return MPAPIResponse(state=True, message=resp_json.get("records"))

    def count(self) -> int | None:
        """
        Get PDQL response count
        """
        self.logger.debug("Trying to get PDQL response row count")
        response = app.API_MP.get(app.API_MP.url_pdql_count, do_retry=True, params={"pdqlToken": self.token})
        if not response.state:
            return
        resp_json = response.message.json()
        return int(resp_json.get('rowCount'))

    def block(self, offset: int, limit: int) -> list | None:
        """
        Get part of PDQL response starting from offset
        :param offset: starting offset
        :param limit: limit number of rows
        """
        self.logger.debug("Trying to get PDQL offset list. Offset: {} Limit: {}".format(offset, limit))
        response = app.API_MP.get(app.API_MP.url_pdql_data,
                                  do_retry=True, params={"pdqlToken": self.token, "offset": offset, "limit": limit})
        if not response.state:
            return
        resp_json = response.message.json()
        return resp_json.get("records")

    def get_response(self, limit: int) -> MPAPIResponse:
        """
        Get PDQL response limited by limit
        :param limit: rows limit
        """
        self.logger.debug("Trying to get PDQL response")
        response = app.API_MP.get(app.API_MP.url_pdql_data, do_retry=True,
                                  params={"pdqlToken": self.token, "limit": limit})
        if not response.state:
            self.logger.error("'PDQL request failed: {}".format(response.message))
            return response
        resp_json = response.message.json()
        return MPAPIResponse(state=True, message=resp_json.get("records"))

    @staticmethod
    def reduce_asset_list(data: dict | list) -> dict | list:
        """
        Asset list reducer
        """
        output = {}
        if type(data) == dict:
            output["name"] = data["@Host"]["name"]
            output["id"] = data["@Host"]["id"]
            output["host_ip"] = data["Host.IpAddress"]
            output["os"] = data["Host.OsName"]
            output["created"] = data["Host.@CreationTime"]
            output["updated"] = data["Host.@UpdateTime"]
        if type(data) == list:
            output = []
            for item in data:
                output.append({
                    "name": item["@Host"]["name"],
                    "id": item["@Host"]["id"],
                    "host_ip": item["Host.IpAddress"],
                    "os": item["Host.OsName"],
                    "created": item["Host.@CreationTime"],
                    "updated": item["Host.@UpdateTime"]
                })
        return output
