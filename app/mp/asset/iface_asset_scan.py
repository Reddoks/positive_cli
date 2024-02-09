import logging
from datetime import datetime, timedelta

import app
from app.app import EVENTS
from app.core.func import console_clear_up
from app.mp.api import MPAPIResponse
from rich.progress import Progress


class iface_MP_Scan:  # noqa
    def __init__(self):
        """
        Interface for Asset Scans
        """
        self.logger = logging.getLogger("mp.asset.iface_scan")

    def get_processed_scans(self, from_date=None, limit=100000, offset=0, return_scans=False, unprocessed=False):
        """
        Get processed scans. It may be statistic or stats + scan structure
        :param from_date: date in ISO format: YY-mm-dd
        :param limit: max results in request
        :param offset: for page output
        :param return_scans: bool, function may return raw scan list in response structure
        :param unprocessed: bool, flag to return unprocessed scans
        """
        response = app.API_MP.get(app.API_MP.url_asset_scan, params={"fromDate": from_date,
                                                                     "offset": offset,
                                                                     "limit": limit})
        if not response.state:
            self.logger.error("Processed scans load failed: {}".format(response.message))
            return MPAPIResponse(state=False, message="Processed scans load failed: {}".format(response.message))
        # Getting statistic
        scans = response.message.json()
        with Progress() as progress:
            task = progress.add_task("Getting asset scans...", total=None)
            response = app.API_MP.get(app.API_MP.url_asset_scan_raw, params={"fromDate": from_date,
                                                                             "offset": offset,
                                                                             "limit": limit})
        console_clear_up(skip_line=True)
        if not response.state:
            self.logger.error("Raw scans load failed: {}".format(response.message))
            return MPAPIResponse(state=False, message="Raw scans load failed: {}".format(response.message))
        raw_scans = response.message.json()
        # Lookup unprocessed scans
        unprocessed_list = []
        for item in raw_scans:
            is_present = False
            for itm in scans:
                if item.get("id") == itm.get("id"):
                    is_present = True
            if not is_present:
                unprocessed_list.append(item)
        scans_stat = {
            "Count": len(scans),
            "Unprocessed": len(unprocessed_list)
        }
        self.logger.debug("Got {} scans".format(len(scans)))
        # Getting statistic
        for item in scans:
            if item["source"] not in scans_stat:
                scans_stat[item["source"]] = 1
            else:
                scans_stat[item["source"]] += 1
        if return_scans:
            scans_stat["scans"] = scans
        if return_scans and unprocessed:
            scans_stat["scans"] = unprocessed_list
        return MPAPIResponse(state=True, message=scans_stat)

    def get_raw_scans(self, from_date=None, limit=100000, offset=0, return_scans=False):
        """
        Get raw scans. It may be statistic or stats + scan structure
        :param from_date: date in ISO format: YY-mm-dd
        :param limit: max results in request
        :param offset: for page output
        :param return_scans: bool, function may return raw scan list in response structure
        """
        with Progress() as progress:
            task = progress.add_task("Getting asset scans...", total=None)
            response = app.API_MP.get(app.API_MP.url_asset_scan_raw, params={"fromDate": from_date,
                                                                             "offset": offset,
                                                                             "limit": limit})
        console_clear_up(skip_line=True)
        if not response.state:
            self.logger.error("Raw scans load failed: {}".format(response.message))
            return MPAPIResponse(state=False, message="Raw scans load failed: {}".format(response.message))
        # Getting statistic
        raw_scans = response.message.json()
        raw_scans_stat = {
            "Count": len(raw_scans)
        }
        self.logger.debug("Got {} scans".format(len(raw_scans)))
        # Getting statistic
        for item in raw_scans:
            if item["source"] not in raw_scans_stat:
                raw_scans_stat[item["source"]] = 1
            else:
                raw_scans_stat[item["source"]] += 1
        if return_scans:
            raw_scans_stat["scans"] = raw_scans
        return MPAPIResponse(state=True, message=raw_scans_stat)

    def get_raw_scan_content(self, scan_id: str) -> MPAPIResponse:
        self.logger.debug("Trying to load content for raw scan {}".format(scan_id))
        response = app.API_MP.get(app.API_MP.url_asset_scan_raw_content.format(scan_id))
        if not response.state:
            self.logger.error("Raw scan content load failed: {}".format(response.message))
            return MPAPIResponse(state=False, message="Raw scan content load failed: {}".format(response.message))
        self.logger.debug("Load content for raw scan succeed")
        return MPAPIResponse(state=True, message=response.message.content)

    def get_scan_content(self, scan_id: str) -> MPAPIResponse:
        self.logger.debug("Trying to load content for scan {}".format(scan_id))
        response = app.API_MP.get(app.API_MP.url_asset_scan_content.format(scan_id))
        if not response.state:
            self.logger.error("Scan content load failed: {}".format(response.message))
            return MPAPIResponse(state=False, message="Scan content load failed: {}".format(response.message))
        self.logger.debug("Load content for scan succeed")
        return MPAPIResponse(state=True, message=response.message.content)

    def load_scan(self, source_scan: dict, overwrite=False, disarm=True) -> MPAPIResponse:
        """
        Load raw scan from specification
        :param source_scan: source spec
        :param overwrite: overwrite scan information
        :param disarm: run in test mode
        """
        self.logger.debug("Trying to load scan {} from specification".format(source_scan.get("id")))
        exist = self.get_raw_scan_by_id(source_scan.get("id"))
        if exist.state and not overwrite:
            EVENTS.push(status="Fail", action="Load", instance="Scan",
                        name="N/A", instance_id=source_scan.get("id"),
                        details="Raw scan {} exist. Can`t create".format(source_scan.get("id")))
            return MPAPIResponse(state=False,
                                 message="Raw scan {} exist. Can`t create".format(source_scan.get("id")))
        self.logger.debug("Raw scan {} not exist".format(source_scan.get("id")))
        if not app.app.GLOBAL_DISARM and not disarm:
            response = app.API_MP.put(app.API_MP.url_asset_scan_create.format(
                source_scan.get("id"),
                source_scan.get("source"),
                source_scan.get("scopeId"),
                source_scan.get("timeStamp"),
                source_scan.get("jobId", "null"),
                source_scan.get("orderedId", "null"),
                source_scan.get("noTtl"),
                source_scan.get("replaceEntities"),
                source_scan.get("createOnly")
                ), data=source_scan.get("content"), xml=True)
            if not response.state:
                self.logger.error("Failed to load scan {} to system: {}".format(source_scan, response.message))
                EVENTS.push(status="Fail", action="Load", instance="Scan",
                            name="N/A", instance_id=source_scan.get("id"),
                            details=response.message)
                return response
        else:
            self.logger.debug("Success - disarmed")
            return MPAPIResponse(state=True, message="Success - disarmed")
        return MPAPIResponse(state=True, message="Scan {} successfully loaded")

    @staticmethod
    def get_raw_scan_by_id(scan_id: str) -> MPAPIResponse:
        """
        Get raw scan by ID
        :param scan_id: string
        """
        response = app.API_MP.get(app.API_MP.url_asset_scan_raw_instance.format(scan_id))
        return response

    @staticmethod
    def get_scan_by_id(scan_id: str) -> MPAPIResponse:
        """
        Get scan by ID
        :param scan_id: string
        """
        response = app.API_MP.get(app.API_MP.url_asset_scan_instance.format(scan_id))
        return response

    @staticmethod
    def get_isodata_subtract_days(days: int) -> str:
        """
        Get ISO data with subtraction
        :param days: int
        """
        time = datetime.today() - timedelta(days=days)
        time = time.strftime('%Y-%m-%d')
        return time

    @staticmethod
    def reduce_scan_list(data: list) -> list:
        """
        Scan list reducer
        """
        output = []
        if type(data) == list:
            for item in data:
                output.append({
                    "id": item.get("id"),
                    "source": item.get("source"),
                    "type": item.get("type"),
                    "timeStamp": item.get("timeStamp"),
                    "noTtl": item.get("noTtl", False),
                    "replaceEntities": item.get("replaceEntities", False),
                    "createOnly": item.get("createOnly", False),
                })
        return output
