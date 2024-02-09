import copy
import logging
import uuid

import app
from app.core.func import fnmatch_ext, deep_get
from app.mp.api import MPAPIResponse

ETL_Sources = []
ETL_Destinations = []


# ETL API Interfaces
class MPAPIETL:
    def __init__(self, load=True):
        self.logger = logging.getLogger("mp.etl_api")
        if load:
            response = self.__load_list()
            self.list = response
        else:
            self.list = []
        self.sources_list = []
        for item in ETL_Sources:
            self.sources_list.append(item.option)
        self.destinations_list = []
        for item in ETL_Destinations:
            self.destinations_list.append(item.option)

    # Create ETL pipeline
    def create(self, raw_spec: dict, disarm=True) -> MPAPIResponse:
        self.logger.debug("Trying to create ETL pipeline")
        # Reload ETL pipline list
        self.list = self.__load_list()
        exist = self.get_by_name(raw_spec.get("name"))
        if exist:
            self.logger.error("ETL pipeline {} exist. Can`t create".format(raw_spec.get("name")))
            return MPAPIResponse(state=False,
                                 message="ETL pipeline {} exist. Can`t create".format(raw_spec.get("name")))
        db_etls = app.DB.table("etl")
        raw_spec["id"] = str(uuid.uuid1())
        if not app.app.GLOBAL_DISARM and not disarm:
            db_etls.insert(raw_spec)
        else:
            self.logger.info("Success - disarmed")
            return MPAPIResponse(state=False, message="Success - disarmed")
        self.logger.info("ETL pipeline {} created".format(raw_spec.get("name")))
        # Reload API pipeline list
        self.list = self.__load_list()
        return MPAPIResponse(state=True, message="ETL pipeline {} created".format(raw_spec.get("name")))

    # Update ETL pipeline
    def update(self, raw_spec: dict, disarm=True) -> MPAPIResponse:
        self.logger.debug("Trying to update ETL pipeline from specification")
        exist = self.get_by_id(raw_spec.get("id"))
        if not exist:
            self.logger.debug("ETL pipeline {}({}) not found".format(raw_spec.get("name"),
                                                                    raw_spec.get("id")))
            return MPAPIResponse(state=False,
                                 message="ETL pipeline {}({}) not found".format(raw_spec.get("name"),
                                                                               raw_spec.get("id")))
        db_etls = app.DB.table("etl")
        if not app.app.GLOBAL_DISARM and not disarm:
            result = db_etls.update(raw_spec, app.DBQUERY.id == raw_spec.get("id"))
        else:
            self.logger.info("Success - disarmed")
            return MPAPIResponse(state=False, message="Success - disarmed")
        if not result:
            self.logger.error("Failed to update ETL DB record")
            return MPAPIResponse(state=False,
                                 message="Failed to update ETL DB record")
        self.logger.info("ETL pipeline {}({}) updated".format(raw_spec.get("name"), raw_spec.get("id")))
        return MPAPIResponse(state=True,
                             message="ETL pipeline {}({}) updated".format(raw_spec.get("name"), raw_spec.get("id")))

    # Get source
    @staticmethod
    def get_source(name: str):
        for item in ETL_Sources:
            if name == item.option:
                return item

    # Get destination
    @staticmethod
    def get_destination(name: str):
        for item in ETL_Destinations:
            if name == item.option:
                return item

    # Get profile by name
    def get_by_name(self, name: str) -> dict | None:
        for item in self.list:
            if item.get("name") == name:
                return item

    # Get profile by id
    def get_by_id(self, etl_id: str) -> dict | None:
        for item in self.list:
            if item.get("id") == etl_id:
                return item

    # Delete ETL profile
    def delete(self, name: str, disarm=True) -> MPAPIResponse:
        self.logger.debug("Trying to delete ETL pipeline {}".format(name))
        self.list = self.__load_list()
        db_etls = app.DB.table('etl')
        etl = self.get_by_name(name)
        if not etl:
            self.logger.debug("Pipeline {} not found".format(name))
            return MPAPIResponse(state=False, message="Pipeline {} not found".format(name))
        if not app.app.GLOBAL_DISARM and not disarm:
            db_etls.remove(app.DBQUERY.name == etl.get("name").replace('"', ""))
        else:
            self.logger.info("Success - disarmed")
            return MPAPIResponse(state=False, message="Success - disarmed")
        self.logger.info("ETL pipeline {} successfully deleted".format(name))
        return MPAPIResponse(state=True, message="ETL pipeline {} successfully deleted".format(name))

    # Find profile by name
    def find_by_name(self, name: str) -> list | None:
        out_list = []
        for item in self.list:
            if fnmatch_ext(item.get("name", "none").lower(), name.lower()):
                out_list.append(item)
        return out_list

    # Load API profiles list
    def __load_list(self) -> list:
        self.logger.debug("Trying to load ETL pipelines list")
        db_etl = app.DB.table('etl')
        etls = db_etl.search(app.DBQUERY.name != 'not_name_for_profile')
        # Rebuild to list of dicts
        etls_list = []
        for item in etls:
            etls_list.append(dict(item))
        return etls_list

    # Reducer
    @staticmethod
    def reduce_list(data) -> list:
        output = []
        for item in data:
            output_item = copy.deepcopy(item)
            if deep_get(output_item, "transform.code"):
                del output_item["transform"]
                output_item["transform"] = True
            else:
                del output_item["transform"]
                output_item["transform"] = False
            output_item["source"] = output_item["source"]["type"]
            output_item["destination"] = output_item["destination"]["type"]
            output.append(output_item)
        return output
