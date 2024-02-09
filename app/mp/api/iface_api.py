import copy
import logging
import app
from app.core.func import fnmatch_ext
from app.mp.iface_api import MPAPIResponse
from rich.prompt import Prompt


class iface_MP_APIProfiles: # noqa
    def __init__(self, load=True):
        """
        Interface for API connection profiles
        :param load: if false - do not load profiles list
        """
        self.logger = logging.getLogger("mp.iface_api")
        if load:
            response = self.__load_list()
            self.list = response
        else:
            self.list = []

    def create(self, raw_spec: dict, disarm=True) -> MPAPIResponse:
        """
        Create connection profile
        :param raw_spec: profile specification
        :param disarm: disarm state
        """
        self.logger.debug("Trying to create API profile from specification")
        # Reload API profile list
        self.list = self.__load_list()
        exist = self.get_by_name(raw_spec.get("name"))
        if exist:
            self.logger.error("API profile {} exist. Can`t create".format(raw_spec.get("name")))
            return MPAPIResponse(state=False,
                                 message="API profile {} exist. Can`t create".format(raw_spec.get("name")))
        db_profiles = app.DB.table("profiles")
        # Look for default profile
        default_profile = db_profiles.search(app.DBQUERY.default == True) # noqa
        if not app.app.GLOBAL_DISARM and not disarm:
            # Reset default profile in DB if default in spec
            if len(default_profile) > 0 and raw_spec.get("default") == True: # noqa
                db_profiles.update({"default": False}, app.DBQUERY.name == default_profile[0].get("name"))
            # Insert new profile
            if len(default_profile) == 0:
                raw_spec["default"] = True
            db_profiles.insert(raw_spec)
        else:
            return MPAPIResponse(state=True, message="Success - disarmed")
        self.logger.info("API profile {} created".format(raw_spec.get("name")))
        # Reload API profile list
        self.list = self.__load_list()
        return MPAPIResponse(state=True, message="API profile {} created".format(raw_spec.get("name")))

    def delete(self, name: str, disarm=True) -> MPAPIResponse:
        """
        Delete connection profile
        :param name: name string
        :param disarm: disarm state
        """
        self.logger.debug("Trying to delete API profile {}".format(name))
        self.list = self.__load_list()
        db_profiles = app.DB.table('profiles')
        profile = self.get_by_name(name)
        if not profile:
            self.logger.error("Profile {} not found".format(name))
            return MPAPIResponse(state=False, message="Profile {} not found".format(name))
        profile_count = db_profiles.count(app.DBQUERY.name != 'not_name_for_profile')
        if not app.app.GLOBAL_DISARM and not disarm:
            db_profiles.remove(app.DBQUERY.name == profile.get("name").replace('"', ""))
        else:
            return MPAPIResponse(state=False, message="Success - disarmed")
        if profile.get("default") is True:
            if profile_count > 1:
                self.list = self.__load_list()
                db_profiles.update({"default": True}, app.DBQUERY.name == self.list[0].get("name"))
        self.logger.debug("API profile {} successfully deleted".format(name))
        return MPAPIResponse(state=True, message="API profile {} successfully deleted".format(name))

    def set_default(self, name: str) -> MPAPIResponse:
        """
        Set default connection profile
        :param name: name string
        """
        # Reload API profile list
        self.list = self.__load_list()
        exist = self.get_by_name(name)
        if not exist:
            self.logger.error("API profile {} does not exist".format(name))
            return MPAPIResponse(state=False, message="API profile {} does not exist".format(name))
        db_profiles = app.DB.table("profiles")
        # Look for default profile
        default_profile = db_profiles.search(app.DBQUERY.default == True) # noqa
        # Reset default profile in DB if default in spec
        if len(default_profile) > 0:
            db_profiles.update({"default": False}, app.DBQUERY.name == default_profile[0].get("name"))
        db_profiles.update({"default": True}, app.DBQUERY.name == name)
        self.logger.info("API Profile {} now is default profile".format(name))
        return MPAPIResponse(state=True, message="API Profile {} now is default profile".format(name))

    def get_by_name(self, name: str) -> dict | None:
        """
        Get connection profile
        :param name: name string
        :return: profile list item
        """
        for item in self.list:
            if item.get("name") == name:
                return item

    # Find profile by name
    def find_by_name(self, name: str) -> list | None:
        """
        Find connection profile
        :param name: name string
        :return: connection profile list
        """
        out_list = []
        for item in self.list:
            if fnmatch_ext(item.get("name", "").lower(), name.lower()):
                out_list.append(item)
        return out_list

    @staticmethod
    def get_spec_from_params(name=None, host=None, secret=None,
                             api_port=None, front_port=None, default=None) -> dict | None:
        """
        Build profile from params
        :param name: name string
        :param host: host string
        :param secret: secret string
        :param api_port: api port string
        :param front_port: front port string
        :param default: bool default
        :return: connection profile specification
        """
        spec = {}
        if not name:
            try:
                name_inpt = Prompt.ask("API Profile name ", default="New API Profile")
            except KeyboardInterrupt:
                print("Operation interrupted")
                return None
            if len(name_inpt) == 0:
                return
            spec["name"] = name_inpt.replace('"', '')
        else:
            spec["name"] = name.replace('"', '')
        if not host:
            try:
                host_inpt = Prompt.ask("API Profile host (FQDN or IP) ", default="127.0.0.1")
            except KeyboardInterrupt:
                print("Operation interrupted")
                return None
            if len(host_inpt) == 0:
                return
            spec["host"] = host_inpt.replace('"', '')
        else:
            spec["host"] = host.replace('"', '')
        if not secret:
            try:
                secret_inpt = Prompt.ask("MaxPatrol API secret (leave empty for session connect) ")
            except KeyboardInterrupt:
                print("Operation interrupted")
                return None
            if len(secret_inpt) == 0:
                spec["secret"] = "N/A"
            else:
                spec["secret"] = secret_inpt.replace('"', '')
        else:
            spec["secret"] = secret.replace('"', '')
        if not api_port:
            try:
                api_inpt = Prompt.ask("MaxPatrol API port ", default="3334")
            except KeyboardInterrupt:
                print("Operation interrupted")
                return None
            if len(api_inpt) == 0:
                spec["api_port"] = "3334"
            else:
                spec["api_port"] = api_inpt.replace('"', '')
        else:
            spec["api_port"] = api_port.replace('"', '')
        if not front_port:
            try:
                front_inpt = Prompt.ask("MaxPatrol Front port ", default="443")
            except KeyboardInterrupt:
                print("Operation interrupted")
                return None
            if len(front_inpt) == 0:
                spec["front_port"] = "443"
            else:
                spec["front_port"] = front_inpt.replace('"', '')
        else:
            spec["front_port"] = front_port.replace('"', '')
        if not default:
            try:
                default_inpt = Prompt.ask("Set profile as default  ", default="False")
            except KeyboardInterrupt:
                print("Operation interrupted")
                return None
            if len(default_inpt) == 0:
                spec["default"] = False
            else:
                spec["default"] = bool(default_inpt.replace('"', ''))
        else:
            spec["default"] = bool(default)
        return spec

    def __load_list(self) -> list:
        """
        API profile list loader
        """
        if app.ARG_RUN:
            return []
        self.logger.debug("Trying to load API profiles list")
        db_profiles = app.DB.table('profiles')
        profiles = db_profiles.search(app.DBQUERY.name != 'not_name_for_profile')
        # Rebuild to list of dicts
        profiles_list = []
        for item in profiles:
            profiles_list.append(dict(item))
        return profiles_list

    @staticmethod
    def reduce_list(data) -> list:
        """
        Profile list reducer
        """
        output = []
        for item in data:
            output_item = copy.deepcopy(item)
            if not output_item["default"]:
                output_item["default"] = " "
            else:
                output_item["default"] = "True"
            if len(output_item["secret"]) > 3:
                output_item["secret"] = "********-****-****-****" + output_item["secret"][-13:]
            output.append(output_item)
        return output
