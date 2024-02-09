import html
import json
import logging
import re
import requests
import time

import app.app
from rich import print as rich_print


# API Response
class MPAPIResponse(object):
    def __init__(self, state=True, message=None):
        self.state = state
        self.message = message


class iface_MP_API(object):  # noqa
    def __init__(self, host: str, client_secret: str, login: str, password: str, api_port: str, front_port: str):
        """
        Interface for MaxPatrol API
        :param host: connection host IP or FQDN string
        :param client_secret: MP client secret
        :param login: MP login
        :param password: Mp password
        :param api_port: API port
        :param front_port: Front port
        """
        requests.packages.urllib3.disable_warnings()  # noqa
        self.logger = logging.getLogger("mp.iface_api")
        self.host = host
        self.login = login
        self.client_secret = client_secret
        self.password = password
        self.api_port = api_port
        self.front_port = front_port
        self.access_token = None
        self.auth_header = None
        self.json_auth_header = None
        self.xml_auth_header = None
        self.json_header = {}
        self.session = None
        self.mc_session = None
        self.product = None
        # API Settings
        # Default response wait time in sec
        self.req_wait_time = 5
        # Max request retries
        self.req_max_retries = 5
        # URLs
        # Base
        self.url_auth = "https://" + self.host + ":" + str(self.api_port)
        self.url_asset_grid = "https://" + self.host + ":8723"
        self.url_auth_session = self.url_auth + "/ui/login"
        self.url_auth_token = self.url_auth + "/connect/token"
        self.url_base = "https://" + self.host + ":" + str(self.front_port)
        self.url_base_auth = self.url_base + "/account/login?returnUrl=/#/authorization/landing"
        # Users
        self.url_user = self.url_base + "/ptms/api/sso/v1/users"
        self.url_user_instance = self.url_auth + "/ptms/api/sso/v1/users/{}"
        # User roles
        self.url_user_roles_ptkb = self.url_base + "/ptms/api/sso/v2/applications/ptkb/roles"
        self.url_user_roles_idmgr = self.url_base + "/ptms/api/sso/v2/applications/idmgr/roles"
        self.url_user_roles_mpx = self.url_base + "/ptms/api/sso/v2/applications/mpx/roles"
        self.url_user_roles_mpx_delete = self.url_base + "/ptms/api/sso/v2/applications/mpx/roles/delete"
        self.url_user_roles_idmgr_delete = self.url_base + "/ptms/api/sso/v2/applications/idmgr/roles/delete"
        self.url_user_roles_ptkb_delete = self.url_base + "/ptms/api/sso/v2/applications/ptkb/roles/delete"
        # User privilege
        self.url_user_privileges_ptkb = self.url_base + "/ptms/api/sso/v2/applications/ptkb/privileges"
        self.url_user_privileges_idmgr = self.url_base + "/ptms/api/sso/v2/applications/idmgr/privileges"
        self.url_user_privileges_mpx = self.url_base + "/ptms/api/sso/v2/applications/mpx/privileges"
        # User actions
        self.url_user_action_categories = self.url_base + "/ptms/api/ual/v2/action_categories"
        self.url_user_action = self.url_auth + "/ptms/api/ual/v2/user_actions?limit={}"
        # Sites
        self.url_site = self.url_auth + "/api/tenants/v2/hierarchy"
        # PDQL
        self.url_pdql = self.url_base + "/api/assets_temporal_readmodel/v1/assets_grid"
        self.url_pdql_count = self.url_base + "/api/assets_temporal_readmodel/v1/assets_grid/row_count"
        self.url_pdql_data = self.url_base + "/api/assets_temporal_readmodel/v1/assets_grid/data"
        self.url_pdql_selection = self.url_base + "/api/assets_temporal_readmodel/v1/assets_grid/selection"
        self.url_pdql_selection_groups = (self.url_base +
                                          "/api/assets_temporal_readmodel/v1/assets_grid/selection/groups")
        self.url_pdql_selection_groups_data = (self.url_base +
                                               "/api/assets_temporal_readmodel/v1/assets_grid/group/data")
        # Core
        self.url_product = self.url_base + "/api/deployment_configuration/v1/system_info"
        self.url_license = self.url_base + "/api/licensing/v3/licenses"
        # AECs
        self.url_aecs = self.url_base + "/api/v1/scanner_agents"
        # Task operations
        self.url_task = self.url_base + "/api/scanning/v3/scanner_tasks"
        self.url_task_instance = self.url_base + "/api/scanning/v3/scanner_tasks/{}"
        self.url_task_instance_start = self.url_base + "/api/scanning/v3/scanner_tasks/{}/start"
        self.url_task_instance_stop = self.url_base + "/api/scanning/v3/scanner_tasks/{}/stop"
        self.url_task_instance_suspend = self.url_base + "/api/scanning/v3/scanner_tasks/{}/suspend"
        self.url_task_history = self.url_base + "/api/scanning/v2/scanner_tasks/{}/runs"
        # Profile operations
        self.url_profile = self.url_base + "/api/scanning/v3/scanner_profiles"
        self.url_profile_instance = self.url_base + "/api/scanning/v3/scanner_profiles/{}"
        # Credential operations
        self.url_credential = self.url_base + "/api/v3/credentials"
        self.url_credential_instance = self.url_base + "/api/v3/credentials/{}"
        self.url_credential_laps = self.url_base + "/api/v3/credentials/laps_provider/{}"
        self.url_credential_certificate = self.url_base + "/api/v3/credentials/certificates/{}"
        self.url_credential_password = self.url_base + "/api/v3/credentials/passwords_only/{}"
        self.url_credential_login = self.url_base + "/api/v3/credentials/login_passwords/{}"
        # Dictionary operations
        self.url_dictionary = self.url_base + "/api/dictionaries"
        self.url_dictionary_instance = self.url_base + "/api/dictionaries/{}"
        # Policy operations
        self.url_policy = self.url_base + "/api/policies/v1/policies"
        self.url_policy_instance = self.url_base + "/api/policies/v1/policies/{}"
        self.url_policy_rules = self.url_base + "/api/policies/v1/policies/{}/rules"
        self.url_policy_rule_instance = self.url_base + "/api/policies/v1/policies/{}/rules/{}"
        self.url_policy_condition_evaluate = self.url_base + "/api/policies/v1/policies/{}/rules/condition/evaluate"
        # Template operations
        self.url_template = self.url_base + "/api/widgets/v1/templates"
        self.url_template_instance = self.url_base + "/api/widgets/v1/templates/{}"
        # Dashboard operations
        self.url_dashboard = self.url_base + "/api/widgets/v3/dashboards"
        self.url_dashboard_instance = self.url_base + "/api/widgets/v3/dashboards/{}"
        self.url_dashboard_instance_widgets = self.url_base + "/api/widgets/v3/dashboards/{}/widgets"
        # https://192.168.1.230/api/widgets/v3/shared/dashboards/57/update_from_dashboard?dashboardId=58
        self.url_dashboard_template_create = self.url_base + "/api/widgets/v3/dashboards/create_from_dashboard"
        self.url_dashboard_template_update = (
                self.url_base + "/api/widgets/v3/shared/dashboards/{}/update_from_dashboard?dashboardId={}")
        # Report operations
        self.url_report = self.url_base + "/api/analytics_reportsdelivery/v2/reports"
        self.url_report_instance = self.url_base + "/api/analytics_reportsdelivery/v2/reports/{}"
        self.url_report_block = self.url_base + "/api/analytics_reportsdelivery/v2/reports/{}/blocks"
        self.url_report_block_instance = self.url_base + "/api/analytics_reportsdelivery/v2/reports/{}/blocks/{}"
        self.url_report_template = self.url_base + "/api/analytics_reportsdelivery/v2/templates"
        self.url_report_template_instance = self.url_base + "/api/analytics_reportsdelivery/v2/templates/{}"
        self.url_report_template_create = self.url_base + ("/api/analytics_reportsdelivery"
                                                           "/v2/templates/create_from_report?reportId={}")
        # Asset operations
        self.url_asset = self.url_base + "/api/asset"
        self.url_asset_scope = self.url_base + "/api/scopes/v2/scopes"
        self.url_asset_group_instance = self.url_base + "/api/assets_temporal_readmodel/v2/groups/{}"
        self.url_asset_group_remove = self.url_base + "/api/assets_processing/v2/groups/removeOperation"
        self.url_asset_group_operations = self.url_base + "/api/assets_processing/v2/groups/operations/{}"
        self.url_asset_group_processing = self.url_base + "/api/assets_processing/v2/groups"
        self.url_asset_group_hierarchy = self.url_base + "/api/assets_temporal_readmodel/v2/groups/hierarchy"
        self.url_asset_query = self.url_base + "/api/assets_temporal_readmodel/v1/stored_queries"
        self.url_asset_query_instance = self.url_base + "/api/assets_temporal_readmodel/v1/stored_queries/queries/{}"
        self.url_asset_query_folders_queries = (
                self.url_base + "/api/assets_temporal_readmodel/v1/stored_queries/folders/queries")
        self.url_asset_state = self.url_base + "/api/v1/asset/state/?assetId={}"
        self.url_asset_passport = self.url_base + "/api/assets_temporal_readmodel/v1/assets_info"
        self.url_asset_config = self.url_base + "/api/assets_processing/v2/assets_input/assets"
        self.url_asset_operations_remove = self.url_base + "/api/assets_processing/v1/asset_operations/removeAssets"
        self.url_asset_operations_remove_state = (
                self.url_base + "/api/assets_processing/v1/asset_operations/removeAssets?operationId={}")

        # Asset scan operations
        self.url_asset_scan = self.url_base + "/api/v1/scans"
        self.url_asset_scan_instance = self.url_base + "/api/v1/scans/{}"
        self.url_asset_scan_create = (
                self.url_base + "/api/v1/scans/{}?source={}&scopeId={}&time={}&jobId={}&orderedId={}&noTtl={}"
                                "&replaceEntities={}&createOnly={}")
        self.url_asset_scan_content = self.url_base + "/api/v1/scans/{}/content"
        self.url_asset_scan_raw_load = (
                self.url_base + "/api/v1/scans/raw/?id={}&source={}&scopeId={}&time={}&jobId={}&noTtl={}"
                                "&replaceEntities={}&createOnly={}")
        self.url_asset_scan_raw = self.url_base + "/api/v1/scans/raw"
        self.url_asset_scan_raw_instance = self.url_base + "/api/v1/scans/raw/{}"
        self.url_asset_scan_raw_content = self.url_base + "/api/v1/scans/raw/{}/content"
        self.url_asset_snapshot = self.url_asset_grid + "/api/assets/{}/raw"

    def connect(self) -> MPAPIResponse:
        """
        Connection to MaxPatrol API method
        """
        data_siem = {"grant_type": "password", "client_id": "mpx", "client_secret": self.client_secret,
                     "scope": "authorization offline_access mpx.api ptkb.api idmgr.api",
                     "response_type": "code id_token token",
                     "username": self.login, "password": self.password}
        data_vm = {"grant_type": "password", "client_id": "mpx", "client_secret": self.client_secret,
                   "scope": "authorization offline_access mpx.api idmgr.api",
                   "response_type": "code id_token token",
                   "username": self.login, "password": self.password}
        self.logger.info("MP API trying to get access token (SIEM)")
        response = self.post(self.url_auth_token, data_siem)
        self.logger.debug("MP API token request response: {}".format(response))
        # If SIEM connect failed, try VM only
        if not response.state:
            if "invalid_scope" in response.message:
                response = self.post(self.url_auth_token, data_vm)
        if not response.state:
            return MPAPIResponse(state=False, message=response.message)
        self.access_token = response.message.json().get("access_token")
        self.auth_header = {'Authorization': 'Bearer ' + self.access_token}
        self.json_auth_header = {
            'Authorization': 'Bearer ' + self.access_token,
            'Content-Type': 'application/json'
        }
        self.xml_auth_header = {
            'Authorization': 'Bearer ' + self.access_token,
            'Content-Type': 'application/xml'
        }
        self.logger.info("MP API got access token")
        # Get product version
        response = self.get(self.url_product)
        if response.state:
            if not isinstance(response.message, str):
                self.product = response.message.json().get("productVersion")
                self.__check_tested(response.message.json().get("productVersion"))
        return MPAPIResponse()

    def session_connect(self) -> MPAPIResponse:
        """
        Connect to MaxPatrol using session
        """
        session = requests.session()
        session.verify = False
        # Getting session from UI
        try:
            response = session.post(self.url_auth_session, json=dict(
                authType=0,
                username=self.login,
                password=self.password
            ))
        except BaseException as err:
            return MPAPIResponse(state=False, message="Session connection failed: {}".format(err))
        if not response:
            return MPAPIResponse(state=False, message="Session connection failed")
        if response.status_code == 401:
            return MPAPIResponse(state=False, message="Access denied")
        # If password change required
        if response.json().get("requiredPasswordChange"):
            return MPAPIResponse(state=False, message="User password change required")
        # Trying to do external auth
        response = session.get(self.url_base_auth)
        if 'access_denied' in response.url:
            return MPAPIResponse(state=False, message="Access denied")
        while '<form' in response.text:
            form_action, form_data = self.parse_form(response.text)
            response = session.post(form_action, data=form_data)
        self.session = session  # Get product version
        response = self.get(self.url_product)
        if not response.state:
            return MPAPIResponse(state=False,
                                 message="[red]Session connect failed. "
                                         "Probably you enter wrong host (e.g. IP instead FQDN)?")
        if response:
            self.product = response.message.json().get("productVersion")
            self.__check_tested(response.message.json().get("productVersion"))
        return MPAPIResponse()

    @staticmethod
    def parse_form(data: str) -> (str, dict):
        return re.search('action=[\'"]([^\'"]*)[\'"]', data).groups()[0], {
            item.groups()[0]: html.unescape(item.groups()[1])
            for item in re.finditer(
                'name=[\'"]([^\'"]*)[\'"] value=[\'"]([^\'"]*)[\'"]',
                data
            )
        }

    def get(self, url: str, req_wait_time=1, retry=0, do_retry=False, params=None) -> MPAPIResponse:
        """
        Get method
        :param url: string
        :param req_wait_time: waiting time for retry request
        :param retry: max retries
        :param do_retry: run with retries
        :param params: params
        """
        if not self.auth_header and not self.session:
            self.logger.error("MP API GET request failed - no auth token")
            return MPAPIResponse(state=False, message="MP API GET request failed - no auth token")
        if retry > self.req_max_retries:
            self.logger.error("MP API GET request to {} failed after {} retries".format(url, retry - 1))
            return MPAPIResponse(state=False,
                                 message="MP API GET request to {} failed after {} retries".format(url, retry - 1))
        try:
            time.sleep(req_wait_time)
            if self.session:
                response = self.session.get(url, params=params)
            else:
                response = requests.get(url, headers=self.auth_header, verify=False, params=params)
            match response.status_code:
                case 201:
                    return MPAPIResponse(state=False, message=response.json())
                case 200:
                    self.logger.debug("MP API GET request to {} completed after {} retries".format(url, retry - 1))
                    return MPAPIResponse(state=True, message=response)
                case _:
                    if do_retry:
                        self.logger.debug("MP API GET request to {}"
                                          " failed: {}. Retry".format(url, response.status_code))
                        self.logger.debug(response.json())
                        # Retry request and increase wait time by 5 sec
                        result = self.get(url, req_wait_time + 5, retry + 1)
                        return result
            return MPAPIResponse(state=False,
                                 message="MP API GET request to {} failed: {}".format(url, response.json()))
        except KeyboardInterrupt:
            return MPAPIResponse(state=False, message="Operation interrupted")
        except BaseException as err:
            self.logger.error("MP API GET request to {} failed: {}".format(url, err))
            return MPAPIResponse(state=False, message="MP API GET request to {} failed: {}".format(url, err))

    def post(self, url: str, data: dict, params=None) -> MPAPIResponse:
        """
        Post method
        :param url: string
        :param params: query data
        :param data: body data
        """
        try:
            self.logger.debug("Entering request POST function")
            if not self.auth_header and not self.session:
                response = requests.post(url, data=data, params=params,
                                         headers={'Content-Type': 'application/x-www-form-urlencoded'}, verify=False)
                self.logger.debug("POST response: {}".format(response.__dict__))
            elif not self.session:
                response = requests.post(url, data=json.dumps(data), params=params,
                                         headers=self.json_auth_header, verify=False)
                self.logger.debug("POST response: {}".format(response.__dict__))
            else:
                response = self.session.post(url=url, headers={'Content-Type': 'application/json'},
                                             params=params, data=json.dumps(data))
            match response.status_code:
                case 400:
                    self.logger.debug("MP API POST request to {} failed: {}".format(url, response.json()))
                    self.logger.debug("Syntax error")
                    return MPAPIResponse(state=False,
                                         message="MP API POST request to {} failed. "
                                                 "Syntax error: {}".format(url, response.json()))
                case 204:
                    self.logger.debug("MP API POST request to {} completed: {}".format(url, response.status_code))
                    return MPAPIResponse(state=True, message=response)
                case 201:
                    return MPAPIResponse(state=True, message=response)
                case 200:
                    return MPAPIResponse(state=True, message=response)
                case _:
                    self.logger.debug("MP API POST request to {} failed: {}".format(url, response.status_code))
                    self.logger.debug(response.json())
                    return MPAPIResponse(state=False,
                                         message="MP API POST request to {} "
                                                 "failed: {}".format(url, response.json()))
        except KeyboardInterrupt:
            return MPAPIResponse(state=False, message="Operation interrupted")
        except BaseException as err:
            self.logger.error("MP API POST request to {} failed: {}".format(url, err))
            return MPAPIResponse(state=False, message="MP API POST request to {} failed: {}".format(url, err))

    def put(self, url: str, data: dict, params=None, xml=False) -> MPAPIResponse:
        """
        Put method
        :param url: string
        :param data: body data
        :param params: query data
        :param xml: send xml data
        """
        if app.app.GLOBAL_DISARM:
            return MPAPIResponse(state=False, message="Global disarmed")
        try:
            self.logger.debug("Entering request PUT function")
            if not self.auth_header and not self.session:
                response = requests.put(url, data=data, params=params,
                                        headers={'Content-Type': 'application/x-www-form-urlencoded'}, verify=False)
            elif not self.session:
                if xml:
                    response = requests.put(url, data=data, params=params,
                                            headers=self.xml_auth_header, verify=False)
                else:
                    response = requests.put(url, data=json.dumps(data), params=params,
                                            headers=self.json_auth_header, verify=False)
            else:
                if xml:
                    response = self.session.put(url, headers={'Content-Type': 'application/xml'}, params=params,
                                                data=data)
                else:
                    response = self.session.put(url, headers={'Content-Type': 'application/json'}, params=params,
                                                data=json.dumps(data))
            match response.status_code:
                case 400:
                    self.logger.debug("MP API PUT request to {} failed: {}".format(url, response.json()))
                    self.logger.debug("Syntax error")
                    return MPAPIResponse(state=False,
                                         message="MP API PUT request to {} "
                                                 "failed: {}".format(url, response.json()))
                case 200:
                    return MPAPIResponse(state=True, message=response)
                case 204:
                    return MPAPIResponse(state=True, message=response)
                case _:
                    self.logger.debug("MP API PUT request to {} failed: {}".format(url, response.json()))
                    return MPAPIResponse(state=False,
                                         message="MP API PUT request to {} failed: "
                                                 "{}".format(url, response.json()))
        except KeyboardInterrupt:
            return MPAPIResponse(state=False, message="Operation interrupted")
        except BaseException as err:
            self.logger.error("MP API PUT request to {} failed: {}".format(url, err))
            return MPAPIResponse(state=False, message="MP API PUT request to {} failed: {}".format(url, err))

    def delete(self, url: str, data: dict) -> MPAPIResponse:
        """
        Delete method
        :param url: string
        :param data: body data
        """
        if app.app.GLOBAL_DISARM:
            return MPAPIResponse(state=False, message="Global disarmed")
        try:
            if not self.auth_header and not self.session:
                response = requests.delete(url, data=data,
                                           headers={'Content-Type': 'application/x-www-form-urlencoded'},
                                           verify=False)
            elif not self.session:
                response = requests.delete(url, data=json.dumps(data), headers=self.json_auth_header, verify=False)
            else:
                response = self.session.delete(url, headers={'Content-Type': 'application/x-www-form-urlencoded'},
                                               data=json.dumps(data))
            match response.status_code:
                case 400:
                    if "errors" in response.json():
                        for item in response.json()["errors"]:
                            if "error" in item:
                                if "type" in item["error"]:
                                    if item["error"]["type"] == "core.scanning.credential.dependency.credential.error":
                                        return MPAPIResponse(state=False,
                                                             message="Unable to delete: dependency present")
                    self.logger.debug("MP API DELETE request to {} failed: {}".format(url, response.json()))
                    return MPAPIResponse(state=False,
                                         message="MP API DELETE request to {} "
                                                 "failed: {}".format(url, response.json()))
                case 204:
                    self.logger.debug("MP API DELETE request to {} completed: {}".format(url, response.status_code))
                    return MPAPIResponse(state=True, message=response)
                case 200:
                    self.logger.debug("MP API DELETE request to {} completed: {}".format(url, response.status_code))
                    return MPAPIResponse(state=True, message=response)
                case _:
                    self.logger.debug("MP API DELETE request to {} failed: {}".format(url, response.json()))
                    return MPAPIResponse(state=False,
                                         message="MP API DELETE request to {} "
                                                 "failed: {}".format(url, response.json()))
        except KeyboardInterrupt:
            return MPAPIResponse(state=False, message="Operation interrupted")
        except BaseException as err:
            self.logger.error("MP API DELETE request to {} failed: {}".format(url, err))
            return MPAPIResponse(state=False, message="MP API DELETE request to {} failed: {}".format(url, err))

    @staticmethod
    def __check_tested(version: str) -> None:
        """
        Version support check
        :param version: string
        """
        version_split = version.split(".")
        major_ok = False
        minor_ok = False
        build_ok = False
        for item in app.MP_TESTED:
            if item.get("major") == int(version_split[0]):
                major_ok = True
                for itm in item["minors"]:
                    if itm.get("minor") == int(version_split[1]):
                        minor_ok = True
                        if itm["min"] <= int(version_split[2]) <= itm["max"]:
                            build_ok = True
        if not major_ok:
            rich_print("[yellow]Product version is {}".format(version))
            rich_print("[yellow]Major version {} is not tested yet. "
                       "Please be careful and let us know your experience".format(version_split[0]))
            return
        if not minor_ok:
            rich_print("[yellow]Product version is {}".format(version))
            rich_print("[yellow]Major version in general looks good, but minor version {} is not tested yet. "
                       "Please be careful and let us know your experience".format(version_split[1]))
            return
        if not build_ok:
            rich_print("[yellow]Product version is {}".format(version))
            rich_print("[yellow]Major and minor version in general looks good, but build version {} is not tested yet. "
                       "Please be careful and let us know your experience".format(version_split[2]))
            return
        return
