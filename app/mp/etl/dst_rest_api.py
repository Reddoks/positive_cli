import sys
import logging
import requests
from rich import print as rich_print
from rich.prompt import Prompt, IntPrompt
from app.core.helpers import get_string_from_fmt
from app.core.func import deep_get
from app.mp.api import MPAPIResponse
from app.mp.etl.api import ETL_Destinations
from app.mp.etl.transform import JSTransform


# Remote REST API
class DestinationRESTAPI:
    def __init__(self):
        # Option for source type
        self.option = "rest_api"
        self.logger = logging.getLogger("mp_etl_destination")
        self.applicable = ["rest_api"]

    # Create source method
    @staticmethod
    def create() -> MPAPIResponse:
        destination = {
            "type": "rest_api",
            "options": {
                "part_size": 0,
                "type": "post",
                "content_type": "application/json",
                "auth": {
                    "type": "basic"
                },
                "endpoint": "",
                "success_status": ["200"]
            }
        }
        rich_print("[bright_black]REST API mode will out data to remote API via requests")
        destination["options"]["type"] = Prompt.ask("Request type ", choices=["post"], default="post")
        # If POST
        if destination["options"]["type"] == "post":
            rich_print("[bright_black]POST request can send data with different content types - "
                       "it depends on data you send and data can be parsed on remote side")
            destination["options"]["content_type"] = Prompt.ask("Content-type ",
                                                                choices=["application/json",
                                                                         "text/plain"], default="application/json")
            destination["options"]["auth"]["type"] = Prompt.ask("Authentication type ", choices=["none", "basic"],
                                                                default="none")
            if destination["options"]["auth"]["type"] == "basic":
                rich_print("[bright_black]You may set credentials for basic auth here "
                           "or use arguments when exec pipeline")
                destination["options"]["auth"]["username"] = Prompt.ask("Username (ENTER to skip) ")
                if destination["options"]["auth"]["username"]:
                    destination["options"]["auth"]["password"] = Prompt.ask("Password (ENTER to skip) ",
                                                                            password=True)
        while True:
            destination["options"]["endpoint"] = Prompt.ask("API endpoint ")
            if not destination["options"]["endpoint"]:
                rich_print("[red]Remote API endpoint can`t be empty")
                continue
            break
        rich_print("[bright_black]Remote API may return various status codes. You can set acceptable "
                   "(success) codes besides 200")
        statuses = Prompt.ask("Success codes (comma separated, ENTER to skip) ")
        stat_split = statuses.split(",")
        for ix in range(0, len(stat_split)):
            stat_split[ix] = stat_split[ix].strip()
        destination["options"]["success_status"] += stat_split

        rich_print("[bright_black]You can divide data load process to several parts (separate requests)")
        use_parts = Prompt.ask("Do you want use parts (separated requests)?", choices=["y", "n"], default="n")
        if use_parts == "y":
            destination["options"]["part_size"] = IntPrompt.ask("Elements in part ", default=1)
        return MPAPIResponse(state=True, message=destination)

    # Load method
    def load(self, obj_block: dict, transform: dict, params: dict, destination: dict) -> MPAPIResponse:
        def post_load(endpoint: str, content_type: str, auth: dict, prms: dict, status: list, data) -> MPAPIResponse:
            auth_username = None
            auth_password = None
            if auth.get("type") == "basic":
                if prms.get("username"):
                    auth_username = prms.get("username")
                else:
                    auth_username = auth.get("username")
                if prms.get("password"):
                    auth_password = prms.get("password")
                else:
                    auth_password = auth.get("password")
                if not auth_username or not auth_password:
                    return MPAPIResponse(state=False,
                                         message="Basic auth enabled, but no auth data provided")
            # Build headers
            headers_str = {
                "Content-Type": content_type
            }
            # POST
            if auth.get("type") == "basic":
                session = requests.session()
                session.auth = (auth_username, auth_password)
                resp = session.post(url=endpoint,
                                    headers=headers_str,
                                    data=data)
            else:
                return MPAPIResponse(state=False, message="Failed POST request - wrong auth")
            for itm in status:
                if str(resp.status_code) == itm:
                    return MPAPIResponse(state=True, message="Success: {}".format(resp.status_code))
            try:
                return MPAPIResponse(state=False, message="Failed POST request - {}".format(resp.json()))
            except:
                return MPAPIResponse(state=False, message="Failed POST request - {}".format(resp.status_code))

        self.logger.debug("Begin REST API load operation")
        # MPPDQL handler
        if obj_block["type"] == "MPPDQL":
            pdql_obj = obj_block["obj"]
            if transform.get("code"):
                try:
                    transform_func = JSTransform(code=transform.get("code"))
                except BaseException as err:
                    print('An exception occurred in transform function: {}'.format(err))
                    return MPAPIResponse(state=False,
                                         message='An exception occurred in transform function: {}'.format(err))
            else:
                transform_func = None
            pdql_offset = 0
            if params.get("part_size"):
                pdql_part_size = params.get("part_size")
            else:
                pdql_part_size = destination.get("options", {}).get("limit")
            if params.get("offset"):
                pdql_offset = params.get("offset")

            # Start REST API output
            block_count = pdql_obj.get_count().message
            # If transform results should be aggregated, run all blocks transformation and get aggregated result
            if transform.get("aggregated"):
                aggregated_result = []
                for idx in range(pdql_offset, block_count, block_count):
                    block_data = pdql_obj.get_offset_list(idx, block_count)
                    aggregated_result = transform_func.transform(block_data.message, aggregated=True)
                if destination.get("options", {}).get("type") == "post":
                    response = post_load(endpoint=destination.get("options", {}).get("endpoint"),
                                         content_type=destination.get("options", {}).get("content_type"),
                                         auth=destination.get("options", {}).get("auth"),
                                         prms=params,
                                         status=destination.get("options", {}).get("success_status"),
                                         data=aggregated_result)
                    return response
        return MPAPIResponse(state=True, message="ETL Job(s) completed")


ETL_Destinations.append(DestinationRESTAPI())
