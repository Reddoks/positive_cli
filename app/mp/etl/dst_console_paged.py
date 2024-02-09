import sys
import logging
from rich import print as rich_print
from rich.prompt import Prompt
from app.core.helpers import get_string_from_fmt
from app.mp.api import MPAPIResponse
from app.mp.etl.api import ETL_Destinations
from app.mp.etl.transform import JSTransform


# Console Stream
class DestinationConsolePaged:
    def __init__(self):
        # Option for source type
        self.option = "console_paged"
        self.logger = logging.getLogger("mp_etl_destination")
        self.applicable = ["assets"]

    # Create source method
    @staticmethod
    def create() -> MPAPIResponse:
        destination = {
            "type": "console_paged",
            "options": {
                "limit": 10
            }
        }
        rich_print("[bright_black]Console paged mode will out data to console page by page with line limit")
        limit = Prompt.ask("Lines limit per page ", default="10")
        try:
            destination["options"]["limit"] = int(limit)
        except:
            return MPAPIResponse(state=False, message="Wrong limit value")
        rich_print("[bright_black]For console_paged destination, you can set format type")
        fmt = Prompt.ask("Output format ", choices=["raw", "json", "yaml", "csv", "table"], default="raw")
        destination["options"]["fmt"] = fmt
        return MPAPIResponse(state=True, message=destination)

    # Load method
    def load(self, obj_block: dict, transform: str, params: dict, destination: dict) -> MPAPIResponse:
        # MPPDQL handler
        if obj_block["type"] == "MPPDQL":
            PDQLOBJ = obj_block["obj"]
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
            if params.get("limit"):
                pdql_limit = params.get("limit")
            else:
                pdql_limit = destination.get("options", {}).get("limit")
            if params.get("offset"):
                pdql_offset = params.get("offset")
            if params.get("fmt"):
                fmt = params.get("fmt")
            else:
                fmt = destination.get("options", {}).get("fmt")

            # Start paged output
            block_count = PDQLOBJ.get_count().message
            # If transform results should be aggregated, run all blocks transformation and get aggregated result
            if transform.get("aggregated"):
                aggregated_result = []
                for idx in range(pdql_offset, block_count, pdql_limit):
                    block_data = PDQLOBJ.get_offset_list(idx, pdql_limit)
                    aggregated_result = transform_func.transform(block_data.message, aggregated=True)
                if type(aggregated_result) != list:
                    if fmt == "csv" or fmt == "table":
                        return MPAPIResponse(state=False,
                                             message="Wrong aggregated result type: {}, "
                                                     "but required list "
                                                     "for fmt: {}".format(type(aggregated_result), fmt))
                    if fmt != "raw":
                        result_formatted = get_string_from_fmt(aggregated_result, fmt=fmt)
                    else:
                        result_formatted = aggregated_result
                    print(result_formatted)
                else:
                    if fmt != "raw":
                        result_formatted = get_string_from_fmt(aggregated_result, fmt=fmt)
                    else:
                        result_formatted = aggregated_result
                    for item in range(0, len(result_formatted), pdql_limit):
                        for ix in range(item, item + pdql_limit):
                            print(result_formatted[ix])
                        try:
                            cont = input("Hit ENTER to continue")
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K')
                        except KeyboardInterrupt:
                            sys.stdout.write('\x1b[1A')
                            # sys.stdout.write('\x1b[2K')
                            print("")
                            return MPAPIResponse(state=False,
                                                 message="Operation interrupted")
            else:
                for idx in range(pdql_offset, block_count, pdql_limit):
                    block_data = PDQLOBJ.get_offset_list(idx, pdql_limit)
                    if transform_func:
                        block_transformed = transform_func.transform(block_data.message)
                    else:
                        block_transformed = block_data.message
                    # Getting formatted block
                    if fmt == "raw":
                        block_formatted = str(block_transformed)
                    else:
                        block_formatted = get_string_from_fmt(block_transformed, fmt=fmt)
                        if type(block_formatted) != str:
                            return MPAPIResponse(state=False, message="Unable to get data using format: {}"
                                                 .format(destination.get("options", {}).get("fmt")))
                    print(block_formatted)
                    try:
                        cont = input("Hit ENTER to continue")
                        sys.stdout.write('\x1b[1A')
                        sys.stdout.write('\x1b[2K')
                    except KeyboardInterrupt:
                        sys.stdout.write('\x1b[1A')
                        # sys.stdout.write('\x1b[2K')
                        print("")
                        return MPAPIResponse(state=False,
                                             message="Operation interrupted")
        return MPAPIResponse(state=True, message="ETL Job(s) completed")


ETL_Destinations.append(DestinationConsolePaged())
