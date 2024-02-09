import logging

from rich import print as rich_print
from rich.prompt import Prompt
from app.mp.api import MPAPIResponse
from app.mp.etl.api import ETL_Sources
from app.mp.asset.iface_asset_group import iface_MP_Group
from app.mp.asset.iface_asset import iface_MP_Asset
from app.mp.iface_pdql import iface_MP_PDQL


# Source Assets PDQL
class SourceAssetsPDQL:
    def __init__(self):
        # Option for source type
        self.option = "assets"
        self.logger = logging.getLogger("mp_etl_source")

    # Create source method
    @staticmethod
    def create() -> MPAPIResponse:
        source = {
            "type": "assets",
            "query": {}
        }
        rich_print("[bright_black]Asset data can be extracted using PDQL query")
        while True:
            source["query"]["pdql"] = Prompt.ask("PDQL Query ")
            if not source.get("query").get("pdql"):
                rich_print("[red]PDQL query can`t be empty")
                continue
            break
        try:
            iface_group = iface_MP_Group()
        except KeyboardInterrupt:
            return MPAPIResponse(state=False, message="Operation interrupted")
        except BaseException as err:
            return MPAPIResponse(state=False, message="MP group API init failed: {}".format(err))
        rich_print("[bright_black]You may enter asset groups for query (Enter to skip or finish)")
        asset_groups = []
        while True:
            response = iface_group.get_group_picker("Asset Group :")
            if not response.state:
                break
            rich_print("[yellow]+ {}".format(response.message.get("name")))
            asset_groups.append(response.message)
        source["query"]["groups"] = asset_groups
        rich_print("[bright_black]Also you may enter assets for query (Enter to skip or finish)")
        assets = []
        while True:
            selected_asset = iface_MP_Asset.get_asset_picker("Asset ")
            if not selected_asset.state:
                break
            rich_print("[yellow]+ {}".format(selected_asset.message.get("name")))
            assets.append(selected_asset.message.get("id"))
        source["query"]["assets"] = assets
        return MPAPIResponse(state=True, message=source)

    # Extraction
    def extract(self, source: dict, params: dict) -> MPAPIResponse:
        self.logger.debug("Running ETL extraction source - asset PDQL")

        def lookup_vars(string: str, vrs: dict) -> str:
            for key, value in vrs.items():
                string = string.replace("{{" + key + "}}", value)
            return string

        # Construct PDQL request
        pdql_string = source.get("query", {}).get("pdql")
        pdql_string = lookup_vars(pdql_string, params)
        self.logger.debug("Request PDQL: {}".format(pdql_string))
        try:
            asset = iface_MP_PDQL(pdql_string, filter={"groupIDs": source.get("query", {}).get("groups"),
                                                   "assetIDs": source.get("query", {}).get("assets")})
        except BaseException as err:
            return MPAPIResponse(state=False,
                                 message="PDQL request failed: {}".format(err))
        if not asset:
            self.logger.error("Error during PDQL request")
            return MPAPIResponse(state=False, message="Error during PDQL request")
        asset_count = asset.get_count().message
        self.logger.debug("PDQL request success - got {} records".format(asset_count))
        return MPAPIResponse(state=True, message={"type": "MPPDQL", "obj": asset})


ETL_Sources.append(SourceAssetsPDQL())
