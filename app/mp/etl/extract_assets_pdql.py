import logging

from rich import print as rich_print
from rich.prompt import Prompt
from app.mp.api import MPAPIResponse
from app.mp.etl.api import ETL_Extract
from app.mp.asset.iface_asset_group import iface_MP_Group
from app.mp.asset.iface_asset import iface_MP_Asset
from app.mp.iface_pdql import iface_MP_PDQL


# Extract Assets PDQL
class ExtractAssetsPDQL:
    def __init__(self):
        # Kind for extraction type
        self.kind = "assets"
        self.logger = logging.getLogger("mp_etl_extract")

    # Extraction
    def extract(self, details: dict, params: dict) -> MPAPIResponse:
        self.logger.debug("Running ETL extraction source - asset PDQL")

        def lookup_vars(string: str, vrs: dict) -> str:
            for key, value in vrs.items():
                string = string.replace("{{" + key + "}}", value)
            return string

        # Validate details
        if not details.get("query", {}).get("pdql"):
            self.logger.error("Missing PDQL query in extraction details")
            return MPAPIResponse(state=False, message="Missing PDQL query in extraction details")

        # Construct PDQL request
        pdql_string = details.get("query", {}).get("pdql")
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


ETL_Extract.append(ExtractAssetsPDQL())
