import logging
from time import sleep

import app
from app.core.func import console_clear_up, get_keys_from_dict
from app.mp.api import MPAPIResponse
from rich.progress import Progress
from rich import print as rich_print


class iface_MP_Reachability:  # noqa
    def __init__(self):
        """
        Interface for Asset Scans
        """
        self.logger = logging.getLogger("mp.asset.iface_reachability")
        self.object_cache = []

    def calculate(self, source_targets: dict, destination_targets: dict, where=False) -> MPAPIResponse:
        """
        Calculate reachability between targets
        :param destination_targets: dst struct
        :param source_targets: src struct
        :param where: where flag
        """
        # Build request structure
        request_struct = {
            "sourceHosts": source_targets["asset"],
            "sourceGroups": source_targets["group"],
            "destinationHosts": destination_targets["asset"],
            "destinationGroups": destination_targets["group"],
            "destinationAddresses": destination_targets["network"],
            "protocols": [],
            "excludedProtocols": []
        }
        # Send request
        response = self.__request(request_struct=request_struct)
        if not response.state:
            return response
        token = response.message
        # Start analysis
        response = self.__start(analysis_token=token)
        if not response.state:
            return response
        # Wait for completion
        retries = 24
        while not self.__state(analysis_token=token).state:
            if retries == 0:
                self.logger.error("Calculation request response not received in 120 seconds.")
                return MPAPIResponse(state=False, message="Calculation request response not received in 120 seconds.")
            retries -= 1
            sleep(5)
        # Getting results
        result_sources = app.API_MP.get(app.API_MP.url_asset_reachability_result_sources.format(token))
        if not result_sources.state:
            return result_sources
        result_destinations = app.API_MP.get(app.API_MP.url_asset_reachability_result_destinations.format(token))
        if not result_destinations.state:
            return result_destinations
        # Getting facts
        output = []
        # Getting units
        units_struct = app.API_MP.get(app.API_MP.url_asset_reachability_units.format(token))
        if units_struct.state:
            units_struct = units_struct.message.json().get("items")
            with Progress() as progress:
                task = progress.add_task("Walk units...", total=len(units_struct))
                # Walk units
                for unit in units_struct:
                    to_val = unit.get("to")
                    from_val = unit.get("from")
                    for proto in unit.get("protocols"):
                        for port in proto.get("ports"):
                            ports = "from: {} to {}".format(port.get("from"), port.get("to"))
                            routes = self.__get_unit_routes(token, port.get("routes"), from_val, to_val)
                            for route in routes:
                                out_instance = {
                                    "from": route.get("firsthop"),
                                    "to": route.get("lasthop"),
                                    "protocol": proto.get("name"),
                                    "ports": ports,
                                    "hopsCount": route.get("hopsCount"),
                                    "hopsPath": route.get("hopsPath"),
                                    "details": route
                                }
                                if out_instance not in output:
                                    output.append(out_instance)
                    progress.update(task, advance=1)
            console_clear_up(skip_line=True)
        if not where:
            # Getting sources
            result_sources = result_sources.message.json().get("items")
            # Walk sources
            with Progress() as progress:
                task = progress.add_task("Walk sources...", total=len(result_sources))
                for source in result_sources:
                    protocol_details = app.API_MP.get(app.API_MP.url_asset_reachability_src_protocols.
                                                      format(token, source.get("id")))
                    if protocol_details.state:
                        protocol_details = protocol_details.message.json().get("items")
                        proto_idx = 0
                        for proto in protocol_details:
                            ports = "from: {} to {}".format(proto.get("ports").get("from"),
                                                            proto.get("ports").get("to"))
                            routes = self.__get_src_routes(token, source.get("id"), proto_idx, proto.get("routesCount"))
                            proto_idx += 1
                            for route in routes:
                                out_instance = {
                                    "from": route.get("firsthop"),
                                    "to": route.get("lasthop"),
                                    "protocol": proto.get("name"),
                                    "ports": ports,
                                    "potentially": route.get("potentially"),
                                    "hopsPath": route.get("hopsPath"),
                                    "details": route
                                }
                                if not self.__compare_routes(output, out_instance):
                                    output.append(out_instance)
                    progress.update(task, advance=1)
            console_clear_up(skip_line=True)
        else:
            # Getting destinations
            result_destinations = result_destinations.message.json().get("items")
            # Walk sources
            with Progress() as progress:
                task = progress.add_task("Walk destinations...", total=len(result_destinations))
                for destination in result_destinations:
                    protocol_details = app.API_MP.get(app.API_MP.url_asset_reachability_dst_protocols.
                                                      format(token, destination.get("id")))
                    if protocol_details.state:
                        protocol_details = protocol_details.message.json().get("items")
                        proto_idx = 0
                        for proto in protocol_details:
                            ports = "from: {} to {}".format(proto.get("ports").get("from"),
                                                            proto.get("ports").get("to"))
                            routes = self.__get_dst_routes(token, destination.get("id"), proto_idx,
                                                           proto.get("routesCount"))
                            proto_idx += 1
                            for route in routes:
                                out_instance = {
                                    "from": route.get("firsthop"),
                                    "to": route.get("lasthop"),
                                    "protocol": proto.get("name"),
                                    "ports": ports,
                                    "potentially": route.get("potentially"),
                                    "hopsPath": route.get("hopsPath"),
                                    "details": route
                                }
                                if not self.__compare_routes(output, out_instance):
                                    output.append(out_instance)
                    progress.update(task, advance=1)
            console_clear_up(skip_line=True)
        return MPAPIResponse(state=True, message=output)

    @staticmethod
    def __compare_routes(route_list, route_item):
        for route in route_list:
            if (route.get("hopsPath") == route_item.get("hopsPath")
                    and route.get("protocol") == route_item.get("protocol")
                    and route.get("ports") == route_item.get("ports")):
                return True
        return False

    def __state(self, analysis_token: str) -> MPAPIResponse:
        """
        Check analysis completed
        :param analysis_token: token string
        """
        self.logger.debug("Trying to get status for {}".format(analysis_token))
        response = app.API_MP.get(app.API_MP.url_asset_reachability_state.format(analysis_token))
        if not response.state:
            self.logger.error("'Analysis state request failed: {}".format(response.message))
            return response
        response = response.message.json()
        if response.get("state") != "completed":
            return MPAPIResponse(state=False, message="Not ready")
        return MPAPIResponse(state=True, message="Completed")

    def __start(self, analysis_token: str) -> MPAPIResponse:
        """
        Start reachable analysis
        :param analysis_token: token string
        """
        self.logger.debug("Trying to start {}".format(analysis_token))
        response = app.API_MP.post(app.API_MP.url_asset_reachability_start.format(analysis_token), data={})
        if not response.state:
            self.logger.error("'Analysis start failed: {}".format(response.message))
            return response
        return MPAPIResponse(state=True, message="Started")

    def __request(self, request_struct: dict) -> MPAPIResponse:
        """
        Execute calculation request
        """
        self.logger.debug("Trying to create reachability calculation request")
        response = app.API_MP.post(app.API_MP.url_asset_reachability, data=request_struct)
        if not response.state:
            rich_print("[red]Create reachability request failed: {}".format(response.message))
            self.logger.error("Create reachability request failed: {}".format(response.message))
            return response
        resp_json = response.message.json()
        self.logger.debug("Reachability request succeeded")
        return MPAPIResponse(state=True, message=resp_json.get("analysisId"))

    def __resolve(self, kind: str, target_id: str) -> MPAPIResponse:
        def check_cache(cache_id: str) -> MPAPIResponse:
            for c_item in self.object_cache:
                if c_item.get("id") == cache_id:
                    return MPAPIResponse(state=True, message=c_item.get("name"))
            return MPAPIResponse(state=False)

        """
        Resolve instance ID to name
        :param kind: host or network
        :param id: id string
        """
        cached = check_cache(cache_id=target_id)
        if cached.state:
            return MPAPIResponse(state=True, message=cached.message)
        if kind == "host":
            asset = app.API_MP.get(app.API_MP.url_asset_reachability_assets.format(target_id))
            if asset.state:
                asset = asset.message.json()
                if len(asset) > 0:
                    self.object_cache.append({
                        "id": target_id,
                        "name": asset[0].get("displayName")
                    })
                    return MPAPIResponse(state=True, message=asset[0].get("displayName"))
                else:
                    return MPAPIResponse(state=True, message="Other devices")
        if kind == "network":
            network = app.API_MP.post(app.API_MP.url_asset_reachability_networks,
                                      data=[target_id])
            if network.state:
                network = network.message.json()
                if len(network) > 0:
                    self.object_cache.append({
                        "id": target_id,
                        "name": network[0].get("displayName")
                    })
                    return MPAPIResponse(state=True, message=network[0].get("displayName"))
                else:
                    return MPAPIResponse(state=True, message="Other devices")
        return MPAPIResponse(state=False, message="Unable to resolve {} with ID: {}".format(kind, target_id))

    def __get_src_routes(self, token, source_id, proto_id, count):
        """
        Getting source routes
        """
        routes = []
        for idx in range(0, count):
            route_raw = app.API_MP.get(app.API_MP.url_asset_reachability_src_routes.
                                       format(token, source_id, proto_id, idx))
            if route_raw.state:
                route = {}
                route_raw = route_raw.message.json()
                if route_raw.get("flags"):
                    route["potentially"] = route_raw.get("flags", {}).get("potentially")
                    if not route["potentially"]:
                        route["potentially"] = " "
                route["hops"] = []
                for itm in route_raw.get("hops"):
                    hop = {}
                    if itm.get("nodeType") == "phantom":
                        hop["instance"] = "phantom"
                    if itm.get("nodeType") == "host":
                        asset = self.__resolve(kind="host", target_id=itm.get("objectId"))
                        if asset.state:
                            hop["instance"] = asset.message
                        else:
                            hop["instance"] = "phantom"
                    if itm.get("nodeType") == "network":
                        network = self.__resolve(kind="network", target_id=itm.get("objectId"))
                        if network.state:
                            hop["instance"] = network.message
                        else:
                            hop["instance"] = "phantom"
                    hop["interfaceIn"] = itm.get("interfaceIn")
                    hop["interfaceOut"] = itm.get("interfaceOut")
                    hop["interfaceIn"] = itm.get("interfaceIn")
                    hop["addresses"] = itm.get("addresses")
                    hop["global"] = itm.get("global")
                    route["hops"].append(hop)
                route["hopsCount"] = len(route["hops"])
                route["firsthop"] = route["hops"][0]["instance"]
                route["lasthop"] = route["hops"][len(route["hops"]) - 1]["instance"]
                route["hopsPath"] = ""
                for itm in route["hops"]:
                    if len(route["hopsPath"]) > 0:
                        route["hopsPath"] += " -> "
                    route["hopsPath"] += itm.get("instance")
                routes.append(route)
        return routes

    def __get_dst_routes(self, token, source_id, proto_id, count):
        """
        Getting destination routes
        """
        routes = []
        for idx in range(0, count):
            route_raw = app.API_MP.get(app.API_MP.url_asset_reachability_dst_routes.
                                       format(token, source_id, proto_id, idx))
            if route_raw.state:
                route = {}
                route_raw = route_raw.message.json()
                if route_raw.get("flags"):
                    route["potentially"] = route_raw.get("flags", {}).get("potentially")
                    if not route["potentially"]:
                        route["potentially"] = " "
                route["hops"] = []
                for itm in route_raw.get("hops"):
                    hop = {}
                    if itm.get("nodeType") == "phantom":
                        hop["instance"] = "phantom"
                    if itm.get("nodeType") == "host":
                        asset = self.__resolve(kind="host", target_id=itm.get("objectId"))
                        if asset.state:
                            hop["instance"] = asset.message
                        else:
                            hop["instance"] = "phantom"
                    if itm.get("nodeType") == "network":
                        network = self.__resolve(kind="network", target_id=itm.get("objectId"))
                        if network.state:
                            hop["instance"] = network.message
                        else:
                            hop["instance"] = "phantom"
                    hop["interfaceIn"] = itm.get("interfaceIn")
                    hop["interfaceOut"] = itm.get("interfaceOut")
                    hop["interfaceIn"] = itm.get("interfaceIn")
                    hop["addresses"] = itm.get("addresses")
                    hop["global"] = itm.get("global")
                    route["hops"].append(hop)
                route["hopsCount"] = len(route["hops"])
                route["firsthop"] = route["hops"][0]["instance"]
                route["lasthop"] = route["hops"][len(route["hops"]) - 1]["instance"]
                route["hopsPath"] = ""
                for itm in route["hops"]:
                    if len(route["hopsPath"]) > 0:
                        route["hopsPath"] += " -> "
                    route["hopsPath"] += itm.get("instance")
                routes.append(route)
        return routes

    def __get_unit_routes(self, token, routes_list, from_adr, to_adr):
        """

        """
        routes = []
        for r in routes_list:
            route_raw = app.API_MP.get(app.API_MP.url_asset_reachability_unit_routes.
                                       format(token, str(r), from_adr, to_adr))
            if route_raw.state:
                route = {}
                route_raw = route_raw.message.json()
                if route_raw.get("flags"):
                    route["potentially"] = route_raw.get("flags", {}).get("potentially")
                    if not route["potentially"]:
                        route["potentially"] = " "
                route["hops"] = []
                for itm in route_raw.get("hops"):
                    hop = {}
                    if itm.get("nodeType") == "phantom":
                        hop["instance"] = "phantom"
                    if itm.get("nodeType") == "host":
                        asset = self.__resolve(kind="host", target_id=itm.get("objectId"))
                        if asset.state:
                            hop["instance"] = asset.message
                        else:
                            hop["instance"] = "phantom"
                    if itm.get("nodeType") == "network":
                        network = self.__resolve(kind="network", target_id=itm.get("objectId"))
                        if network.state:
                            hop["instance"] = network.message
                        else:
                            hop["instance"] = "phantom"
                    hop["interfaceIn"] = itm.get("interfaceIn")
                    hop["interfaceOut"] = itm.get("interfaceOut")
                    hop["interfaceIn"] = itm.get("interfaceIn")
                    hop["addresses"] = itm.get("addresses")
                    hop["global"] = itm.get("global")
                    route["hops"].append(hop)
                route["hopsCount"] = len(route["hops"])
                route["firsthop"] = route["hops"][0]["instance"]
                route["lasthop"] = route["hops"][len(route["hops"]) - 1]["instance"]
                route["hopsPath"] = ""
                for itm in route["hops"]:
                    if len(route["hopsPath"]) > 0:
                        route["hopsPath"] += " -> "
                    route["hopsPath"] += itm.get("instance")
                routes.append(route)
        return routes

    @staticmethod
    def reduce(data: list) -> list:
        """
        Reachability info reducer
        """
        output = []
        for item in data:
            output.append(
                get_keys_from_dict(item, ["from", "to", "protocol", "ports", "potentially", "hopsPath"]))
        return output
