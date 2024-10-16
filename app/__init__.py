from app.core import *
from app.mp import *
from app.settings import *
from rich import print as rich_print

PROFILE_MP = None
PROFILE_NAD = None
ENABLE_STATUS = ''
API_MP = None

VERSION = "24.07.29.1"
MIXIN_REF_VERSION = "2"

DB = None
DBQUERY = None
ARG_RUN = False

CONTEXT = None
LAST_CONTEXT = None

GLOBAL_DISARM = False

SECRET_KEY = "none"
SETTINGS = None
HISTORY_PATH = None

MP_TESTED = [
    {
        "major": 25,
        "minors": [
            {"minor": 1, "min": 6027, "max": 6027}
        ]
    },
    {
        "major": 26,
        "minors": [
            {"minor": 0, "min": 5304, "max": 6901},
            {"minor": 1, "min": 8323, "max": 8760},
            {"minor": 2, "min": 9861, "max": 10757}
        ]
    }
]
MP_APPS = None


def dev_print(string: str):
    rich_print("[bright_cyan]{}".format(string))
