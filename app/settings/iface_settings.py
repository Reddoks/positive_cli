from rich import print as rich_print
from sys import exit


# Settings
class iface_Settings: # noqa
    def __init__(self, db, dbquery):
        """
        Interface for CLI settings
        :param db: database object
        :param dbquery: dbquery object
        """
        self.db = db.table('settings')
        self.dbquery = dbquery
        self.data = {
            "log_level": "INFO",
            "log_path": ".",
            "history_path": "."
        }
        self.__load_settings()

    def set(self, param_name: str, value: str) -> None:
        """
        Settings set method
        :param param_name: string
        :param value: string
        """
        exist = self.db.search(self.dbquery[param_name] != "something")
        if exist:
            self.db.update({param_name: value})
            self.__load_settings()
            print("To activate changes you should restart CLI")
        else:
            return

    def __load_settings(self) -> None:
        """
        Settings loader
        """
        # Log level
        try:
            resp = self.db.search(self.dbquery.log_level != "something")
        except BaseException as err:
            rich_print("[red]Unable to decrypt CLI database. Probably you entered wrong encryption secret.")
            print("If you would like to create other database - delete pt_cli.encrypted in you home folder and "
                  ".history.encrypted")
            print("Error details: {}".format(err))
            exit()
        if not resp:
            self.db.insert({"log_level": self.data.get("log_level")})
        else:
            self.data["log_level"] = resp[0]["log_level"]
        # Log path
        resp = self.db.search(self.dbquery.log_path != "something")
        if not resp:
            self.db.insert({"log_path": self.data.get("log_path")})
        else:
            self.data["log_path"] = resp[0]["log_path"]
        # History path
        resp = self.db.search(self.dbquery.history_path != "something")
        if not resp:
            self.db.insert({"history_path": self.data.get("history_path")})
        else:
            self.data["history_path"] = resp[0]["history_path"]
