

class SyncFailure(Exception):
    def __init__(self, code: str, transient: bool = False, detail: dict | None = None):
        super().__init__(code)
        self.code = code
        self.transient = transient
        self.detail = detail or {}
