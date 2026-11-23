

class ConfigurationError(Exception):
    def __init__(self, key: str, code: str, message: str):
        super().__init__(f"{key}: {message} ({code})")
        self.key = key
        self.code = code


class NetFailure(Exception):
    def __init__(self, code: str, status: int = 400, detail: dict | None = None):
        super().__init__(code)
        self.code = code
        self.status = status
        self.detail = detail or {}
