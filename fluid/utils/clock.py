from datetime import datetime, UTC


class Clock:
    offset = None

    @classmethod
    def now(cls) -> datetime:
        moment = datetime.now(UTC).replace(microsecond=0)
        return moment + cls.offset if cls.offset is not None else moment

    @classmethod
    def ts(cls) -> str:
        return cls.now().strftime("%Y-%m-%dT%H:%M:%SZ")
