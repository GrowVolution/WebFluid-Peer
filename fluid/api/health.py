from datetime import datetime, UTC


def handle_request():
    return {
        "status": "ok",
        "timestamp": datetime.now(UTC).isoformat()
    }
