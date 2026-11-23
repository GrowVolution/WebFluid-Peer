from webfluid.utils.countries import is_valid as valid_country
from webfluid.utils.logging import factory as log_factory
from wf_peering.protocol.canonical import canonical
import hashlib

from ..exceptions import ConfigurationError

FORMS = ("natural_person", "sole_trader", "company", "association", "public_body")
REPRESENTED = ("company", "association", "public_body")
BASES = ("art6_1_f",)
EEA = ("AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GR", "HR", "HU", "IE", "IT", "LT", "LU",
       "LV", "MT", "NL", "PL", "PT", "RO", "SE", "SI", "SK", "IS", "LI", "NO")
PUBLIC_FIELDS = ("name", "form", "legal_form", "address", "country", "email", "phone", "contact_form",
                 "representatives", "register", "vat_id", "economic_id", "capital", "outstanding",
                 "supervisory_authority", "profession", "in_liquidation", "editorial", "provisions")
REPLICATED_FIELDS = ("name", "form", "country", "ids")

DATAFLOWS = (
    { "id": "visit", "basis": "art6_1_f", "retention": "transient", "public": False, "third": False },
    { "id": "proxy", "basis": "art6_1_f", "retention": "proxy_logs_days", "public": False, "third": False },
    { "id": "app_join", "basis": "art6_1_f", "retention": "metadata", "public": True, "third": True },
    { "id": "node_join", "basis": "art6_1_f", "retention": "network", "public": True, "third": True },
    { "id": "operator", "basis": "art6_1_f", "retention": "declaration", "public": True, "third": True },
    { "id": "liveness", "basis": "art6_1_f", "retention": "network", "public": True, "third": True },
    { "id": "ledger", "basis": "art6_1_f", "retention": "metadata", "public": True, "third": True },
    { "id": "observations", "basis": "art6_1_f", "retention": "network", "public": True, "third": True },
    { "id": "events", "basis": "art6_1_f", "retention": "network", "public": True, "third": True },
    { "id": "search", "basis": "art6_1_f", "retention": "transient", "public": False, "third": False },
    { "id": "verifier", "basis": "art6_1_f", "retention": "transient", "public": False, "third": False },
    { "id": "rate_limit", "basis": "art6_1_f", "retention": "window", "public": False, "third": False },
    { "id": "references", "basis": "art6_1_f", "retention": "transient", "public": False, "third": True },
    { "id": "backups", "basis": "art6_1_f", "retention": "backups_days", "public": False, "third": False }
)


def _text(value) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _lines(value) -> bool:
    return isinstance(value, (list, tuple)) and bool(value) and all(_text(line) for line in value)


def _country(value) -> bool:
    return isinstance(value, str) and len(value) == 2 and value.isupper() and valid_country(value)


def problems(legal) -> list[str]:
    found = []
    if not isinstance(legal, dict): return ["LEGAL"]
    operator = legal.get("operator")
    if not isinstance(operator, dict): return ["LEGAL.operator"]
    for key in ("name", "email"):
        if not _text(operator.get(key)): found.append(f"LEGAL.operator.{key}")
    if not _lines(operator.get("address")): found.append("LEGAL.operator.address")
    if not _country(operator.get("country")): found.append("LEGAL.operator.country")
    form = operator.get("form")
    if form not in FORMS: found.append("LEGAL.operator.form")
    if type(operator.get("commercial")) is not bool: found.append("LEGAL.operator.commercial")
    if form in REPRESENTED:
        people = operator.get("representatives")
        if not isinstance(people, (list, tuple)) or not people or not all(_text(item) for item in people):
            found.append("LEGAL.operator.representatives")
    if form == "company" and not _text(operator.get("legal_form")): found.append("LEGAL.operator.legal_form")
    register = operator.get("register")
    if form == "company" or operator.get("registered") is True or register is not None:
        if not isinstance(register, dict) or not all(_text(register.get(key)) for key in ("court", "type", "number")) \
                or ("country" in register and not _country(register.get("country"))):
            found.append("LEGAL.operator.register")
    if operator.get("permit_required") is True and not _text(operator.get("supervisory_authority")):
        found.append("LEGAL.operator.supervisory_authority")
    profession = operator.get("profession")
    if profession is not None and (not isinstance(profession, dict)
                                   or not all(_text(profession.get(key)) for key in ("title", "state", "chamber", "rules"))):
        found.append("LEGAL.operator.profession")
    editorial = operator.get("editorial")
    if operator.get("journalistic") is True or editorial is not None:
        if not isinstance(editorial, dict) or not _text(editorial.get("name")) or not _lines(editorial.get("address")):
            found.append("LEGAL.operator.editorial")
    privacy = legal.get("privacy")
    if not isinstance(privacy, dict): return found + ["LEGAL.privacy"]
    if privacy.get("legal_basis") not in BASES: found.append("LEGAL.privacy.legal_basis")
    if not _text(privacy.get("hosting")): found.append("LEGAL.privacy.hosting")
    if not _text(privacy.get("supervisory_authority")): found.append("LEGAL.privacy.supervisory_authority")
    transfers = privacy.get("transfers")
    if transfers is not False and not _text(transfers): found.append("LEGAL.privacy.transfers")
    for key in ("proxy_logs_days", "backups_days"):
        value = privacy.get(key)
        if value is not None and (type(value) is not int or value < 0): found.append(f"LEGAL.privacy.{key}")
        if key not in privacy: found.append(f"LEGAL.privacy.{key}")
    dpo = privacy.get("dpo", None)
    if "dpo" not in privacy or (dpo is not False and (not isinstance(dpo, dict) or not _text(dpo.get("email")))):
        found.append("LEGAL.privacy.dpo")
    if _country(operator.get("country")) and operator["country"] not in EEA:
        representative = privacy.get("representative")
        exempt = privacy.get("representative_exempt") is True
        if not exempt and (not isinstance(representative, dict) or not _text(representative.get("name"))
                           or not _lines(representative.get("address"))):
            found.append("LEGAL.privacy.representative")
    return found


def validate(config, debug: bool) -> list[str]:
    found = problems(config.get("LEGAL"))
    if not found: return []
    message = "incomplete operator information for the imprint and privacy pages: " + ", ".join(found)
    if debug:
        log_factory.warning(f"[peering] LEGAL: {message} (debug mode: the pages show what is missing).")
        return found
    raise ConfigurationError("LEGAL", "INCOMPLETE", message)


def _section(config, name: str) -> dict:
    legal = config.get("LEGAL") if isinstance(config.get("LEGAL"), dict) else {}
    return legal.get(name) if isinstance(legal.get(name), dict) else {}


def provisions(operator: dict) -> list[str]:
    out = ["§ 5 DDG"] if operator.get("commercial") is True else []
    out.append("§ 18 Abs. 1 MStV")
    if isinstance(operator.get("editorial"), dict): out.append("§ 18 Abs. 2 MStV")
    return out


def _register(operator: dict) -> dict | None:
    register = operator.get("register")
    if not isinstance(register, dict) or not _text(register.get("number")): return None
    kind, number = str(register.get("type") or "").strip(), str(register["number"]).strip()
    shown = number if not kind or number.upper().replace(" ", "").startswith(kind.upper().replace(" ", "")) \
        else f"{kind} {number}"
    return { "country": register.get("country") or operator.get("country"), "court": register.get("court"),
             "type": kind or None, "number": number, "display": shown }


def public_imprint(config) -> dict:
    operator = _section(config, "operator")
    data = {
        "name": operator.get("name"), "form": operator.get("form"), "legal_form": operator.get("legal_form"),
        "address": list(operator.get("address") or []), "country": operator.get("country"),
        "email": operator.get("email"), "phone": operator.get("phone"), "contact_form": operator.get("contact_form"),
        "representatives": list(operator.get("representatives") or []), "register": _register(operator),
        "vat_id": operator.get("vat_id"), "economic_id": operator.get("economic_id"),
        "capital": operator.get("capital"), "outstanding": operator.get("outstanding"),
        "supervisory_authority": operator.get("supervisory_authority") if operator.get("permit_required") is True
        else None,
        "profession": operator.get("profession") if isinstance(operator.get("profession"), dict) else None,
        "in_liquidation": operator.get("in_liquidation") is True,
        "editorial": operator.get("editorial") if isinstance(operator.get("editorial"), dict) else None,
        "provisions": provisions(operator)
    }
    return { key: data[key] for key in PUBLIC_FIELDS }


def imprint_digest(imprint: dict) -> str:
    return hashlib.sha256(canonical(imprint)).hexdigest()


def declared_operator(imprint: dict) -> dict | None:
    if not _text(imprint.get("name")) or imprint.get("form") not in FORMS or not _country(imprint.get("country")):
        return None
    ids = []
    register = imprint.get("register")
    if register and _text(register.get("court")) and _text(register.get("type")):
        ids.append({ "scheme": "register", "country": register["country"], "authority": register["court"].strip()[:128],
                     "type": register["type"].strip()[:16], "number": register["number"].strip()[:64] })
    if _text(imprint.get("vat_id")): ids.append({ "scheme": "vat", "number": imprint["vat_id"].strip()[:64] })
    if _text(imprint.get("economic_id")):
        ids.append({ "scheme": "economic", "number": imprint["economic_id"].strip()[:64] })
    return { "name": imprint["name"].strip()[:128], "form": imprint["form"], "country": imprint["country"],
             "ids": ids[:4] }


def node_operator(config) -> dict | None:
    imprint = public_imprint(config)
    if not _text(imprint.get("name")): return None
    return { "name": imprint["name"], **({ "contact": imprint["email"] } if _text(imprint.get("email")) else {}) }


def context(config) -> dict:
    privacy = _section(config, "privacy")
    imprint = public_imprint(config)
    controller = privacy.get("controller") if isinstance(privacy.get("controller"), dict) else imprint
    return {
        "operator": imprint, "privacy": privacy, "controller": controller,
        "missing": problems(config.get("LEGAL")), "flows": DATAFLOWS,
        "logging": { "path": bool(config.get("REQUEST_LOG_PATH")), "client": bool(config.get("REQUEST_LOG_CLIENT")),
                     "agent": bool(config.get("REQUEST_LOG_USER_AGENT")) },
        "retention_days": int(config.get("PEERING_METADATA_RETENTION_DAYS") or 90),
        "references": bool(config.get("PEERING_TRUSTED_REFERENCES")),
        "outside_eea": imprint.get("country") not in EEA if imprint.get("country") else False
    }
