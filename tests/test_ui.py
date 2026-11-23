import copy, re, pytest

VALID = {
    "operator": { "name": "Erika Beispiel", "form": "natural_person", "address": ["Weg 1", "12345 Ort"],
                  "country": "DE", "commercial": False, "email": "erika@example.org" },
    "privacy": { "legal_basis": "art6_1_f", "hosting": "Eigener Server", "proxy_logs_days": 0, "backups_days": None,
                 "supervisory_authority": "Aufsichtsbehörde Beispielland", "transfers": False, "dpo": False }
}


async def test_dashboard_renders_without_cookies_or_external_resources(client):
    from wf_peering.services import BindingService
    response = await client.get("/")
    assert response.status_code == 200 and "set-cookie" not in response.headers
    text = response.text
    assert await BindingService.network() in text and 'id="q"' in text and 'href="#main"' in text
    assert 'aria-current="page"' in text and "/imprint" in text and "/privacy" in text
    assert "https://" not in text.split("<main", 1)[0].replace("https://example.org", "")
    assert "Applications in this network" in text
    german = await client.get("/", headers={ "Accept-Language": "de" })
    assert '<html lang="de">' in german.text and "Anwendungen in diesem Netz" in german.text
    assert "Stand dieses Masters" in german.text
    filtered = await client.get("/", params={ "q": "two-shop" })
    assert "https://two-shop.example" in filtered.text
    css = await client.get("/net/static/css/net.css")
    assert css.status_code == 200 and "var(--tertiary-1" in css.text
    theme_url = re.search(r'<link rel="stylesheet" href="([^"]+/css/theme\.css)"', text)
    assert theme_url and (await client.get(theme_url[1])).status_code == 200


async def test_app_detail_shows_the_masters_own_state(client):
    from fluid.utils.apps import AppRegistry
    items = (await AppRegistry.search(None, 1, 50, True))["items"]
    app = items[0]["app"]
    page = await client.get(f"/apps/{app}")
    assert page.status_code == 200
    assert f"/api/v1/apps/{app}/evidence" in page.text and "Verdict of this master" in page.text
    unknown = await client.get("/apps/app1.AAAAAAAAAAAAAAAAAAAAAA")
    assert "does not know the application" in unknown.text


async def test_imprint_renders_only_configured_sections(client):
    text = (await client.get("/imprint", headers={ "Accept-Language": "de" })).text
    assert "Beispiel Peering e.V." in text and "Musterweg 1" in text and "Erika Beispiel (Vorsitz)" in text
    assert "Amtsgericht Musterstadt, Registernummer VR 12345" in text and "Angaben gemäß § 18 Abs. 1 MStV" in text
    assert "§ 5 DDG" not in text and "/api/v1/net/operator" in text
    assert "kontakt@example.org" in text and "https://example.org/kontakt" in text
    for absent in ("Umsatzsteuer-Identifikationsnummer", "Aufsichtsbehörde", "Berufsrechtliche", "Liquidation",
                   "journalistisch"):
        assert absent not in text
    english = (await client.get("/imprint")).text
    assert "Represented by" in english and "register number VR 12345" in english


async def test_privacy_policy_is_complete_and_follows_the_configuration(client):
    from fluid.utils.legal import DATAFLOWS
    text = (await client.get("/privacy", headers={ "Accept-Language": "de" })).text
    assert "Datenschutzerklärung" in text and "datenschutz@example.org" in text
    assert text.count("<tr>") == len(DATAFLOWS) + 1
    assert "Art. 6 Abs. 1 lit. f DSGVO" in text and "Proxy-Protokolle: 7 Tage" in text and "Sicherungen: 14 Tage" in text
    assert "Die Landesbeauftragte für Datenschutz Musterland" in text and "außerhalb von EU/EWR bekannt" in text
    assert "§ 25 TDDDG" in text and "Art. 77 DSGVO" in text and "Art. 14 DSGVO" in text
    assert "den aufgerufenen Pfad" not in text and "deine IP-Adresse" not in text.split("Ihr eigenes Protokoll")[1][:200]
    assert "noch nicht bestätigt" not in text and "keine Datenschutzbeauftragte Person benannt" in text
    assert "Dein Widerspruchsrecht (Art. 21 DSGVO)" in text and "Betreibererklärungen von Mastern" in text
    assert "Vertreter in der Union" not in text
    english = (await client.get("/privacy")).text
    assert "Privacy policy" in english and "Art. 6(1)(f) GDPR" in english


def test_legal_validation_by_operator_form():
    from fluid.utils.legal import problems
    assert problems(VALID) == []
    company = copy.deepcopy(VALID)
    company["operator"].update(form="company")
    assert set(problems(company)) == { "LEGAL.operator.representatives", "LEGAL.operator.legal_form",
                                       "LEGAL.operator.register" }
    company["operator"].update(representatives=["A. Geschäftsführerin"], legal_form="GmbH",
                               register={ "court": "AG Ort", "number": "HRB 1" })
    assert problems(company) == ["LEGAL.operator.register"]
    company["operator"]["register"]["type"] = "HRB"
    assert problems(company) == []
    association = copy.deepcopy(VALID)
    association["operator"].update(form="association", representatives=["Vorstand"], registered=True)
    assert problems(association) == ["LEGAL.operator.register"]
    permit = copy.deepcopy(VALID)
    permit["operator"]["permit_required"] = True
    assert problems(permit) == ["LEGAL.operator.supervisory_authority"]
    basis = copy.deepcopy(VALID)
    del basis["privacy"]["legal_basis"]
    del basis["privacy"]["backups_days"]
    assert set(problems(basis)) == { "LEGAL.privacy.legal_basis", "LEGAL.privacy.backups_days" }
    assert problems({}) == ["LEGAL.operator"]


def test_conditional_fields_are_required_only_when_their_condition_applies():
    from fluid.utils.legal import problems, provisions, public_imprint
    unknown = copy.deepcopy(VALID)
    for key in ("country", "commercial"): del unknown["operator"][key]
    del unknown["privacy"]["dpo"]
    del unknown["privacy"]["transfers"]
    assert set(problems(unknown)) == { "LEGAL.operator.country", "LEGAL.operator.commercial", "LEGAL.privacy.dpo",
                                       "LEGAL.privacy.transfers" }
    officer = copy.deepcopy(VALID)
    officer["privacy"]["dpo"] = { "name": "D. Schutz" }
    assert problems(officer) == ["LEGAL.privacy.dpo"]
    officer["privacy"]["dpo"]["email"] = "dsb@example.org"
    assert problems(officer) == []
    abroad = copy.deepcopy(VALID)
    abroad["operator"]["country"] = "CH"
    assert problems(abroad) == ["LEGAL.privacy.representative"]
    abroad["privacy"]["representative_exempt"] = True
    assert problems(abroad) == []
    press = copy.deepcopy(VALID)
    press["operator"]["journalistic"] = True
    assert problems(press) == ["LEGAL.operator.editorial"]
    press["operator"]["editorial"] = { "name": "R. Edakteur", "address": ["Weg 2", "12345 Ort"] }
    assert problems(press) == []
    assert provisions(VALID["operator"]) == ["§ 18 Abs. 1 MStV"]
    assert provisions(dict(VALID["operator"], commercial=True)) == ["§ 5 DDG", "§ 18 Abs. 1 MStV"]
    assert provisions(press["operator"]) == ["§ 18 Abs. 1 MStV", "§ 18 Abs. 2 MStV"]
    assert public_imprint({ "LEGAL": VALID })["supervisory_authority"] is None
    assert set(public_imprint({ "LEGAL": VALID })) == { "name", "form", "legal_form", "address", "country", "email",
                                                        "phone", "contact_form", "representatives", "register",
                                                        "vat_id", "economic_id", "capital", "outstanding",
                                                        "supervisory_authority", "profession", "in_liquidation",
                                                        "editorial", "provisions" }


def test_declared_operator_carries_only_the_assignment_fields():
    from fluid.utils.legal import declared_operator, public_imprint
    company = copy.deepcopy(VALID)
    company["operator"].update(form="company", legal_form="GmbH", representatives=["A. Geschäftsführerin"],
                               register={ "court": "Amtsgericht Ort", "type": "HRB", "number": "1" },
                               vat_id="DE123456789", phone="+49 0", commercial=True)
    operator = declared_operator(public_imprint({ "LEGAL": company }))
    assert set(operator) == { "name", "form", "country", "ids" }
    assert operator["ids"] == [{ "scheme": "register", "country": "DE", "authority": "Amtsgericht Ort", "type": "HRB",
                                 "number": "1" }, { "scheme": "vat", "number": "DE123456789" }]
    assert "Weg 1" not in str(operator) and "erika@example.org" not in str(operator) and "+49" not in str(operator)


def test_production_refuses_incomplete_operator_information():
    from fluid.exceptions import ConfigurationError
    from fluid.utils.legal import validate
    with pytest.raises(ConfigurationError) as caught:
        validate({ "LEGAL": { "operator": { "name": "X" } } }, False)
    assert caught.value.code == "INCOMPLETE" and "LEGAL.operator.email" in str(caught.value)
    assert "LEGAL.privacy" in validate({ "LEGAL": { "operator": VALID["operator"] } }, True)
    assert validate({ "LEGAL": VALID }, False) == []
