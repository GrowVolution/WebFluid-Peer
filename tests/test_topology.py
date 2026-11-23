import pytest


def resolve(**config):
    from fluid.utils.topology import resolve as run
    return run(config)


def test_default_peer_joins_the_default_master():
    from fluid.config import DEFAULT_MASTER
    topology = resolve(JOIN_MASTER=DEFAULT_MASTER)
    assert (topology.role, topology.primary, topology.upstream) == ("peer", False, "https://peers.webfluid.dev")
    assert resolve().upstream == "https://peers.webfluid.dev"


def test_is_master_alone_is_a_secondary_of_the_default():
    topology = resolve(IS_MASTER=True, PEERING_PUBLIC_URL="https://m2.example.org")
    assert topology.label == "secondary" and topology.upstream == "https://peers.webfluid.dev"


def test_explicit_none_founds_only_on_a_master():
    from fluid.exceptions import ConfigurationError
    assert resolve(IS_MASTER=True, JOIN_MASTER=None, PEERING_PUBLIC_URL="https://m.example.org").label == "primary"
    for value in (None, "", "   "):
        with pytest.raises(ConfigurationError) as caught:
            resolve(JOIN_MASTER=value)
        assert caught.value.code == "MISSING" and caught.value.key == "JOIN_MASTER"


@pytest.mark.parametrize("value,code", [
    ("http://master.example.org", "HTTPS_REQUIRED"),
    ("https://master.example.org/path", "ORIGIN_ONLY"),
    ("https://user:pw@master.example.org", "CREDENTIALS_NOT_ALLOWED"),
    ("https://localhost", "INTERNAL_HOST"),
    (42, "INVALID_URL")
])
def test_invalid_master_urls_fail_clearly(value, code):
    from fluid.exceptions import ConfigurationError
    with pytest.raises(ConfigurationError) as caught:
        resolve(JOIN_MASTER=value)
    assert caught.value.code == code


def test_local_development_allows_insecure_targets():
    topology = resolve(JOIN_MASTER="http://127.0.0.1:8571", PEERING_ALLOW_INSECURE=True)
    assert topology.upstream == "http://127.0.0.1:8571"


def test_a_master_cannot_join_itself_and_needs_a_public_url():
    from fluid.exceptions import ConfigurationError
    with pytest.raises(ConfigurationError) as caught:
        resolve(IS_MASTER=True, JOIN_MASTER="https://m.example.org", PEERING_PUBLIC_URL="https://m.example.org/")
    assert caught.value.code == "SELF_JOIN"
    with pytest.raises(ConfigurationError) as caught:
        resolve(IS_MASTER=True, JOIN_MASTER=None, BASE_URL="http://localhost:8000")
    assert caught.value.key == "PEERING_PUBLIC_URL"
