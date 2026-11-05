"""Project deployment routes; preserve unrelated user-configured servers."""
DEFAULT_ENDPOINTS=('http://10.205.103.120:10888','http://8.134.112.170:35981')


def current_endpoints(endpoints):
    # This project's old public port belonged to the replaced tunnel.
    return [DEFAULT_ENDPOINTS[1] if endpoint.rstrip('/')=='http://8.134.112.170:10888' else endpoint
            for endpoint in endpoints]
