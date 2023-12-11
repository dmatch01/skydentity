"""
Forwarding for SkyPilot requests.
"""
import json
import os
import subprocess
from collections import namedtuple
from functools import cache
from urllib.parse import urlparse

import requests
from flask import Flask, Response, request

from .constants import COMPUTE_API_ENDPOINT, CREDS_PATH, SERVICE_ACCOUNT_EMAIL_FILE
from .logging import get_logger, print_and_log

SkypilotRoute = namedtuple(
    "SkypilotRoute",
    [
        "methods",  # HTTP methods for the route
        "path",  # Flask rule for the route path
        "fields",  # fields in the routing rule
        "view_func",  # explicit view function to use; optional
    ],
    defaults=[None, None],  # defaults for "fields" and "view_func"
)


# list of all routes required; must be defined after `build_generic_forward`
ROUTES: list[SkypilotRoute] = [
    SkypilotRoute(
        methods=["GET"],
        path="/compute/v1/projects/<project>/global/images/family/<family>",
        fields=["project", "family"],
    ),
    SkypilotRoute(
        methods=["POST", "GET"],
        path="/compute/v1/projects/<project>/zones/<region>/instances",
        fields=["project", "region"],
    ),
    SkypilotRoute(
        methods=["GET"],
        path="/compute/v1/projects/<project>/regions/<region>",
        fields=["project", "region"],
    ),
    SkypilotRoute(
        methods=["GET"],
        path="/compute/v1/projects/<project>/aggregated/reservations",
        fields=["project"],
    ),
    SkypilotRoute(
        methods=["GET"],
        path="/compute/v1/projects/<project>",
        fields=["project"],
    ),
    SkypilotRoute(
        methods=["GET"],
        path="/compute/v1/projects/<project>/global/networks",
        fields=["project"],
    ),
    SkypilotRoute(
        methods=["GET"],
        path="/compute/v1/projects/<project>/global/networks/default/getEffectiveFirewalls",
        fields=["project"],
    ),
    SkypilotRoute(
        methods=["GET"],
        path="/compute/v1/projects/<project>/regions/<region>/subnetworks",
        fields=["project", "region"],
    ),
    SkypilotRoute(
        methods=["GET"],
        path="/compute/v1/projects/<project>/zones/<region>/operations/<operation>",
        fields=["project", "region", "operation"],
    ),
    SkypilotRoute(
        methods=["POST"],
        path="/compute/v1/projects/<project>/zones/<region>/instances/<instance>/setLabels",
        fields=["project", "region", "instance"],
    ),
    SkypilotRoute(
        methods=["POST"],
        path="/compute/v1/projects/<project>/zones/<region>/instances/<instance>/stop",
        fields=["project", "region", "instance"],
    ),
    SkypilotRoute(
        methods=["DELETE"],
        path="/compute/v1/projects/<project>/zones/<region>/instances/<instance>",
        fields=["project", "region", "instance"],
    ),
    SkypilotRoute(
        methods=["POST"],
        path="/compute/v1/projects/<project>/zones/<region>/instances/<instance>/start",
        fields=["project", "region", "instance"],
    ),
]


def generic_forward_request(request, log_dict=None):
    """
    [SkyPilot Integration]
    Forward a generic request to google APIs.
    """
    logger = get_logger()
    if log_dict is not None:
        log_str = f"PATH: {request.full_path}\n"
        for key, val in log_dict.items():
            log_str += f"\t{key}: {val}\n"
        print_and_log(logger, log_str.strip())

    new_url = get_new_url(request)
    new_headers = get_headers_with_auth(request)

    # don't modify the body in any way
    new_json = None
    if len(request.get_data()) > 0:
        new_json = request.json

    gcp_response = send_gcp_request(request, new_headers, new_url, new_json=new_json)
    return Response(gcp_response.content, gcp_response.status_code, new_headers)


def build_generic_forward(path: str, fields: list[str]):
    """
    Return the appropriate generic forward view function for the fields provided.

    The path is only used to create a unique and readable name for the anonymous function.
    """
    func = None
    if fields == ["project"]:
        func = lambda project: generic_forward_request(request, {"project": project})
    elif fields == ["project", "region"]:
        func = lambda project, region: generic_forward_request(
            request, {"project": project, "region": region}
        )
    elif fields == ["project", "family"]:
        func = lambda project, family: generic_forward_request(
            request, {"project": project, "family": family}
        )
    elif fields == ["project", "region", "operation"]:
        func = lambda project, region, operation: generic_forward_request(
            request, {"project": project, "region": region, "operation": operation}
        )
    elif fields == ["project", "region", "instance"]:
        func = lambda project, region, instance: generic_forward_request(
            request, {"project": project, "region": region, "instance": instance}
        )
    else:
        raise ValueError(
            f"Invalid list of variables to build generic forward for: {fields}"
        )

    # Flask expects all view functions to have unique names
    # (otherwise it complains about overriding view functions)
    func.__name__ = path

    return func


def setup_routes(app: Flask):
    """
    Set up all routes for SkyPilot forwarding.
    """
    for route in ROUTES:
        if route.view_func is not None:
            # use view_func if specified
            app.add_url_rule(
                route.path, view_func=route.view_func, methods=route.methods
            )
        elif route.fields is not None:
            # create a generic view function from the fields
            app.add_url_rule(
                route.path,
                view_func=build_generic_forward(route.path, route.fields),
                methods=route.methods,
            )
        else:
            raise ValueError(
                "Invalid route specification; missing either `view_func` or `fields`"
            )


@cache  # shouldn't change throughout the proxy lifespan
def get_service_account_email():
    """
    Retrieve the service account email from the
    """
    with open(
        SERVICE_ACCOUNT_EMAIL_FILE, "r", encoding="utf-8"
    ) as service_account_file:
        service_account_file_json = json.load(service_account_file)

    assert "email" in service_account_file_json.keys()
    return service_account_file_json["email"]


def get_gcp_creds():
    """
    Get GCP credentials from the specified credentials path.
    """
    cred_files = [
        f for f in os.listdir(CREDS_PATH) if os.path.isfile(os.path.join(CREDS_PATH, f))
    ]
    return os.path.join(CREDS_PATH, cred_files[0])


def get_json_with_service_account(request, service_account_email):
    """
    Modify the JSON of the request to include service account details.
    """
    json_dict = request.json
    service_account_dict = {
        "email": f"{service_account_email}",
        "scopes": [f"https://www.googleapis.com/auth/cloud-platform"],
    }
    new_dict = json_dict.copy()
    new_dict["serviceAccounts"] = [service_account_dict]
    return new_dict


@cache
def activate_service_account(credential_file):
    auth_command = f"gcloud auth activate-service-account --key-file={credential_file}"
    auth_process = subprocess.Popen(auth_command.split())
    auth_process.wait()


@cache
def get_service_account_auth_token():
    auth_token_command = "gcloud auth print-access-token"
    auth_token_process = subprocess.Popen(
        auth_token_command.split(), stdout=subprocess.PIPE
    )
    auth_token_process_out_bytes, _ = auth_token_process.communicate()

    return auth_token_process_out_bytes


def get_headers_with_auth(request):
    """
    Append authentication headers for a service account to the request.
    """
    # print_and_log(logger, "Entered get_headers_with_auth")
    ## Get authorization token and add to headers
    new_headers = {k: v for k, v in request.headers}  # if k.lower() == 'host'}

    # print_and_log(logger, f"ORIGINAL HEADERS: {new_headers}")
    parsed_compute_api_endpoint = urlparse(f"{COMPUTE_API_ENDPOINT}")
    hostname = parsed_compute_api_endpoint.netloc
    new_headers["Host"] = f"{hostname}"

    # Activate service account and get auth token
    service_acct_creds = get_gcp_creds()
    activate_service_account(service_acct_creds)

    auth_token_process_out_bytes = get_service_account_auth_token()

    auth_token = auth_token_process_out_bytes.strip().decode("utf-8")
    # print_and_log(logger, f"AUTH TOKEN: {auth_token}")
    new_headers["Authorization"] = f"Bearer {auth_token}"
    return new_headers


def get_new_url(request):
    """
    Redirect the URL (originally to the proxy) to the correct GCP endpoint.
    """
    new_url = request.url.replace(request.host_url, f"{COMPUTE_API_ENDPOINT}")
    logger = get_logger()
    print_and_log(logger, f"\tNew URL: {new_url}")
    return new_url


def send_gcp_request(request, new_headers, new_url, new_json=None):
    """
    Send a request to the GCP endpoint, with new headers, URL, and request body.
    """
    # If no JSON body, don't include a json body in proxied request
    if len(request.get_data()) == 0:
        return requests.request(
            method=request.method,
            url=new_url,
            headers=new_headers,
            cookies=request.cookies,
            allow_redirects=False,
        )
    return requests.request(
        method=request.method,
        url=new_url,
        headers=new_headers,
        json=new_json,
        cookies=request.cookies,
        allow_redirects=False,
    )