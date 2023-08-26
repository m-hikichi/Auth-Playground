import pytest
import requests
from requests.auth import HTTPBasicAuth
import json


def test_public_page():
    # GIVEN
    url = "http://dev:5000/public"

    # WHEN
    response = requests.get(url)

    # THEN
    response_dict = json.loads(response.text)
    response_message = response_dict["message"]
    assert response.status_code == 200
    assert response_message == "Welcome to public page! This page is open to everyone."


@pytest.mark.parametrize(
    "username, password",
    [
        ("admin", "admin"),
    ]
)
def test_authenticate_valid_user(username, password):
    # GIVEN
    url = "http://dev:5000/protected"

    # WHEN
    response = requests.get(
        url,
        auth=HTTPBasicAuth(username, password),
    )

    # THEN
    response_dict = json.loads(response.text)
    response_message = response_dict["message"]
    assert response.status_code == 200
    assert response_message == "Welcome to protected page! This page is only available to authenticated users."


@pytest.mark.parametrize(
    "username, password",
    [
        ("Admin", "admin"),
        ("admin", "Admin"),
        ("admin", ""),
        ("", "admin"),
    ]
)
def test_authenticate_invalid_user(username, password):
    # GIVEN
    url = "http://dev:5000/protected"

    # WHEN
    response = requests.get(
        url,
        auth=HTTPBasicAuth(username, password),
    )

    # THEN
    response_dict = json.loads(response.text)
    response_message = response_dict["detail"]
    assert response.status_code == 401
    assert response_message == "Incorrect username or password."

