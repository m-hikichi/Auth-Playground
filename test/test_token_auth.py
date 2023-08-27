import pytest
import requests
from requests.auth import HTTPBasicAuth
import json


@pytest.fixture()
def access_token():
    url = "http://dev:5000/login"

    response = requests.post(
        url,
        data={
            "grant_type": "password",
            "username": "admin",
            "password": "admin",
        }
    )

    response_dict = json.loads(response.text)
    access_token = response_dict["access_token"]
    return access_token


def test_authenticate_valid_user(access_token):
    # GIVEN
    url = "http://dev:5000/protected"
    headers = {
        "Authorization": f"Bearer {access_token}"
    }

    # WHEN
    response = requests.get(
        url,
        headers=headers,
    )

    # THEN
    assert response.status_code == 200
