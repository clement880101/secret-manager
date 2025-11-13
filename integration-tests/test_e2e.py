import os, requests

API_URL = os.environ.get("API_URL", "http://localhost:8000")

def login_mock(user_id):
    r = requests.post(f"{API_URL}/auth/mock", params={"user_id": user_id}); r.raise_for_status()
    return r.json()["access_token"]

def test_rbac_flow():
    owner_tok = login_mock("owner@example.com")
    r = requests.post(f"{API_URL}/secrets", json={"key":"db_pass","value":"s3cr3t"}, headers={"Authorization": f"Bearer {owner_tok}"})
    assert r.status_code in (200, 409)

    # Owner can read
    r = requests.get(f"{API_URL}/secrets/db_pass", headers={"Authorization": f"Bearer {owner_tok}"})
    assert r.status_code == 200

    # Other user cannot read yet
    user_tok = login_mock("user@example.com")
    r = requests.get(f"{API_URL}/secrets/db_pass", headers={"Authorization": f"Bearer {user_tok}"})
    assert r.status_code == 403

    # Share
    r = requests.post(f"{API_URL}/secrets/db_pass/share", json={"user_id":"user@example.com","can_write": True}, headers={"Authorization": f"Bearer {owner_tok}"})
    assert r.status_code == 200

    # Now user can read
    r = requests.get(f"{API_URL}/secrets/db_pass", headers={"Authorization": f"Bearer {user_tok}"})
    assert r.status_code == 200

    # List
    r = requests.get(f"{API_URL}/secrets", headers={"Authorization": f"Bearer {user_tok}"}); r.raise_for_status()
    keys = [it["key"] for it in r.json()["items"]]
    assert "db_pass" in keys
