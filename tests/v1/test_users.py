"""Tests for /api/v1/account/* endpoints."""
from tests.conftest import db_get_user, do_register

ROLE_URL = "/api/v1/account/role"


class TestAccountRole:
    def test_returns_first_role(self, client):
        do_register(client)
        resp = client.get(ROLE_URL)
        assert resp.status_code == 200
        # registration assigns customer-admin by default
        assert resp.json()["message"] == "customer-admin"

    def test_unauthenticated(self, client):
        resp = client.get(ROLE_URL)
        assert resp.status_code == 401

    def test_user_with_no_roles_returns_empty(self, client, db):
        do_register(client)
        user = db_get_user(db)
        user.roles.clear()
        db.commit()
        resp = client.get(ROLE_URL)
        assert resp.status_code == 200
        assert resp.json()["message"] == ""
