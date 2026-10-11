"""Authentication tests for the Bankism web console and API."""

import pytest

from app import app, hash_password, verify_password

TEST_USERNAME = "tester"
TEST_PASSWORD = "correct horse battery staple"


def _csrf(client):
    """Prime a session CSRF token and return it."""
    client.get("/login")
    with client.session_transaction() as sess:
        return sess.get("csrf_token")


@pytest.fixture
def anon_client(monkeypatch):
    """Create an unauthenticated Flask test client with valid credentials configured."""
    monkeypatch.setenv("BANKISM_USERNAME", TEST_USERNAME)
    monkeypatch.setenv("BANKISM_PASSWORD_HASH", hash_password(TEST_PASSWORD))
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_password_hash_roundtrip():
    """Hashed passwords verify correctly and reject wrong input."""
    stored = hash_password("s3cret!")
    assert stored.startswith("pbkdf2_sha256$")
    assert verify_password("s3cret!", stored)
    assert not verify_password("wrong", stored)
    assert not verify_password("s3cret!", "not-a-valid-hash")


def test_health_is_public(anon_client):
    """The health endpoint stays reachable without authentication."""
    assert anon_client.get("/health").status_code == 200


def test_login_page_reachable(anon_client):
    """The login page is served to anonymous users."""
    assert anon_client.get("/login").status_code == 200


def test_index_redirects_when_anonymous(anon_client):
    """The console page redirects anonymous users to the login page."""
    response = anon_client.get("/")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_static_console_shell_protected(anon_client):
    """The console shell cannot be fetched directly as a static file."""
    response = anon_client.get("/static/index.html")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_evaluate_requires_auth(anon_client):
    """The evaluate API returns 401 JSON when unauthenticated."""
    response = anon_client.post("/evaluate", json={"message": "What's my balance?"})
    assert response.status_code == 401
    assert response.get_json()["error"] == "Authentication required"


def test_login_rejects_wrong_password(anon_client):
    """A wrong password is rejected and no session is granted."""
    token = _csrf(anon_client)
    response = anon_client.post(
        "/login",
        data={"username": TEST_USERNAME, "password": "wrong", "csrf_token": token},
    )
    assert response.status_code == 401
    assert anon_client.post("/evaluate", json={"message": "hi"}).status_code == 401


def test_login_rejects_missing_csrf(anon_client):
    """A login attempt without a CSRF token is refused."""
    response = anon_client.post(
        "/login", data={"username": TEST_USERNAME, "password": TEST_PASSWORD}
    )
    assert response.status_code == 400


def test_login_then_access_granted(anon_client):
    """Valid credentials establish a session and unlock the console."""
    token = _csrf(anon_client)
    response = anon_client.post(
        "/login",
        data={"username": TEST_USERNAME, "password": TEST_PASSWORD, "csrf_token": token},
    )
    assert response.status_code == 302
    assert anon_client.get("/").status_code == 200


def test_logout_clears_session(anon_client):
    """Logging out revokes API access."""
    token = _csrf(anon_client)
    anon_client.post(
        "/login",
        data={"username": TEST_USERNAME, "password": TEST_PASSWORD, "csrf_token": token},
    )
    assert anon_client.get("/").status_code == 200
    anon_client.get("/logout")
    assert anon_client.post("/evaluate", json={"message": "hi"}).status_code == 401


def test_login_fails_closed_without_configured_credentials(monkeypatch):
    """With no credentials configured, no login is possible (fail closed)."""
    monkeypatch.delenv("BANKISM_USERNAME", raising=False)
    monkeypatch.delenv("BANKISM_PASSWORD_HASH", raising=False)
    app.config["TESTING"] = True
    with app.test_client() as client:
        token = _csrf(client)
        response = client.post(
            "/login",
            data={"username": "admin", "password": "admin", "csrf_token": token},
        )
        assert response.status_code == 401
