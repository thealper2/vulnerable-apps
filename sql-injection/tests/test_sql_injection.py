import pytest

from app import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_insecure_endpoint(client):
    """Test that insecure endpoint is vulnerable to SQL injection"""
    # Legitimate login
    response = client.post('/insecure/login_string_format', json={
        'username': 'admin',
        'password': 'securepassword123'
    })
    assert response.status_code == 200
    assert response.json['status'] == 'success'
    
    # SQL injection attack
    response = client.post('/insecure/login_string_format', json={
        'username': "admin' --",
        'password': ''
    })
    assert response.status_code == 200
    assert response.json['status'] == 'success'  # This should NOT be success in a secure endpoint

def test_secure_endpoint(client):
    """Test that secure endpoint blocks SQL injection"""
    # Legitimate login
    response = client.post('/secure/login_parameterized', json={
        'username': 'admin',
        'password': 'securepassword123'
    })
    assert response.status_code == 200
    assert response.json['status'] == 'success'
    
    # SQL injection attempt
    response = client.post('/secure/login_parameterized', json={
        'username': "admin' --",
        'password': ''
    })
    assert response.status_code == 200
    assert response.json['status'] == 'error'  # Should be error for injection attempt

def test_waf_protection(client):
    """Test that WAF blocks obvious SQL injection attempts"""
    response = client.post('/secure/login_combined', json={
        'username': "admin' UNION SELECT * FROM users --",
        'password': ''
    })
    assert response.status_code == 403
    assert 'Potential SQL injection detected' in response.json['message']