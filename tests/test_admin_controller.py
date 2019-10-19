import pytest

def test_admin_action(client):
    """Test case for admin_action

    for admin actions
    """
    response = client.open(
        '/v1/admin/{action}'.format(action='test_action'),
        method='GET')
    print( 'Response body is : ' + response.data.decode('utf-8'))
    assert response.status_code == 200


