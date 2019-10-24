# coding: utf-8

from __future__ import absolute_import




#
# def test_create_scan(client):
#     """Test case for create_scan
#
#     Create scan
#     """
#     body = ScanModel()
#     response = client.open(
#         '/v1/scan',
#         method='POST',
#         data=json.dumps(body),
#         content_type='application/json')
#     assert response.status_code == 200

def test_get_scan(client, mocker):
    """Test case for get_scan

    Get user by id
    """
    get_scan_mocked = mocker.patch('qg_api.api.get_scan')
    get_scan_mocked.return_value = 'tttttttttttEEEEEEEEEEEEE'
    response =client.open(
        '/v1/scan/{scan_id}'.format(scan_id=789),
        method='GET')
    assert response == 200


