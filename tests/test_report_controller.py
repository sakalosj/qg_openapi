# coding: utf-8

from __future__ import absolute_import

from flask import json
from six import BytesIO

#
#
# class TestReportController(BaseTestCase):
#     """ReportController integration test stubs"""
#
#     def test_create_report(self):
#         """Test case for create_report
#
#         Create report
#         """
#         body = Report()
#         response = self.client.open(
#             '/v1/report',
#             method='POST',
#             data=json.dumps(body),
#             content_type='application/json')
#         self.assert200(response,
#                        'Response body is : ' + response.data.decode('utf-8'))
#
#     def test_get_report(self):
#         """Test case for get_report
#
#         Get report by id
#         """
#         response = self.client.open(
#             '/v1/report/{reportId}'.format(report_id=789),
#             method='GET')
#         self.assert200(response,
#                        'Response body is : ' + response.data.decode('utf-8'))
#
#
# if __name__ == '__main__':
#     import unittest
#     unittest.main()
