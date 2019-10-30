import json
import unittest
from frida_rpc.app import app
from frida_rpc.lib import Command


class TestRPCApp(unittest.TestCase):

    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['WHITELIST_APP'] = []
        app.config['debug'] = False
        app.config['token'] = None
        self.data = {'method_name': 'add', 'process': 'python', 'script': 'null', 'args': '[]'}

        self.app = app.test_client()
        self.assertEqual(app.debug, False)

    @staticmethod
    def set_debug():
        app.config['debug'] = True

    def tearDown(self):
        pass

    def test_app_fail_no_debug_no_token(self):
        """Do not allow request if not in debug mode and token not supplied in request"""
        response = self.app.get('/rpc', data=self.data)
        self.assertEqual(response.status_code, 405)

    def test_fail_app_no_debug_wrong_token(self):
        """Do not allow request if not in debug and token supplied is wrong from app config token"""
        app.config['token'] = 'RIGHT_TOKEN'
        local_data = self.data.copy()
        local_data['token'] = 'WRONG_TOKEN'
        response = self.app.get('/rpc', data=local_data)
        self.assertEqual(response.status_code, 405)

    def test_pass_app_no_debug_right_token(self):
        """Allow request if token is supplied and correct and app not in debug"""
        app.config['token'] = 'RIGHT_TOKEN'
        local_data = self.data.copy()
        local_data['token'] = 'RIGHT_TOKEN'
        response = self.app.get('/rpc', data=local_data)
        self.assertEqual(response.status_code, 200)

    def test_pass_app_debug_no_token(self):
        """Allow request to pass if set debug is on"""
        self.set_debug()
        response = self.app.get('/rpc', data=self.data)
        self.assertEqual(response.status_code, 200)

    def test_fail_app_not_whitelist(self):
        """Do not process app not in whitelist"""
        self.set_debug()
        response = self.app.get('/rpc', data=self.data)
        data = json.loads(response.data)
        self.assertFalse(data['success'])
        self.assertIn('error', data)
        self.assertEqual(data['error'], Command.ERROR['app_not_whitelist'])

    def test_allow_app_in_whitelist(self):
        """ Allow to process app in whitelist """
        self.set_debug()
        app.config['WHITELIST_APP'] = ['python']
        response = self.app.get('/rpc', data=self.data)
        data = json.loads(response.data)
        self.assertNotEqual(data['error'], Command.ERROR['app_not_whitelist'])


if __name__ == '__main__':
    unittest.main()
