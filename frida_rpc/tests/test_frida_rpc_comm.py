import base64
import unittest
import multiprocessing
import time
from frida_rpc.lib import Command, CommandException, InvalidDataException


class TestWebRPCCommand(unittest.TestCase):

    def setUp(self):
        self.p = multiprocessing.Process(target=time.sleep, args=(60,))
        self.p.start()

        program = self.p.pid
        self.white_list = [program]
        self.data = {'method_name': 'add', 'process': program,
                     'script': """{
                            add: function (a, b) {
                                        return a + b;
                                    }
                         };""", 'args': '[2,4]'}

        self.result = 6

    def tearDown(self):
        self.p.terminate()

    def test_command_fail_exception(self):
        """Command """
        c = Command(self.data, whitelist=[])
        self.assertRaises(InvalidDataException, c.validate_data)

    def test_command_fail_no_process(self):
        """Command failed no process supplied"""
        c_data = self.data.copy()
        del c_data['process']
        try:
            c = Command(c_data, whitelist=[])
            c.validate_data()
        except InvalidDataException as e:
            return_data = e.args[0]
            self.assertFalse(return_data['success'])
            self.assertIn('error', return_data)
            self.assertEqual(return_data['error'], Command.ERROR['supply_process'])

    def test_command_fail_no_script(self):
        """Command failed no script supplied"""
        c_data = self.data.copy()
        del c_data['script']
        try:
            c = Command(c_data, whitelist=self.white_list)
            c.validate_data()
        except InvalidDataException as e:
            return_data = e.args[0]
            self.assertFalse(return_data['success'])
            self.assertIn('error', return_data)
            self.assertEqual(return_data['error'], Command.ERROR['supply_script'])

    def test_command_fail_no_method(self):
        """Command failed no method supplied"""
        c_data = self.data.copy()
        del c_data['method_name']
        try:
            c = Command(c_data, whitelist=self.white_list)
            c.validate_data()
        except InvalidDataException as e:
            return_data = e.args[0]
            self.assertFalse(return_data['success'])
            self.assertIn('error', return_data)
            self.assertEqual(return_data['error'], Command.ERROR['method_not_present'])

    def test_command_fail_no_args(self):
        """Command failed no args supplied"""
        c_data = self.data.copy()
        del c_data['args']
        try:
            c = Command(c_data, whitelist=self.white_list)
            c.validate_data()
        except InvalidDataException as e:
            return_data = e.args[0]
            self.assertFalse(return_data['success'])
            self.assertIn('error', return_data)
            self.assertEqual(return_data['error'], Command.ERROR['args_not_present'])

    def test_command_fail_no_such_process(self):
        """Command failed process does not exist supplied"""
        c_data = self.data.copy()
        c_data['process'] = 'invalid_process'
        try:
            c = Command(c_data, whitelist=['invalid_process'])
            c.validate_data()
            c.run_command()

        except CommandException as e:

            return_data = e.args[0]
            self.assertFalse(return_data['success'])
            self.assertIn('error', return_data)
            self.assertEqual(return_data['error'], Command.ERROR['unable_to_start_app'])

    def test_command_good_script(self):
        """Command failed process does not exist supplied"""
        c_data = self.data.copy()
        c = Command(c_data, whitelist=self.white_list)
        c.validate_data()
        result = c.run_command()
        self.assertEqual(result, self.result)

    def test_command_invalid_script(self):
        """Command failed process does not exist supplied"""
        c_data = self.data.copy()
        c_data['script'] = 'Invalid script'
        c = Command(c_data, whitelist=self.white_list)
        c.validate_data()
        self.assertRaises(CommandException, c.run_command)

    def test_command_good_bs64_script(self):
        """Command failed process does not exist supplied"""
        c_data = self.data.copy()
        c_data['script'] = base64.b64encode(bytes(c_data['script'], encoding='utf8'))
        c = Command(c_data, whitelist=self.white_list)
        c.validate_data()
        result = c.run_command()
        self.assertEqual(result, self.result)


if __name__ == '__main__':
    unittest.main()
