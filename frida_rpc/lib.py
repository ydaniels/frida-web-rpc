import time
import base64
import binascii
import logging
from .system import BaseOS

logging.getLogger(__name__).addHandler(logging.NullHandler())


class InvalidDataException(Exception):
    pass


class CommandException(Exception):
    pass


class Command:
    """
    Implements a command interface for frida to the flask app .
    """
    ERROR = {'process_not_found': 'Please make sure process is running',
             'supply_process': 'Please supply process in command ', 'supply_script':
                 'Please supply script to process', 'app_not_whitelist': 'App not included in whiteliste contact admin',
             'app_not_installed': ' APP is not installed please contact admin',
             'unable_to_start_app': 'Unable to start app please check logs if error persist',
             'method_not_present': 'Method name must present', 'args_not_present': 'Args   must present'
             }

    def __init__(self, command_data, whitelist=None):
        """command_data = {'process':'com.google.chrome', 'script': 'javascript base64 code',
         'method_name':doCommand, 'args':[]}"""
        self.command_data = command_data
        self.system = BaseOS(command_data.get('process'), frida_location=command_data.get('frida_location'))
        self.WHITELIST_APP = whitelist or []
        self.app_args = self.command_data.get('args')
        self.process = self.command_data.get('process')
        self.method_name = self.command_data.get('method_name')
        self.script = self.command_data.get('script')

    def validate_data(self):

        data = {'success': False}
        if not self.command_data.get('process'):
            data['error'] = self.ERROR['supply_process']

        elif self.command_data.get('process') not in self.WHITELIST_APP:
            logging.critical(
                'Gotten process {} from command  which is not in whitelist '.format(self.command_data.get('process')))
            data['error'] = self.ERROR['app_not_whitelist']

        elif not self.command_data.get('script'):
            data['error'] = self.ERROR['supply_script']

        elif not self.command_data.get('method_name'):

            data['error'] = self.ERROR['method_not_present']

        elif not self.command_data.get('args'):

            data['error'] = self.ERROR['args_not_present']
        if data.get('error'):
            raise InvalidDataException(data)

        try:

            self.script = base64.b64decode(self.script, validate=True)
        except binascii.Error as e:
            logging.warning('An error occured while decoding script : {}'.format(str(e)))

    def run_command(self):
        data = {'success': False}
        process = self.command_data['process']
        logging.info('Gotten process {} from command '.format(process))
        logging.info('Check process {} is istalled '.format(process))
        if not self.system.is_app_installed:
            data['error'] = self.ERROR['app_not_installed']
            raise CommandException(data)
        logging.info('Check if process {} is running currently '.format(process))
        if not self.system.is_app_running:
            logging.warning('Process {} is not running '.format(process))
            logging.info('Spawning process {}  '.format(process))
            spawned = self.system.spawn()
            time.sleep(1)
            if spawned and self.system.is_app_running:
                logging.info('Successfully spawned process {}  and process is running '.format(process))

                return self.do_main_script()
            else:
                data['error'] = self.ERROR['unable_to_start_app']
                raise CommandException(data)
        else:
            logging.info('Process {} is running already '.format(process))
            return self.do_main_script()

    def do_main_script(self):
        result = self.system.run_rpc(self.process, self.script, self.method_name, self.app_args)
        if result == 'NOT_RUNNING':
            raise CommandException({'success': False, 'error': 'unable to connect to server please start frida'})
        return result
