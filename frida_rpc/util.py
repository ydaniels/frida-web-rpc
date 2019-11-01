from ast import literal_eval as make_tuple
import frida

from .exceptions import CommandException


class FridaServer:
    default_location = '/data/local/tmp/system_server'

    def __init__(self, device_type , frida_location=None):
        device_type = device_type or 'local'
        self.device = frida.get_device(device_type)
        self.frida_location = frida_location or self.default_location

    @staticmethod
    def start_frida():
        # p = subprocess.Popen(['su'], shell=False)
        # p.wait()
        # p = subprocess.Popen([self.frida_location, '&'], shell=False)
        # ret = p.wait()
        return True

    def get_processes(self):
        processes = self.device.enumerate_processes()

        return processes

    def get_apps(self):
        return self.device.enumerate_applications()

    def frida_spawn(self, process):
        pid = self.device.spawn([process])
        self.device.resume(pid)
        return pid

    def load_script(self, process, script, method_name, args):
        try:

            session = self.device.attach(process)
        except frida.ServerNotRunningError as e:
            raise  CommandException({'success': False, 'error': str(e)})
        except frida.ProcessNotFoundError as e:
            raise CommandException({'success': False, 'error': str(e)})
        except frida.PermissionDeniedError as e:
            raise CommandException({'success': False, 'error': str(e)})

        try:
            source = """rpc.exports = """ + script.decode() + """;"""
        except (UnicodeDecodeError, AttributeError):
            source = """rpc.exports = """ + script + """;"""

        try:
            script = session.create_script(source)
        except frida.InvalidArgumentError as e:
            raise CommandException({'success': False, 'error': str(e), 'script': source})

        script.load()
        f_method = getattr(script.exports, method_name)
        try:
            result = f_method(*make_tuple(args))
            return result
        except frida.core.RPCException as e:
            raise CommandException({'success': False, 'error': str(e), 'script': source})
