import logging
import frida
from .util import FridaServer

logging.getLogger(__name__).addHandler(logging.NullHandler())


class BaseOS:
    """This class abstracts some os and frida functions for getting informations about processes
     You can overide this class to implement custom and specified os functions"""

    def __init__(self, process, device='local', frida_location=None):

        self.process = process
        self.device = device
        self.frida = FridaServer(device_type=device, frida_location=frida_location)
        try:
            self.frida.get_processes()
        except frida.ServerNotRunningError:
            logging.critical('Server is not running try and start again')
            ret = self.frida.start_frida()
            if ret != 0:
                logging.error('Cannot start frida server  ')

    def spawn(self):
        self.frida_spawn()
        return True

    def frida_spawn(self):
        try:
            self.frida.frida_spawn(self.process)
        except frida.ExecutableNotFoundError:
            return False
        return True

    @property
    def is_app_installed(self):
        return True

    @property
    def is_app_running(self):
        processes = self.frida.get_processes()
        for process in processes:

            if process.name == self.process or process.pid == self.process:
                return True
        return False

    def run_rpc(self, *args):
        return self.frida.load_script(*args)
