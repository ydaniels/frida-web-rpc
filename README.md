
What is this ?
===============
This is a simple library to make frida rpc call over the internet. You can setup your reverse engineering environment
on another computer and perform a rpc call from your mobile phone or elsewhere over the internet.

Installation
==============
pip install frida_rpc

Running
========

 - export FLASK_APP=frida_rpc.app  FLASK_DEBUG=1 FRIDA_RPC_CONFIG=/path/to/your/config.cfg
 - For windows change export above to set
 - flask run


**Send request to http://your_ip:port/rpc  with request below**

    {'method_name': 'add', 'process': program,
                         'script': """{
                                add: function (a, b) {
                                            return a + b;
                                        }
    };""", 'args': '[2,4]'}

**Result**

    {'success': true, 'result': 6}
