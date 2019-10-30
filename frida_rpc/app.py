import json
from flask import Flask, request, jsonify, abort
from frida_rpc.lib import Command, InvalidDataException, CommandException

app = Flask('frida_rpc')


@app.route('/rpc', methods=['GET', 'POST'])
def rpc_command():
    """run command on app request in format {'process':'process_name', 'script': base64=.script}"""
    request_json = request.get_json()
    app_debug = app.config.get('debug')
    app_token = app.config.get('token')
    req_token = request.values.get('token')

    if (not app_debug and not req_token) or (not app_debug and app_token != req_token):
        abort(405, 'You must supply token when not in debug')

    white_list = app.config.get('WHITELIST_APP', [])

    if request.values:
        c = Command(dict(request.values), whitelist=white_list)
    elif request_json:
        c = Command(json.loads(request_json))
    else:
        return abort(405)

    try:
        data = {'success': True}
        c.validate_data()
        message = c.run_command()
        data['result'] = message
        return jsonify(data)
    except InvalidDataException as e:
        return jsonify(e.args[0])
    except CommandException as e:
        return jsonify(e.args[0])


def start_app(host='127.0.0.1', port=5000, debug=True, use_reloader=False, whitelist=None, token=None):
    app.config['WHITELIST_APP'] = whitelist or []
    app.config['token'] = token
    app.run(host=host, port=port, debug=debug, use_reloader=use_reloader)


if __name__ == '__main__':
    start_app()
