import json
from flask import current_app, Blueprint
from flask import request, jsonify, abort
from frida_rpc.lib import Command, InvalidDataException, CommandException

frida_rpc_bp = Blueprint('frida_rpc_bp', __name__)


@frida_rpc_bp.route('/rpc', methods=['GET', 'POST'])
def rpc_command():
    """run command on app request in format {'process':'process_name', 'script': base64=.script}"""
    request_json = request.get_json()
    app_debug = current_app.config.get('DEBUG')
    app_token = current_app.config.get('SECRET_KEY')
    req_token = request.values.get('SECRET_KEY')

    if (not app_debug and not req_token) or (not app_debug and app_token != req_token):
        abort(405, 'You must supply SECRET_KEY when not in debug')

    white_list = current_app.config.get('WHITE_LIST_APP', [])

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
