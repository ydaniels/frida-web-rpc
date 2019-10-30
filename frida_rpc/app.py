from flask import Flask


def create_app(config_file=None):
    """Factory to create the Flask application
    :param config_file: A python file or dict from which to load the config.
                        If omitted, the config file must be set using
                        the ``FRIDA_RPC_CONFIG`` environment variable.
                        If set, the environment variable is ignored
    :return: A `Flask` application instance
    """
    from .routes import frida_rpc_bp
    app = Flask('frida_rpc')
    _load_config(app, config_file)
    app.register_blueprint(frida_rpc_bp)
    return app


def _load_config(app, config_file):
    app.config.from_pyfile('defaults.cfg')
    if isinstance(config_file, dict):
        app.config.update(config_file)
    elif config_file:
        app.config.from_pyfile(config_file)
    else:
        app.config.from_envvar('FRIDA_RPC_CONFIG')
