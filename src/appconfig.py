from config import config_from_env, config_from_yaml
from config.configuration_set import ConfigurationSet
import voluptuous as vol

CONFIG_SCHEMA = vol.Schema({
    vol.Required('input'): {
        vol.Required('imap'): {
            vol.Required('server'): str,
            vol.Optional('port', default=993): int,
            vol.Required('username'): str,
            vol.Required('password'): str,
            vol.Optional('folder', default='Inbox'): str,
            'filter': str,
            'post_action': {
                'flag': vol.In(['SEEN', 'ANSWERED', 'FLAGGED', 'UNFLAGGED', 'DELETED'])
            }
        }
    },
    'conversion': {
        'wkhtmltopdf': {
            'options': str
        }
    },
    vol.Required('output'): {
        vol.Exclusive('smtp', 'outputs'): {
            vol.Required('server'): str,
            vol.Optional('port', default=587): int,
            'username': str,
            'password': str,
            vol.Optional('encryption', default='STARTTLS'): vol.In(['NONE', 'SSL', 'STARTTLS']),
            vol.Required('sender'): str,
            vol.Required('destination'): str
        },
        vol.Exclusive('folder', 'outputs'): {
            vol.Required('destination'): vol.PathExists
        }
    },
    'logging': {
        'level': vol.In(['DEBUG', 'INFO', 'WARNING', 'ERROR']),
        'output_msg_on_error': bool
    }
})

def load_config():
    config = ConfigurationSet(
        config_from_env('EMAIL2PDF'),
        config_from_yaml('config.yaml', read_from_file=True)
    ).as_attrdict()

    return CONFIG_SCHEMA(config)
