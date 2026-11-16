import sys
from os import path, getenv

import pytest

sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))
from thunderstormAPI.thunderstorm import ThunderstormAPI

THUNDERSTORM_HOST = getenv('THUNDERSTORM_HOST', '127.0.0.1')
THUNDERSTORM_PORT = getenv('THUNDERSTORM_PORT', '8080')


@pytest.fixture(scope='session', autouse=True)
def thunderstorm_running():
    """
    Abort the test run if the Thunderstorm service is not reachable, since some tests block otherwise
    """
    result = ThunderstormAPI(host=THUNDERSTORM_HOST, port=THUNDERSTORM_PORT).get_status()
    if 'status' in result:
        pytest.exit(f'Thunderstorm service at {THUNDERSTORM_HOST}:{THUNDERSTORM_PORT} is not running: {result["message"]}',
                    returncode=1)
