import sys
from os import path, listdir, getenv
from os.path import isfile, join
sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))
from thunderstormAPI.thunderstorm import ThunderstormAPI

PROGRAM_DIR = path.dirname(path.dirname(path.abspath(__file__)))

THOR_THUNDERSTORM_HOST = getenv('THOR_THUNDERSTORM_HOST', '127.0.0.1')
THOR_THUNDERSTORM_PORT = getenv('THOR_THUNDERSTORM_PORT', '8080')

def test_status():
    """
    Tests the status response from the Thunderstorm servicess
    :return:
    """
    t = ThunderstormAPI(host=THOR_THUNDERSTORM_HOST, port=THOR_THUNDERSTORM_PORT)
    result = t.get_status()
    assert result['uptime_seconds'] > 0


def test_info():
    """
    Tests the info response from the Thunderstorm service
    :return:
    """
    t = ThunderstormAPI(host=THOR_THUNDERSTORM_HOST, port=THOR_THUNDERSTORM_PORT)
    result = t.get_info()
    assert result
    assert result['thor_version']
