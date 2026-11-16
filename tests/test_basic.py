import sys
from os import path, getenv
sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))
from thunderstormAPI.thunderstorm import ThunderstormAPI

PROGRAM_DIR = path.dirname(path.dirname(path.abspath(__file__)))
THUNDERSTORM_HOST = getenv('THUNDERSTORM_HOST', '127.0.0.1')
THUNDERSTORM_PORT = getenv('THUNDERSTORM_PORT', '8080')

def test_status():
    """
    Tests the status response from the Thunderstorm servicess
    :return:
    """
    t = ThunderstormAPI(host=THUNDERSTORM_HOST, port=THUNDERSTORM_PORT)
    result = t.get_status()
    assert 'status' not in result
    assert result['scanned_samples'] >= 0
    # Uptime is only reported by THOR 10
    if 'uptime_seconds' in result:
        assert result['uptime_seconds'] > 0
        print(f'\nUptime: {result["uptime_seconds"]} seconds')


def test_info():
    """
    Tests the info response from the Thunderstorm service
    :return:
    """
    t = ThunderstormAPI(host=THUNDERSTORM_HOST, port=THUNDERSTORM_PORT)
    result = t.get_info()
    assert result
    if 'version_info' in result:  # THOR 11
        assert result['version_info']['thor']
        print(f"\nThor Version: {result['version_info']['thor']}")
        print(f"License Expiration Date: {result['license_expiration']}")
        print(f"Signature Version: {result['version_info']['signatures']}")
        print(f"Sigma Version: {result['version_info']['sigma']}")
    else:  # THOR 10
        assert result['thor_version']
        print(f"\nThor Version: {result['thor_version']}")
        print(f"License Expiration Date: {result['license_expiration_date']}")
        print(f"Signature Version: {result['signature_version']}")
        print(f"Sigma Version: {result['sigma_version']}")
    print(f"Threads: {result['threads']}")