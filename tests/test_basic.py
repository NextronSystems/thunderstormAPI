import sys
from os import path, listdir
from os.path import isfile, join
sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))

from thunderstormAPI.thunderstorm import ThunderstormAPI

PROGRAM_DIR = path.dirname(path.dirname(path.abspath(__file__)))
THOR_THUNDERSTORM_HOST = '127.0.0.1'
THOR_THUNDERSTORM_PORT = '8081'
SAMPLE_1 = path.join(PROGRAM_DIR, 'samples/test-mimi.txt')
SAMPLE_DIR = path.join(PROGRAM_DIR, 'samples')
SAMPLES = [path.join(SAMPLE_DIR, f) for f in listdir(SAMPLE_DIR) if isfile(join(SAMPLE_DIR, f))]


def test_status():
    """
    Tests the status response from the Thunderstorm servicess
    :return:
    """
    t = ThunderstormAPI(host=THOR_THUNDERSTORM_HOST, port=THOR_THUNDERSTORM_PORT)
    result = t.get_status()
    assert result['scanned_samples']


def test_info():
    """
    Tests the info response from the Thunderstorm service
    :return:
    """
    t = ThunderstormAPI(host='127.0.0.1', port='8081')
    result = t.get_info()
    assert result
    assert result['thor_version']


def test_sample():
    """
    Tests the single sample submission
    :return:
    """
    t = ThunderstormAPI(host='127.0.0.1', port='8081')
    status1 = t.get_status()
    filepath, result = t.scan(SAMPLE_1)
    status2 = t.get_status()
    assert result
    assert len(result) > 0
    assert int(status1['scanned_samples']) < int(status2['scanned_samples'])


def test_sample_multi():
    """
    Tests the multi-threaded sample submission
    :return:
    """
    t = ThunderstormAPI(host='127.0.0.1', port='8081')
    status1 = t.get_status()
    results = t.scan_multi(SAMPLES)
    status2 = t.get_status()
    assert results
    assert len(results) > 0
    assert int(status1['scanned_samples']) < int(status2['scanned_samples'])
    for r in results:
        filepath, result = r
        assert result != []
