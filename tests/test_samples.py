import sys
from os import path, listdir
from os.path import isfile, join
sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))
from thunderstormAPI.thunderstorm import ThunderstormAPI

#PROGRAM_DIR = path.dirname(path.dirname(path.abspath(__file__)))
PROGRAM_DIR = "."
THOR_THUNDERSTORM_HOST = '127.0.0.1'
THOR_THUNDERSTORM_PORT = '8080'
SAMPLE_1 = path.join(PROGRAM_DIR, 'samples/test-mimi.txt')
SAMPLE_DIR = path.join(PROGRAM_DIR, 'samples')
SAMPLES_1 = [path.join(SAMPLE_DIR, f) for f in listdir(SAMPLE_DIR) if isfile(join(SAMPLE_DIR, f))]
REACT_DIR = path.join(SAMPLE_DIR, 'react')
SAMPLES_2 = [path.join(REACT_DIR, f) for f in listdir(REACT_DIR) if isfile(join(REACT_DIR, f))]


def test_sample():
    """
    Tests the single sample submission
    :return:
    """
    t = ThunderstormAPI(host=THOR_THUNDERSTORM_HOST, port=THOR_THUNDERSTORM_PORT)
    status1 = t.get_status()
    result = t.scan(SAMPLE_1)
    status2 = t.get_status()
    assert result
    assert len(result) > 0
    assert int(status1['scanned_samples']) < int(status2['scanned_samples'])


def test_sample_multi_sync_1():
    """
    Tests the multi-threaded sample submission
    :return:
    """
    t = ThunderstormAPI(host=THOR_THUNDERSTORM_HOST, port=THOR_THUNDERSTORM_PORT)
    status1 = t.get_status()
    results = t.scan_multi(SAMPLES_1)
    status2 = t.get_status()
    assert results
    assert len(results) > 0
    assert int(status1['scanned_samples']) < int(status2['scanned_samples'])
    for r in results:
        assert r != {}


def test_sample_multi_sync_2():
    """
    Tests the multi-threaded sample submission
    :return:
    """
    t = ThunderstormAPI(host=THOR_THUNDERSTORM_HOST, port=THOR_THUNDERSTORM_PORT)
    status1 = t.get_status()
    results = t.scan_multi(SAMPLES_2)
    status2 = t.get_status()
    assert results
    assert len(results) > 0
    assert int(status1['scanned_samples']) < int(status2['scanned_samples'])
    for r in results:
        assert r != {}

