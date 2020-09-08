#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# THOR Service API Client
# Florian Roth

import json
import requests
import platform
import traceback
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

from urllib.parse import urlparse

__version__ = "0.0.14"

API_CHECK_URI = '/api/check'
API_SUBMIT_URI_ASYNC = '/api/checkAsync'
API_CHECK_URI_ASYNC = '/api/getAsyncResults'
API_STATUS_URI = '/api/status'
API_INFO_URI = '/api/info'

urllib3.disable_warnings()


def scan_exception(request, exception):
    print("Error: {0}: {1}".format(request.url, exception))


class ThunderstormAPI(object):
    """
    THOR API Client Class
    """
    host = None
    port = None
    method = 'http'
    verify_ssl = False
    proxies = {}

    def __init__(self, host="127.0.0.1", port=8080, source=platform.uname()[1], use_ssl=False, verify_ssl=False):
        """
        Initializes the API client object
        :param source: source identifier (which is the hostname by default)
        :param host: host on which runs THOR Thunderstorm service
        :param port: port on which listens THOR Thunderstorm service
        :param use_ssl: use SSL for the transmission
        :param verify_ssl: verify the SSL/TLS server certificate
        """
        self.source = source
        self.host = host
        self.port = port
        self.verify_ssl = verify_ssl
        if use_ssl:
            self.method = 'https'

    def set_proxy(self, proxy, user="", pwd=""):
        """
        Set a proxy URL, user and password
        :param proxy: Proxy URL (e.g. https://proxy.local:8080)
        :param user: user name
        :param pwd: password
        :return:
        """
        u = urlparse(proxy)
        # Auth
        auth_string = ""
        if user:
            auth_string = "{1}:{2}@".format(user, pwd)
        # Set the proxy
        self.proxies = {u.scheme: '{0}://{1}{2}/'.format(
            u.scheme,
            auth_string,
            u.netloc
        )}

    def scan(self, filepath, asyn=False, trace=False):
        """
        Scan a certain file
        :param filelist: list of absolute file paths
        :param asyn: asynchronous mode, just submit, don't wait for scan result (server returns only a submission receipt)
        :param trace: more verbose than debug
        :return:
        """

        # Synchronous or Asynchronous mode
        api_endpoint = API_CHECK_URI
        if asyn:
            api_endpoint = API_SUBMIT_URI_ASYNC
        # Compose the URL
        url = "{}://{}:{}{}?source={}".format(self.method, self.host, self.port, api_endpoint, self.source)

        try:
            with open(filepath, 'rb') as f:
                headers = {'User-Agent': "THOR Thunderstorm API Client %s" % __version__}
                files = {"file": (filepath, f.read(), 'application/octet-stream')}
                try:
                    if trace:
                        print("SUBMIT > %s" % filepath)
                    resp = requests.post(url=url, headers=headers, files=files, proxies=self.proxies,
                                         verify=self.verify_ssl, stream=True)
                except Exception as e:
                    traceback.print_exc()
                    print(str(e))
                    return {'status': 'error', 'message': str(e), 'content': 'Cannot submit file'}

                # Warning
                if resp.status_code != 200:
                    print("Status code != 200 : %d" % resp.status_code)
                    raise Exception("Server returned status code != 200. Something is wrong.")

                # Process response
                try:
                    # Python 3.5 compatibility
                    content = resp.content
                    if isinstance(resp.content, (bytes, bytearray)):
                        content = resp.content.decode('utf-8')

                    # Process the JSON response
                    result = json.loads(content)

                    # Add the original file
                    # in synchronous results
                    if not asyn:
                        if len(result) > 0:
                            for r in result:
                                r['context']['file'] = filepath
                    # in asynchronous results
                    else:
                        result['file'] = filepath

                    if trace:
                        print("RESP < %s" % filepath)
                        print("RESULT: %s" % result)

                    return result

                except KeyError as e:
                    return {'error': str(e),
                            'message': 'Malformed JSON returned from the Thunderstorm service'}
                except TypeError as e:
                    return {'status': 'error', 'message': str(e), 'content': resp.content.decode('ascii')}
                except json.JSONDecodeError as e:
                    return {'status': 'error', 'message': str(e), 'content': resp.content[:128].decode('ascii')}
                except Exception as e:
                    return {'status': 'error', 'message': str(e), 'content': 'Unexpected error'}

        except FileNotFoundError as e:
            traceback.print_exc()
            return {'status': 'error', 'message': str(e), 'content': 'Cannot open file %s' % filepath}

    def scan_multi(self, filelist, num_threads=16, asyn=False, trace=False):
        """
        Multi-threaded scan of a set of files
        :param filelist: list of absolute file paths
        :param num_threads: number of threads
        :param asyn: asynchronous mode, just submit, don't wait for scan result (server returns only a submission receipt)
        :param trace: more verbose than debug
        :return:
        """
        threads = []
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            for file in filelist:
                threads.append(executor.submit(self.scan, filepath=file, asyn=asyn, trace=trace))

        results = []
        for task in as_completed(threads):
            results.append(task.result())
        return results

    def get_async_result(self, id):
        """
        Retrieves a result for a given sample id that has previous been submitted in asynchronous mode
        :param id: id of the sample result (returned after asynchronous submission)
        :return:
        """
        # Prepare URL
        url = "{}://{}:{}{}?id={}".format(self.method, self.host, self.port, API_CHECK_URI_ASYNC, id)
        # Retrieve the result
        try:
            r = requests.get(url,
                             proxies=self.proxies,
                             verify=self.verify_ssl)
            if r.status_code != 200:
                return {'status': 'error', 'status_code': r.status_code, 'message': str(r.content)}
        except requests.exceptions.ConnectionError as e:
            print("Cannot connect to %s" % url)
            return {"status": "error", "message": str(e), "content": "-"}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
        # Process result
        try:
            jresult = json.loads(r.text)
            # Wrong JSON response
            if 'status' not in jresult:
                return {"status": "error", "message": "JSON content is not the expected one",
                        "content": json.dumps(str(r.content[:128]))}
        except json.JSONDecodeError as e:
            return {"status": "error", "message": str(e), "content": json.dumps(str(r.content[:128]))}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
        return jresult

    def get_status(self):
        """
        Retrieve the service status
        :return:
        """
        url = "{}://{}:{}{}".format(self.method, self.host, self.port, API_STATUS_URI)
        try:
            r = requests.get(url,
                             proxies=self.proxies,
                             verify=self.verify_ssl)
        except requests.exceptions.ConnectionError as e:
            print("Cannot connect to %s" % url)
            return {"status": "error", "message": str(e), "content": "-"}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
        try:
            jresult = json.loads(r.text)
            # Wrong JSON response
            if 'uptime_seconds' not in jresult:
                return {"status": "error", "message": "JSON content is not the expected one",
                        "content": json.dumps(str(r.content[:128]))}
        except json.JSONDecodeError as e:
            return {"status": "error", "message": str(e), "content": json.dumps(str(r.content[:128]))}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
        return jresult

    def get_info(self):
        """
        Retrieve the service information
        :return:
        """
        url = "{}://{}:{}{}".format(self.method, self.host, self.port, API_INFO_URI)
        try:
            r = requests.get(url,
                             proxies=self.proxies,
                             verify=self.verify_ssl)
        except requests.exceptions.ConnectionError as e:
            print("Cannot connect to %s" % url)
            return {"status": "error", "message": str(e), "content": "-"}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
        try:
            jresult = json.loads(r.text)
        except json.JSONDecodeError as e:
            return {"status": "error", "message": str(e), "content": json.dumps(str(r.content[:128]))}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
        return jresult
