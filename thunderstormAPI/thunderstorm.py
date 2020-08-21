#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# THOR Service API Client
# Florian Roth

import json
import requests
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed

from urllib.parse import urlparse

__version__ = "0.0.6"

API_CHECK_URI = '/api/check'
API_STATUS_URI = '/api/status'
API_INFO_URI = '/api/info'


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

    def __init__(self, host="127.0.0.1", port=8080, use_ssl=False, verify_ssl=False):
        """
        Initializes the API client object
        :param host: host on which runs THOR Thunderstorm service
        :param port: port on which listens THOR Thunderstorm service
        :param use_ssl:
        :param verify_ssl:
        """
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

    def scan(self, filepath):
        """
        Scan a certain file
        :param filepath:
        :return:
        """
        url = "{}://{}:{}{}".format(self.method, self.host, self.port, API_CHECK_URI)

        try:
            with open(filepath, 'rb') as f:
                headers = {'User-Agent': "THOR Thunderstorm API Client %s" % __version__}
                files = {"file": (filepath, f.read(), 'application/octet-stream')}
                try:
                    resp = requests.post(url=url, headers=headers, files=files, proxies=self.proxies,
                                         verify=self.verify_ssl)
                except Exception as e:
                    traceback.print_exc()

                # Warning
                if resp.status_code != 200:
                    print("Status code != 200 : %d" % resp.status_code)

                # Process response
                try:
                    # Python 3.5 compatibility
                    content = resp.content
                    if isinstance(resp.content, (bytes, bytearray)):
                        content = resp.content.decode('utf-8')

                    result = json.loads(content)
                    # Add the original file
                    if len(result) > 0:
                        for r in result:
                            r['context']['file'] = filepath
                    #print(json.dumps(result, indent=4))
                    return result
                except KeyError as e:
                    return {'error': str(e),
                            'message': 'Malformed JSON returned from the Thunderstorm service'}
                except TypeError as e:
                    return {'error': str(e), 'message': resp.content.decode('ascii')}
                except json.JSONDecodeError as e:
                    return {'error': str(e), 'message': resp.content[:128].decode('ascii')}
                except Exception as e:
                    traceback.print_exc()

        except FileNotFoundError as e:
            traceback.print_exc()
            return {'error': str(e), 'message': 'Cannot open file %s' % filepath}

    def scan_multi(self, filelist, num_threads=16):
        """
        Multi-threaded scan of a set of files
        :param filelist:
        :param num_threads:
        :return:
        """
        threads = []
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            for file in filelist:
                threads.append(executor.submit(self.scan, file))

        results = []
        for task in as_completed(threads):
            results.append(task.result())
        return results

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
        except requests.exceptions.ConnectionError:
            traceback.print_exc()
            print("Cannot connect to %s" % url)
        try:
            jresult = json.loads(r.text)
        except json.JSONDecodeError as e:
            jresult = {"status": "error", "message": str(e), "content": json.dumps(str(r.content[:128]))}
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
        except requests.exceptions.ConnectionError:
            traceback.print_exc()
            print("Cannot connect to %s" % url)
        try:
            jresult = json.loads(r.text)
        except json.JSONDecodeError as e:
            jresult = {"status": "error", "message": str(e), "content": json.dumps(str(r.content[:128]))}
        return jresult
