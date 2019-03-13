import os
import requests
import urllib3
import logging
import time

def create_dump_directories(dirs):
    for directory in dirs:
        logging.debug('creating {} directory'.format(directory))
        if not os.path.exists(directory):
            os.makedirs(directory)


class DumpRequests:
    def __init__(self, method, url, directory, cookies={}, headers={}, proxies=(), timeout=50, data={},NODUMP=False):
        self.url = url
        self.cookies = cookies
        self.headers = headers
        self.proxies = proxies
        self.timeout = timeout
        self.method = method
        self.directory = directory
        self.cd = os.path.dirname(os.path.abspath(__file__))
        self.file_directory = '{}/{}.html'.format(self.directory, self.url.replace('/', '_'))[:150]
        self.data = data
        self.NODUMP = NODUMP

    def make_dump(self, response):
        t1 = time.time()
        for i in range(5):
            try:
                logging.debug('making dump for {}'.format(self.url))
                create_dump_directories([self.directory])
                file = open(self.file_directory, 'wb')
                file.write(response.encode('ascii', 'ignore'))
                file.close()
                return time.time() - t1
            except OSError:
                print('Can`t create dump for {}, {} try'.format(self.url, i))
        return time.time() - t1

    def make_request(self):
        try:
            t1 = time.time()
            if self.NODUMP:
                raise FileNotFoundError
            file = open(os.path.join(self.cd, self.file_directory), 'r')
            file_response = file.read()
            file.close()
            logging.debug('dump opened without requests')
            return True, file_response, time.time() - t1, None, None
        except FileNotFoundError:
            # SSLError warning log disable
            t1 = time.time()
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            try:
                response = requests.request(self.method,
                                            self.url,
                                            headers=self.headers,
                                            timeout=self.timeout,
                                            cookies=self.cookies,
                                            data=self.data,
                                            verify=False)
                logging.debug(
                    'request to {} received {} status code with without proxy'.format(self.url, response.status_code))
                if str(response.status_code)[0] in ('2', '3') and str(response.status_code)[0] != "302":
                    if self.directory:
                        time_for_dump = self.make_dump(response.text)
                    else:
                        time_for_dump = None
                    return True, response.text, None, time_for_dump, time.time() - t1
                for proxy in self.proxies:
                    response = requests.request(self.method,
                                                self.url,
                                                proxies=proxy,
                                                headers=self.headers,
                                                timeout=self.timeout,
                                                cookies=self.cookies,
                                                verify=False)
                    logging.debug('request to {} received {} status code with {} proxy'.format(self.url,
                                                                                               response.status_code,
                                                                                               proxy))
                    if str(response.status_code)[0] in ('2', '3') and str(response.status_code)[0] != "302":
                        if self.directory:
                            time_for_dump = self.make_dump(response.text)
                        else:
                            time_for_dump = None

                        return True, response.text, None, time_for_dump, time.time() - t1
                    else:
                        del response
                        continue
                return False, None, None, None, time.time() - t1
            except Exception as e:
                logging.debug(e)
                return False, None, None, None, time.time() - t1
