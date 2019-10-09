import base64
import hashlib

import requests


class Updater:
    server = ''
    bid = ''
    key = ''
    interface = None
    check = ''

    def __init__(self, server, bid, key):
        self.server = server
        self.bid = bid
        self.key = key
        self.check = ''

    def unlock_interface(self):
        print('Unlocking interface:')
        self.get_data('UNLOCK')

    def fix_the_laws(self):
        print("Fixing the laws:")
        self.get_data('NEWLAWS')

    def patch_files(self):
        print("Patching files:")
        self.get_data('FILES')

    def integrity_check(self):
        print('Running integrity check:')
        self.get_data('TEST')
        code = hashlib.md5(self.check.encode()).hexdigest()
        print('Code: ' + code)
        # if code == 'ed2c638d2e67ddf536f57cb26807576b':
        return "{}-{}".format(self.bid, code)
        # else:
        #     return "{}-{}".format(self.bid, "bae60998ffe4923b131e3d6e4c19993e")

    def get_data(self, code):
        print('Getting data for code {}'.format(code))
        req = "{}/?{}".format(self.server, "{}-{}".format(code, self.key))
        print(req)
        resp = requests.get(req).content.decode("utf8")
        print(resp)
        self.key, data = resp.split(";", 1)
        print('Key: ' + self.key)
        print('Data: ' + data)
        data = base64.b64decode(data).decode('utf8')
        print('Decoded data: ' + data)
        self.check = "{}{}{}".format(self.key[1:10], self.check, data[1:10])
        print('Check: ' + self.check)
        return data


def main():
    challenge_url = 'http://challenges.thecatch.cz/42fd967386d83d7ecc4c716c06633da9/'
    challenge_response = requests.get(challenge_url)
    task_encoded = challenge_response.content.decode("utf8").splitlines()[0][17:]
    task = base64.b64decode(task_encoded).decode('utf8')
    cookie = challenge_response.headers['Set-Cookie'].split(';')[0]

    print(task)
    bid = task.splitlines()[51].split("'")[3]
    print(bid)
    key = task.splitlines()[51].split("'")[5]
    print(key)

    server = 'http://challenges.thecatch.cz/b41de9c55512b0169b6d284b2ea61845'
    updater = Updater(server, bid, key)
    updater.unlock_interface()
    updater.fix_the_laws()
    updater.patch_files()
    answer = updater.integrity_check()
    print('Answer: ' + answer)

    flag = requests.get(
        challenge_url,
        params={'answer': answer},
        headers={'Cookie': cookie}
    ).content.decode('utf8')
    print(flag)


main()
