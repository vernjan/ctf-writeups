import base64
import requests


def main():
    challenge_url = 'http://challenges.thecatch.cz/42fd967386d83d7ecc4c716c06633da9/'
    assignment = requests.get(challenge_url)
    task_encoded = assignment.content.decode('utf8').splitlines()[0][17:]
    task = base64.b64decode(task_encoded).decode('utf8')
    cookie = assignment.headers['Set-Cookie'].split(';')[0]
    bid = task.splitlines()[51].split("'")[3]
    code = task.splitlines()[46].split("'")[1]

    flag = requests.get(
        challenge_url,
        params={'answer': '{}-{}'.format(bid, code)},
        headers={'Cookie': cookie}
    ).content.decode('utf8')

    print(flag)


main()
