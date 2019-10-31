import requests
import hashlib
import sys


def reques_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error feteching: {res.status_code}, check API and try again')
    return res


def getPasswordsLeaksCount(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

def pwned_api_check(password):
    #     has password
    sha1Password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1Password[:5], sha1Password[5:]
    response = reques_api_data(first5_char)
    return getPasswordsLeaksCount(response, tail)


def main(args):
    for password in args:
        count= pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times. You should change your password ASAP.')
        else:
            print(f'{password} was NOT found. Good job!')
    return 'DONE!!'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
