#! /usr/bin/env python3

import os
import re

from pathlib import Path
from hashlib import sha256

SECRET = 'th1$_1z_$up3r_s3cr3t'

def log(s):
    print(f'[+++] {s}')

def login(alias, asurite):
    if not re.match('^[a-z0-9_]+$', alias):
        return 'Hacker Alias must match: ^[a-z0-9_]+$'
    if not re.match('^[a-z0-9]+$', asurite):
        return 'ASURITE must match: ^[a-z0-9]+$'

    users = dict()
    for path in Path.home().iterdir():
        if path.is_dir() and ':' in path.name:
            existing_alias, existing_asurite = path.name.split(':', 1)
            users[existing_alias] = existing_asurite

    user_path = Path.home() / f'{alias}:{asurite}'

    current_asurite = users.get(alias)
    if current_asurite == asurite:
        return user_path
    elif alias not in users.keys() and asurite not in users.values():
        user_path.mkdir()
        (user_path / 'logs').mkdir()
        (user_path / 'solves').mkdir()
        return user_path
    elif alias in users.keys():
        return 'Hacker Alias already registered!'
    elif asurite in users.values():
        return 'ASURITE already registered!'
    else:
        raise Exception("???")

def show_scoreboard():
    users = dict()
    for path in Path.home().iterdir():
        if path.is_dir() and ':' in path.name:
            existing_alias, existing_asurite = path.name.split(':', 1)
            solves = len(list((path / 'solves').iterdir()))
            users[existing_alias] = solves

    log()
    log("=" * 20 + "SCOREBOARD" + "=" * 20)
    for i, alias in enumerate(reversed(sorted(users, key=lambda k: users[k]))):
        log(f"{i+1}.  {alias}  =  {users[alias]}")
    log()

def solve(binary_path, alias, log_path):
    flag = sha256(f'{SECRET}+{alias}+{binary_path}'.encode()).hexdigest()
    flag = 'CSE466{' + flag + '}'

    docker = f'docker run --name hw1_{alias} --rm -it -e FLAG={flag} -e BINARY_FILE={binary_path} --cpus=0.5 --memory=500m --memory-swap=-1 --pids-limit=100 hw1'
    cmd = f'script -aqc "{docker}" {str(log_path)}'
    os.system(cmd)

    input_flag = input("Flag: ")
    return input_flag == flag

def main():
    alias = input("Hacker Alias: ")
    asurite = input("ASURITE: ")

    result = login(alias, asurite)
    if type(result) is str:
        log(result)
        return

    user_path = result

    while True:
        log("1. Show Scoreboard")
        log("2. Solve HW1")

        try:
            choice = int(input("Choice: "))
        except ValueError:
            choice = 0

        if choice == 1:
            show_scoreboard()

        elif choice == 2:
            binary_path = input("Path to Binary: ")
            if not re.match('^/[a-zA-Z0-9/_\-]+$', binary_path):
                log("Path to Binary must match: ^/[a-zA-Z0-9/_\-]+$")
            binary_path = re.sub('/+', '/', binary_path)

            solved = solve(binary_path, alias, (user_path / 'logs' / binary_path.replace('/', '_')))
            if solved:
                log("Correct Flag!")
                (user_path / 'solves' / binary_path.replace('/', '_')).touch()

            else:
                log("Wrong Flag!")

        else:
            log("Invalid choice!")

        log("\n")

if __name__ == '__main__':
    main()
