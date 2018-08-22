#! /usr/bin/env python3

import os
import re
import readline

from pathlib import Path
from hashlib import sha256

SECRET = 'th1$_1z_$up3r_s3cr3t'

def fancy_print(s=''):
    print(f'[+++] {s}')

def fancy_input(s=''):
    return input(f'[+++] {s}')

def login(alias, asurite):
    if not re.match('^[a-z0-9_]+$', alias):
        return 'Hacker Alias must match: ^[a-z0-9_]+$'
    if not re.match('^[a-z0-9]+$', asurite):
        return 'ASURITE must match: ^[a-z0-9]+$'

    fancy_print()
    fancy_print()

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

    fancy_print()
    fancy_print("=" * 20 + "SCOREBOARD" + "=" * 20)
    for i, alias in enumerate(reversed(sorted(users, key=lambda k: users[k]))):
        fancy_print(f"{i+1}.  {alias}  =  {users[alias]}")
    fancy_print()

def solve(binary_path, alias, log_path):
    flag = sha256(f'{SECRET}+{alias}+{binary_path}'.encode()).hexdigest()
    flag = 'CSE466{' + flag + '}'

    docker = f'docker run --name hw1_{alias} --rm -it -e FLAG={flag} -e BINARY_FILE={binary_path} --cpus=0.5 --memory=500m --memory-swap=-1 --pids-limit=100 hw1'
    cmd = f'script -aqc "{docker}" {str(log_path)}'
    result = os.system(cmd)

    if result == 0:
        input_flag = fancy_input("Flag: ")
        return input_flag == flag
    else:
        fancy_print("Error starting container! Maybe you are already connected in a different session?")
        return False

def main():
    alias = fancy_input("Hacker Alias: ")
    asurite = fancy_input("ASURITE: ")

    result = login(alias, asurite)
    if type(result) is str:
        fancy_print(result)
        return

    user_path = result

    while True:
        fancy_print("1. Show Scoreboard")
        fancy_print("2. Solve HW1")

        try:
            choice = int(fancy_input("Choice: "))
        except ValueError:
            choice = 0

        if choice == 1:
            show_scoreboard()

        elif choice == 2:
            binary_path = fancy_input("Path to Binary: ")
            if not re.match('^/[a-zA-Z0-9/_\-]+$', binary_path):
                fancy_print("Path to Binary must match: ^/[a-zA-Z0-9/_\-]+$")
            binary_path = re.sub('/+', '/', binary_path)

            solved = solve(binary_path, alias, (user_path / 'logs' / binary_path.replace('/', '_')))
            if solved:
                fancy_print("Correct Flag!")
                (user_path / 'solves' / binary_path.replace('/', '_')).touch()

            else:
                fancy_print("Wrong Flag!")

        else:
            fancy_print("Invalid choice!")

        fancy_print()
        fancy_print()

if __name__ == '__main__':
    main()
