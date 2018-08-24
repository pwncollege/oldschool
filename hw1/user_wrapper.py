#! /usr/bin/env python3

import os
import re
import sys
import readline
import subprocess

from collections import defaultdict
from pathlib import Path
from hashlib import sha256

SECRET = 'th1$_1z_$up3r_s3cr3t'
SAFETY_SECRET = sha256(f'{SECRET}asdfasdfasdfasdfasdfasdfasdfasdfasfjaslkdfjalskjfalsdjf'.encode()).hexdigest()

session_log = None

def fancy_print(s=''):
    s = f'[+++] {s}'
    if session_log:
        with session_log.open('a') as f:
            f.write(s + '\n')
    print(s)

def fancy_input(s=''):
    s = f'[+++] {s}'
    result = input(s)
    if session_log:
        with session_log.open('a') as f:
            f.write(s + result + '\n')
    return result

def login(alias, asurite):
    if not re.match('^[a-z0-9_]{2,15}$', alias):
        return 'Hacker Alias must match: ^[a-z0-9_]{2,15}$'
    if not re.match('^[a-z0-9]{2,15}$', asurite):
        return 'ASURITE must match: ^[a-z0-9]{2,15}+$'

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

def grades(user_scores):
    below_grades = {
        user: score
        for user, score in user_scores.items()
        if score <= 70
    }
    above_grades = {
        user: score
        for user, score in user_scores.items()
        if score > 70
    }

    above_score_users = defaultdict(list)
    for user, score in above_grades.items():
        above_score_users[score].append(user)

    clusters = {
        (score, score): above_score_users[score]
        for score in sorted(above_score_users)
    }

    while len(clusters) > 40:
        closest_low = None
        closest_high = None
        closest_distance = None

        prev_cluster = None
        for cluster in sorted(clusters.keys(), key=lambda k: k[0]):
            if closest_low is None:
                closest_low = cluster
            elif closest_high is None:
                closest_high = cluster
                closest_distance = closest_high[0] - closest_low[1]
            else:
                current_distance = cluster[0] - prev_cluster[1]
                if current_distance < closest_distance:
                    closest_low = prev_cluster
                    closest_high = cluster
                    closest_distance = current_distance
            prev_cluster = cluster

        new_cluster = (closest_low[0], closest_high[1])
        new_cluster_data = [*clusters[closest_low], *clusters[closest_high]]

        del clusters[closest_low]
        del clusters[closest_high]
        clusters[new_cluster] = new_cluster_data

    above_grades = dict()
    score = 110
    for cluster in reversed(sorted(clusters.keys(), key=lambda k: k[0])):
        cluster_data = clusters[cluster]
        for user in cluster_data:
            above_grades[user] = score
        score -= 1

    return {**below_grades, **above_grades}

def show_scoreboard():
    user_scores = dict()
    for path in Path.home().iterdir():
        if path.is_dir() and ':' in path.name:
            existing_alias, existing_asurite = path.name.split(':', 1)
            solves = len(list((path / 'solves').iterdir()))
            user_scores[existing_alias] = solves

    user_grades = grades(user_scores)

    max_alias_length = max(len(user) for user in user_scores)
    max_score_length = max(len(str(user_scores[user])) for user in user_scores)

    fancy_print()
    fancy_print("=" * 20 + " SCOREBOARD " + "=" * 20)
    fancy_print(f"{'Rank':<6}    {'Hacker':<{max_alias_length}}    {'Score':<{max_score_length}}    {'Grade':<5}")
    for i, alias in enumerate(reversed(sorted(user_scores, key=lambda k: user_scores[k]))):
        fancy_print(f"{i+1:>5}.    {alias:<{max_alias_length}}    {user_scores[alias]:>{max_score_length}}    {user_grades[alias]:>5}")
    fancy_print()

def validate_binary_path(binary_path):
    return re.match('^/[a-zA-Z0-9/_\-]+$', binary_path) and True or False

def get_binary_path():
    binary_path = fancy_input("Path to Binary: ")
    if not validate_binary_path(binary_path):
        fancy_print("Path to Binary must match: ^/[a-zA-Z0-9/_\-]+$")
        return False

    binary_path = re.sub('/+', '/', binary_path)

    if binary_path.count('proc') > 1:
        fancy_print("Don't be greedy!")
        return False

    return binary_path

def solve(binary_path, alias, log_path):
    flag = sha256(f'{SECRET}+{alias}+{binary_path}'.encode()).hexdigest()
    flag = 'CSE466{' + flag + '}'
    cmd = f'script -aqec "{sys.argv[0]} EXECUTE {alias} {binary_path}" {str(log_path)}'
    result = os.system(cmd)
    #p = subprocess.Popen(['script', '-aqec', docker, f'{str(log_path)}'], stdin=0, stderr=2, stdout=1, env={'SAFETY_SECRET':SAFETY_SECRET})
    #result = p.wait()

    input_flag = fancy_input("Flag: ")
    return input_flag == flag

def run_docker(alias, binary_path):
    flag = sha256(f'{SECRET}+{alias}+{binary_path}'.encode()).hexdigest()
    flag = 'CSE466{' + flag + '}'
    docker = (f'for id in $(docker ps -q --filter="name=hw1_{alias}"); do docker kill $id; done; '
              f'docker run --name hw1_{alias} --rm -it -e FLAG={flag} -e BINARY_FILE={binary_path} --cpus=0.5 --memory=500m --memory-swap=-1 --pids-limit=100 hw1')

    result = os.system(docker)
    if result != 0:
        fancy_print("Container returned an error! This might be because your last")
        fancy_print("command failed (which is okay) or because you already have another")
        fancy_print("session running. If you have lost connection to your other session,")
        fancy_print("it should time out within 10 minutes.")

def main():
    if os.environ.get('CHECK_AUTH') == 'yes':
        password = fancy_input("Password: ")
        if password != 's3cr3t':
            fancy_print("Wrong password! Check the mailing list.")
            return

    alias = fancy_input("Hacker Alias: ")
    asurite = fancy_input("ASURITE: ")

    result = login(alias, asurite)
    if type(result) is str:
        fancy_print(result)
        return

    user_path = result
    global session_log
    session_log = result / 'session_log'

    running = True
    while running:
        fancy_print("1. Show Scoreboard")
        fancy_print("2. Solve HW1")
        fancy_print("3. Quit")

        try:
            choice = int(fancy_input("Choice: "))
        except ValueError:
            choice = 0

        if choice == 1:
            show_scoreboard()

        elif choice == 2:
            binary_path = get_binary_path()

            if binary_path:
                solved = solve(binary_path, alias, (user_path / 'logs' / binary_path.replace('/', '_')))

                if solved is True:
                    fancy_print("Correct Flag!")
                    (user_path / 'solves' / binary_path.replace('/', '_')).touch()

                elif solved is False:
                    fancy_print("Wrong Flag!")

        elif choice == 3:
            running = False

        else:
            fancy_print("Invalid choice!")

        fancy_print()
        fancy_print()

if __name__ == '__main__':
    if os.environ.get('SAFETY_SECRET', '') == SAFETY_SECRET and len(sys.argv) == 4 and sys.argv[1] == 'EXECUTE':
        run_docker(sys.argv[2], sys.argv[3])
    else:
        os.environ.clear()
        os.environ['SAFETY_SECRET'] = SAFETY_SECRET
        main()
