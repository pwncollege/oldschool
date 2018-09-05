# cse466

## Useful One-Liners

Number of solves for each binary:
```sh
ls /home/<HOMEWORK>/*/solves/* | tr -t '/solves/' ' ' | awk '{print $3}' | sort | uniq -c | sort -r | awk 'BEGIN {print "Solves Binary"} {print $1 " " $2}' | column -t
```

Scoreboard without guests:
```sh
nc cse466.pwn.college 23 <<(echo '<HOMEWORK_PASSWORD>' && sleep 1 && echo -e 'scorebot\nscorebot\n1') | grep '^\[+++\]  *\d\d*\.  *\w\w*  *\d\d*  *.*$' | grep -v 'GUEST$' | awk 'BEGIN {print "Rank Alias Score Grade"} {print NR " " $3 " " $4 " " $5}' | column -t
```
