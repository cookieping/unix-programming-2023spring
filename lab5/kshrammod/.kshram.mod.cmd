cmd_/home/angelahsi/lab5/kshrammod/kshram.mod := printf '%s\n'   kshram.o | awk '!x[$$0]++ { print("/home/angelahsi/lab5/kshrammod/"$$0) }' > /home/angelahsi/lab5/kshrammod/kshram.mod
