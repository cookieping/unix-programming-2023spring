cmd_/home/angelahsi/lab5/kshrammod/kshrammod.mod := printf '%s\n'   kshrammod.o | awk '!x[$$0]++ { print("/home/angelahsi/lab5/kshrammod/"$$0) }' > /home/angelahsi/lab5/kshrammod/kshrammod.mod
