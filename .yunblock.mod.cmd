cmd_/mnt/2tb/sdk1/youtubeUnblock/yunblock.mod := printf '%s\n'   yunblock.o | awk '!x[$$0]++ { print("/mnt/2tb/sdk1/youtubeUnblock/"$$0) }' > /mnt/2tb/sdk1/youtubeUnblock/yunblock.mod
