CC          := gcc
CFLAGS      := -O3 -std=c99
EXECUTABLES := hashy hashy-64 hashy-256 hashy-512 hashy-1024 hashy-2048 hashy-4096 hashy-65536

all: $(EXECUTABLES)

hashy: hashy.c
	$(CC) $< -o $@ $(CFLAGS)

hashy-%: longhashy.c
	$(CC) $< -o $@ $(CFLAGS) -DBITS=$(subst hashy-,,$@)

.PHONY: clean
clean:
	rm $(EXECUTABLES)

