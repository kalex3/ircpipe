CFLAGS=-Wall -Wpedantic -std=c89 -g -ltls
ircpipe: ircpipe.c

.PHONY: test
test: ircpipe
	./ircpipe -n asdfsdw -j '#vxmvcxcwe' irc.efnet.org
