CFLAGS=-Wall -Wpedantic -std=c89 -g
ircpipe: ircpipe.c

.PHONY: test
test: ircpipe
	./ircpipe -n asdfsdw -j '#vxmvcxcwe' irc.efnet.org
