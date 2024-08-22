# `ircpipe` - netcat for IRC

Sets up an irc connection, and takes care of PINGs and PONGs.


## Usage

```
ircpipe [-pP] [-sSk] [-n NICK] [-j CHAN] HOST [PORT]
```

* `-n`: nick to use (mandatory)
* `-j`: channel to join on connect
* `-p`: read server password from `$IRC_PASSWD`
* `-P`: authenticate using SASL PLAIN; reads password from `$IRC_PASSWD`
* `-S`: use plain TCP socket (default port 6667, enabled by default)
* `-s`: use TLS (default port 6697)
* `-k`: use TLS without certificate verification


## Theory of Operation

ircpipe aims to abstract away the annoying parts of connecting to IRC with
netcat. It handles authentication (including initial channel joins) and
sends out and responds to pings to avoid the connection from timing out. During
setup, received IRC messages are partially parsed and checked for common error
numerics to check for failures. Until this point, data on stdin is not read and
kept buffered by the operating system to avoid sending commands before the
connection is ready. Afterwards, ircpipe only listens to pings (to which it
automatically responds) and fatal `ERROR` messages (on which ircpipe exits).
When exiting due to an IRC protocol level error, ircpipe prints the full line of
the responsible response to stderr and exits with code 1.

ircpipe reads from stdin and writes to stdout and does not modify in- or
output. The user is expected to pass (or parse) raw IRC messages, as per RFC
1459 or 2812. While ircpipe is meant to be used in shell pipelines to implement
half-duplex bots, it can easily be used as a quick and dirty interactive IRC
client as well (especially using the highlight script in contrib). By setting
up a fifo (named pipe) and redirecting one of the streams though it and piping
the other, both to the same program, it is possible to implement bidirectional
bots as well.

While only the last `-j` flag is processed, it is still possible to supply
multiple channels by seperating them with a comma (no space). To join a
password protected channel, append a space and a comma seperated list of
passwords for each channel. This behaviour emerges from how IRC specifies the
argument of the `JOIN` message (same syntax) to which we forward `CHAN`
unmodified.

For TLS, the only sane option, OpenBSD's libTLS or libreTLS (the reimplemen-
tation on top of OpenSSL for other operating systems) was chosen. It removes
all the complexity of using TLS and therefore prevents accidental misuse.

No nickserv (or chanserv or similar) support is implemented or planned. Modern
IRC networks should support authenticating with SASL (as specified by IRCv3);
for bouncers, IRC server passwords work well. Patches for SASL certificate
authentication may be accepted, assuming they don't add an unproportional
amount of code and complexity. Similarly, no fallback nicks can be configured
and when the chosen nick is already in use, ircpipe exits with an error.
Patches to improve this situation might get accepted (once again barring too
much added complexity).


## Examples

Connect to an IRC bouncer and highlight incoming messages. Timestamps are
provided by `ts`, part of the moreutils suite. This is a surprisingly usable
interactive IRC client. Posting to a channel (or messaging a user) is possible
by sending the raw command, e.g. `privmsg #myChan :hello, world!` (most ircd
implementations are matching commands case-insensitively). For better input
handling, wrapping the whole pipeline with `rlwrap sh -c '...'` prevents
incoming messages from mangling half-typed commands.

```
IRC_PASSWD=myNick/myNet:myPass ircpipe -n myNick -p -s bouncer.example.org | ./contrib/highlight | ts
# or:
IRC_PASSWD=myNick/myNet:myPass rlwrap sh -c 'ircpipe -n myNick -p -s bouncer.example.org | ./contrib/highlight | ts'
```

Forward some error logs to a special IRC channel. This is the original use case
ircpipe was built for. It's easy to trigger anti-flood protections when using
this, so only critical stuff should end up here. A client on your phone can then
audibly alert you to important events (e.g by mentioning your nick in a prefix).

```
tail -f /var/log/myProgram | grep -i error | sed 's/^/PRIVMSG #myChan :/' | ircpipe -n myNick -j '#myChan' -s irc.example.com
```

Keep a very rudimentary log of conversations from multiple channels. Since you
are not supposed to create too many connections to a network, this example
exploits how the server interprets JOIN messages with multiple channels.

```
ircpipe -n myNick -j '#myChan1,#myChan2' -s irc.example.com >> /var/log/irc
```

Sometimes, communicating using stdin and stdout might not be ideal. socat(1) can
be used to connect ircpipe to a UNIX domain (or any other kind of) socket.

```
socat EXEC:'ircpipe -s -n myNick irc.example.com' UNIX-LISTEN:/tmp/ircpipe
```

## Caveats

The spec caps line length at 512 bytes; longer messages may or may not make it
through the network unscathed. Since ircpipe doesn't understand PRIVMSG (the
most likely message to go over that limit) it can't split messages up for you.
Either make sure to only send relatively short payloads, or use an input filter
to split them up into multiple privmsgs. Be sure to keep flooding limits in
mind to avoid getting kicked when doing so.

IRC specifies that lines must be terminated by CR LF, but most if not all
servers accept UNIX style (plain LF) line endings, too. ircpipe also relays
lines from the IRC server unmodified, so it is likely that responses are CR LF
terminated. If either of this is a problem, a simple pair of input and output
filters, e.g. unix2dos(1) and dos2unix(1), can be placed around ircpipe.

### Security Considerations

ircpipe is not hardened against injections. While this is plainly obvious for
stdin (and indeed the whole point of ircpipe), this also applies to command line
arguments: they are neither checked for illegal white-space, nor for newlines.
When arguments are taken from user controlled input, the former allows for
malformed IRC messages and the latter for outright IRC message injection.

We also don't guard against escape sequences in responses. When used
interactively, a bad actor could send malicious sequences causing terminal
corruption. Causing data leaks (by querying terminal information) is unlikely,
as the responses won't be proper irc PRIVMSGs.

## Building

Make sure libreTLS (or libTLS when on OpenBSD) library and development headers
are installed, then simply run `make`. Sensible `CFLAGS` are provided by
default, unless given from either the environment or as an argument to make(1).
The resulting executable, `ircpipe`, can then simply be copied to `$PATH` e.g.
with install(1).


## Licensing

This software is made available at https://git.gir.st/ircpipe.git under the
terms of the GNU General Public License Version 3.
