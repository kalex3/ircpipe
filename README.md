# `ircpipe` - netcat for IRC

Sets up an irc connection, and takes care about PINGs and PONGs.


## Usage

```
ircpipe [-pP] [-sSk] [-n NICK] [-j CHAN] HOST [PORT]
```

* `-n`: nick to use (mandatory)
* `-j`: channel to join on connect
* `-p`: read server password from `$IRC_PASSWD`
* `-P`: authenticate using SASL PLAIN; reads password from `$IRC_PASSWD`
* `-s`: use TLS (default port 6697)
* `-S`: use plain TCP socket (default port 6667)
* `-k`: use TLS without certificate verification


## Theory of Operation

ircpipe aims to abstract away the annoying parts of connecting to IRC with
netcat. It handles authentication (including initial channel joins) and
sends out and responds to pings to avoid the connection from timing out. During
setup, received IRC messages are parsed (using strtok) and checked for common
error numerics to check for failures. Afterwards, ircpipe only listens to pings
(to which it automatically responds) and fatal `ERROR` messages (on which
ircpipe exits). When exiting due to an IRC protocol level error, ircpipe prints
the full line of the responsible response to stderr and exits with code 1.

ircpipe reads from stdin and writes to stdout and does not modify in- or
output. The user is expected to pass (or parse) raw IRC messages, as per RFC
1459 or 2812. While ircpipe is meant to be used in shell pipelines to implement
half-duplex bots, it can easily be used as a quick and dirty interactive IRC
client as well (especially using the highlight script in contrib). By setting
up a fifo (named pipe) and redirecting one of the streams though it and piping
the other, both to the same program, it is possible to implement bidirectional
bots as well.

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
filters, e.g. `unix2dos`(1) and `dos2unix`(1), can be placed around ircpipe.

While only the last `-j` flag is processed, it is still possible to supply
multiple channels by seperating them with a comma (no space). To join a
password protected channel, append a space and a comma seperated list of
passwords for each channel. This behaviour emerges from how IRC specifies the
argument of the `JOIN` message (same syntax) to which we forward `CHAN`
unmodified.

For TLS, the only sane option, OpenBSD's libTLS or libreTLS (the reimplemen-
tation on top of OpenSSL for other operating systems) was chosen. It removes
all the complexity of using TLS and therefore prevents accidental misuse.

Note that there is one known vulnerability: we don't guard against escape
sequences in responses. when used interactively, a bad actor could send
malicious sequences causing terminal corruption. causing data leaks (by
querying terminal information) is unlikely, as the responses won't be proper
irc PRIVMSGs. An output filter (like the included `highlight`) is recommended
to strip them out.

No nickserv (or chanserv or similar) support is implemented or planned. Modern
IRC networks should support authenticating with SASL (as specified in IRCv3);
for bouncers, IRC server passwords work well. Patches for SASL certificate
authentication may be accepted, assuming they don't add an unproportional
amount of code and complexity. Similarly, no fallback nicks can be configured
and when the chosen nick is already in use, ircpipe exits with an error.
Patches to improve this situation might get accepted (once again barring too
much added complexity).


## Building

Make sure libreTLS (or libTLS) library and development headers are installed,
then simply run `make`. Sensible `CFLAGS` are provided by default, unless given
from either the environment or as an argument to make(1).
The resulting executable, `ircpipe`, can then simply be copied to `$PATH` e.g.
with install(1).
