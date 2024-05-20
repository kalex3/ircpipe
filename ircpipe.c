#define _POSIX_C_SOURCE 200112L /* getopt(>=2), strtok_r(*), getaddrinfo(>=200112L), clock_gettime(>=199309L), sigaction(*) */
#include <poll.h>
#include <time.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <tls.h>

#define DEFAULT_TLS NO_TLS
#define DEFAULT_PORT_TCP "6667"
#define DEFAULT_PORT_TLS "6697"

#define POLL_TIMEOUT     100 /*ms*/
#define PING_INTERVAL 120000 /*ms*/
#define PONG_TIMEOUT    2000 /*ms*/

#define STR_(x) #x
#define STR(x) STR_(x)
#define OR_DIE < 0 && (perror(__FILE__ ":" STR(__LINE__)), exit(1), 0)
#define OR_DIE_gai(err) if (err) {fprintf(stderr, __FILE__ ":" STR(__LINE__) ": %s\n", gai_strerror(err));exit(1);}
#define OR_DIE_tls(ctx) < 0 && (exit((fprintf(stderr, __FILE__ ":" STR(__LINE__) ": %s\n", tls_error(ctx)), 1)), 0)

enum pass_type_e {
	NO_PASSWD,
	SERVER_PASSWD,
	SASL_PLAIN_PASSWD
};

enum tls_use_e {
	NO_TLS,
	USE_TLS,
	INSECURE_TLS
};

typedef struct {
	int fd; /* always contains the underlying file descriptor */
	struct tls *tls; /* tls context, or NULL with plain socket */
} sock_t;
#define _IMPLFN(fn, sock, buf, sz) (    \
	sock.tls                        \
	? tls_ ## fn(sock.tls, buf, sz) \
	: fn(sock.fd, buf, sz)          \
)
#define READ(sock, buf, sz) _IMPLFN(read, sock, buf, sz)
#define WRITE(sock, buf, sz) _IMPLFN(write, sock, buf, sz)

void irc_help(const char *exe, const int code) {
	fprintf(stderr, "Usage: %s [-pP] [-sSk] [-n NICK] [-j CHAN] HOST [PORT]\n", exe);
	exit(code);
}

sock_t irc_connect(const char *host, const char *port, const int tls, const char *ca_file) {
	sock_t sock;
	struct addrinfo *results, *r;
	struct timeval timeout;

	int err = getaddrinfo(host, port, NULL, &results); OR_DIE_gai(err); /*unable to resolve*/

	timeout.tv_sec = 10;
	timeout.tv_usec = 0;

	for (r = results; r != NULL; r = r->ai_next) {
		sock.fd = socket(r->ai_family, SOCK_STREAM, 0);
		if (sock.fd < 0) continue; /* try next; todo: should check errno */

		setsockopt(sock.fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout) OR_DIE;
		if (connect(sock.fd, r->ai_addr, r->ai_addrlen) == 0)
			break; /* successfully connected */

		close(sock.fd); /* failed, try next addr */
	}

	if (r == NULL) {
		/* all failed; abort. */
		sock.fd = -1;
	} else {
		/* connection established. */
		if (tls != NO_TLS) {
			struct tls *ctx = tls_client();
			struct tls_config *cfg = tls_config_new();

			if (tls == INSECURE_TLS) {
				tls_config_insecure_noverifycert(cfg);
				tls_config_insecure_noverifyname(cfg);
				tls_config_insecure_noverifytime(cfg);
				tls_config_set_ciphers(cfg, "legacy"); /* even more: 'insecure' */
			}
			tls_config_set_dheparams(cfg, "auto") OR_DIE_tls(ctx);
			if (ca_file) tls_config_set_ca_file(cfg, ca_file) OR_DIE_tls(ctx);
			/* todo: if ca_file ends in /, call tls_config_set_ca_path() instead */
			/* todo: otherwise, set to tls_default_ca_cert_file() iff libtls (not libretls) */

			tls_configure(ctx, cfg) OR_DIE_tls(ctx);
			tls_config_free(cfg);
			tls_connect_socket(ctx, sock.fd, host) OR_DIE_tls(ctx);
			tls_handshake(ctx) OR_DIE_tls(ctx);

			sock.tls = ctx;
		} else sock.tls = NULL;
		/* connect timeout here */
	}

	freeaddrinfo(results);
	return sock;
}

enum { /* requested command: */
	NO_CMD = 0,
	NICK = 1<<0,
	JOIN = 1<<1,
	PING = 1<<2,
	ERRS = 1<<3
};
int irc_answer(const sock_t sock, char *buf, const unsigned int command) {
	unsigned int seen = 0;
	char *saveptr;
	char *line = strtok_r(buf, "\r\n", &saveptr);
	/*TODO: it often happens that we take multiple calls to read() all the available lines (e.g. large motd, NAMES message). when this happens, one call to read() will return an incomplete line, and the next will start in the middle of a line. this can't be parsed properly! we need to check if the last line ends with a newline. that's hard because we use strtok which removes newlines. on the second read we should either skip over the first partial line or better, defer parsing the last line of the first read until we have the complete line.*/
	do {
		/* skip over prefix (servername): */
		if (line[0] == ':')
			while (*line && *line++ != ' ');

		/* look for command responses or relevant error numerics: */
		/* TODO: our current handling of only a specific set of error numerics makes us vulnerable to hangs, when an unexpected code was received. we should really respect a response timeout here (during setup this must be quite large, because of ident and port scanning!) */
		switch (command) {
		case PING: seen |= PING * (strncmp(line, "PONG ", 5)==0); break;
		case JOIN: seen |= JOIN * (strncmp(line, "JOIN ", 5)==0);
		           seen |= ERRS * (strncmp(line, "403 ",  4)==0);
		           seen |= ERRS * (strncmp(line, "405 ",  4)==0);
		           seen |= ERRS * (strncmp(line, "471 ",  4)==0);
		           seen |= ERRS * (strncmp(line, "473 ",  4)==0);
		           seen |= ERRS * (strncmp(line, "474 ",  4)==0);
		           seen |= ERRS * (strncmp(line, "475 ",  4)==0);
		           seen |= ERRS * (strncmp(line, "476 ",  4)==0);
		           seen |= ERRS * (strncmp(line, "477 ",  4)==0); break;
		case NICK: seen |= NICK * (strncmp(line, "001 ",  4)==0);
		           seen |= ERRS * (strncmp(line, "432 ",  4)==0);
		           seen |= ERRS * (strncmp(line, "433 ",  4)==0);
		           seen |= ERRS * (strncmp(line, "436 ",  4)==0);
		           seen |= ERRS * (strncmp(line, "464 ",  4)==0);
		           seen |= ERRS * (strncmp(line, "902 ",  4)==0);
		           seen |= ERRS * (strncmp(line, "904 ",  4)==0); break;
		}
		/* look for common error numerics if any command was given */
		if (command & (NICK|JOIN)) {
		           seen |= ERRS * (strncmp(line, "400 ",  4)==0);
		           seen |= ERRS * (strncmp(line, "421 ",  4)==0);
		           seen |= ERRS * (strncmp(line, "465 ",  4)==0);
		}
		/* always look for a fatal error */
		if (strncmp(line, "ERROR ", 6)==0) seen |= ERRS;

		if (seen & ERRS) {
			fprintf(stderr, "IRC error: %s\n", line);
			exit(1);
		}

		/* reply to pings: */
		if (strncmp(line, "PING ", 5) == 0) {
			line[1] = 'O'; /* PING :foo -> PONG :foo */
			WRITE(sock, line, strlen(line));
			WRITE(sock, "\r\n", 2);
		}
	} while ((line = strtok_r(NULL, "\r\n", &saveptr)));

	return seen;
}

int irc_base64(char *buf, int n) {
	const char *b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	int i, o, v, l = ((n+(3-n%3)%3)/3)*4;
	buf[n+1] = buf[n+2] = buf[l] = '\0';
	for (i=(n+(3-n%3)%3)-3, o=l-4; i>=0 && o>=0; i-=3, o-=4) {
		v = buf[i+0]<<16 | buf[i+1]<<8 | buf[i+2]<<0;
		buf[o+0] =          b[v>>18 & 0x3f];
		buf[o+1] =          b[v>>12 & 0x3f];
		buf[o+2] = (i+1<n)? b[v>>06 & 0x3f]:'=';
		buf[o+3] = (i+2<n)? b[v>>00 & 0x3f]:'=';
	}
	return l;
}

int irc_setup(const sock_t sock, const int outfd, const char *nick, const char *pass, int pass_type, const char *chan) {
	char buf[BUFSIZ];
	int n;
	struct pollfd fds[1];
	fds[0].fd = sock.fd;
	fds[0].events = POLLIN;

	if (pass_type == SASL_PLAIN_PASSWD) {
		n = snprintf(buf, BUFSIZ, "CAP REQ :sasl\r\n");
		WRITE(sock, buf, n);
	} else if (pass_type == SERVER_PASSWD) {
		n = snprintf(buf, BUFSIZ, "PASS %s\r\n", pass);
		WRITE(sock, buf, n);
	}

	n = snprintf(buf, BUFSIZ, "NICK %s\r\n", nick);
	WRITE(sock, buf, n);
	n = snprintf(buf, BUFSIZ, "USER %s 0 * :%s\r\n", nick, nick);
	WRITE(sock, buf, n);

	if (pass_type == SASL_PLAIN_PASSWD) {
		/* TODO: assert strlen(pass) < 300 or abort */
		/* should wait for 'CAP <nick|*> ACK :<...>' */
		WRITE(sock, "AUTHENTICATE PLAIN\r\n", 20);
		/* server sends 'AUTHENTICATE +' */
		/* split base64-output into 400 byte chunks; if last is exactly
		   400 bytes, send empty msg ('+') afterwards */
		n = snprintf(buf, BUFSIZ, "AUTHENTICATE %s%c%s%c%s", nick, 0, nick, 0, pass);
		n = irc_base64(buf+13, n-13)+13; /*13==strlen("AUTHENTICATE ")*/
		n += snprintf(buf+n, BUFSIZ-n, "\r\n");
		WRITE(sock, buf, n);
		/* wait for response 900+903 (ok) or 902/904 (err) */
		WRITE(sock, "CAP END\r\n", 9);
	}

	/* block until we get a RPL_WELCOME or an error: */
	for (;;) {
		if (poll(fds, 1, POLL_TIMEOUT)) {
			n = READ(sock, buf, BUFSIZ); buf[n] = '\0';
			write(outfd, buf, n);
			n = irc_answer(sock, buf, NICK);
			if (n & NICK) break;
			else if (n & ERRS) return -1;
		}
	}

	if (chan) {
		n = snprintf(buf, BUFSIZ, "JOIN %s\r\n", chan);
		WRITE(sock, buf, n);

		/* block until we get a JOIN response or an error: */
		/* todo: dedup this block with NICK/RPL_WELCOME */
		for (;;) {
			if (poll(fds, 1, POLL_TIMEOUT)) {
				n = READ(sock, buf, BUFSIZ); buf[n] = '\0';
				write(outfd, buf, n);
				n = irc_answer(sock, buf, JOIN);
				if (n & JOIN) break;
				else if (n & ERRS) return -1;
			}
		}
	}

	return 0;
}

long irc_time() {
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t) OR_DIE;
	return t.tv_sec*1000 + t.tv_nsec / 1000000; /* milliseconds */
}

int irc_poll(const sock_t sock, const int infd, const int outfd) {
	int n;
	char buf[BUFSIZ];

	int want_pong = 0;
	long recv_ts = irc_time();

	enum { IRC, CLI };
	struct pollfd fds[2];
	fds[IRC].fd = sock.fd;
	fds[IRC].events = POLLIN;
	fds[CLI].fd = infd;
	fds[CLI].events = POLLIN;

	for (;;) {
		poll(fds, 2, POLL_TIMEOUT) OR_DIE;

		/* XXX: should handle EINTR, EAGAIN    -> retry
		        should handle EPIPE and others -> exit */
		/* todo: could check for fds[IRC].revents & (POLLERR|POLLHUP): tcp FIN or RST received */
		if (fds[IRC].revents & POLLIN) {
			n = READ(sock, buf, BUFSIZ); buf[n] = '\0';
			if (n == 0) return -1; /* server closed connection */
			fds[IRC].events = POLLIN | (n==TLS_WANT_POLLOUT?POLLOUT:0);
			write(outfd, buf, n);
			if (irc_answer(sock, buf, want_pong?PING:NO_CMD) & PING)
				want_pong = 0;
			recv_ts = irc_time();
		}
		if (fds[CLI].revents & POLLIN) {
			n = read(infd, buf, BUFSIZ); buf[n] = '\0';
			if (n == 0) return 0; /* we closed connection */
			n = WRITE(sock, buf, n);
			fds[IRC].events = POLLIN | (n==TLS_WANT_POLLOUT?POLLOUT:0);
		}
		if (fds[IRC].revents & POLLOUT) { /* needed for TLS only */
			n = WRITE(sock, buf, n);
			fds[IRC].events = POLLIN | (n==TLS_WANT_POLLOUT?POLLOUT:0);
		}

		if (want_pong && irc_time() - recv_ts > PING_INTERVAL + PONG_TIMEOUT) {
			/* pong timeout reached, abort. */
			fprintf(stderr, "PONG timeout");
			return -1;
		} else if (!want_pong && irc_time() - recv_ts > PING_INTERVAL) {
			/* haven't rx'd anything in a while, sending ping. */
			WRITE(sock, "PING :ircpipe\r\n", 15);
			want_pong = 1;
		}
	}
}

void irc_cleanup(const sock_t sock) {
	WRITE(sock, "QUIT :ircpipe\r\n", 15);
	if (sock.tls) tls_close(sock.tls);
	shutdown(sock.fd, SHUT_RDWR);
	close(sock.fd);
}

sock_t sock;

void irc_sighandler(int signum) {
	switch (signum) {
	case SIGHUP:
	case SIGINT:
	case SIGTERM:
		irc_cleanup(sock);
		exit(signum);
	}
}

int main(int argc, char **argv) {
	char *host = NULL;
	char *port = NULL;
	char *nick = NULL;
	char *pass = NULL;
	char *chan = NULL;
	int tls = DEFAULT_TLS;
	char *ca_file = NULL;
	int pass_type = NO_PASSWD;

	int rv;
	struct sigaction act;

	int opt; opterr = 0;

	pass = getenv("IRC_PASSWD");
	ca_file = getenv("IRC_CAFILE");

	while ((opt = getopt(argc, argv, "n:j:pPsSkh")) != -1) {
		switch (opt) {
		case 'n': nick = optarg; break;
		case 'p': pass_type = SERVER_PASSWD; break;
		case 'P': pass_type = SASL_PLAIN_PASSWD; break;
		case 's': tls = USE_TLS; break;
		case 'S': tls = NO_TLS; break;
		case 'k': tls = INSECURE_TLS; break;
		case 'j': chan = optarg; break;
		default: irc_help(argv[0], opt != 'h');
		}
	}

	if (optind < argc) {
		host = argv[optind++];
	} else {
		/* too few positional arguments */
		fprintf(stderr, "missing HOST\n");
		irc_help(argv[0], 1);
	}
	if (optind < argc) {
		port = argv[optind++];
	} else {
		port = (tls == NO_TLS)
			? DEFAULT_PORT_TCP
			: DEFAULT_PORT_TLS;
	}
	if (optind < argc) {
		/* too many positional arguments */
		fprintf(stderr, "too many args\n");
		irc_help(argv[0], 1);
	}

	if (pass_type != NO_PASSWD && pass == NULL) {
		fprintf(stderr, "must set IRC_PASSWD envvar to use -p/-P\n");
		exit(1);
	}

	memset(&act, 0, sizeof act);
	act.sa_handler = irc_sighandler;
	sigaction(SIGHUP, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);

	sock = irc_connect(host, port, tls, ca_file); sock.fd OR_DIE;
	irc_setup(sock, 1, nick, pass, pass_type, chan);
	rv = irc_poll(sock, 0, 1);
	irc_cleanup(sock);

	return (rv < 0);
}
