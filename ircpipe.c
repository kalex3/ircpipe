/* Copyright 2024 Tobias Girstmair <https://gir.st/>, GPLv3 licensed. */
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

#define PROGNAME "ircpipe"
#define VERSION "0.1"

#define DEFAULT_TLS NO_TLS
#define DEFAULT_PORT_TCP "6667"
#define DEFAULT_PORT_TLS "6697"

#define POLL_TIMEOUT     100 /*ms*/
#define PING_INTERVAL 120000 /*ms*/
#define PONG_TIMEOUT    2000 /*ms*/
#define SETUP_TIMEOUT  30000 /*ms*/
#define SOCKET_TIMEOUT  5000 /*ms*/

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

typedef struct {
	size_t off; /* offset, at which read(2) should start writing bytes */
	size_t nextoff; /* length of the final partial/unterminated line */
	char *nextbuf; /* start of the unterminated partial line */
	char buf[BUFSIZ];
} buf_t;
#define BUF(b) (b->buf + b->off)
#define SIZ(b) (BUFSIZ - b->off)

void irc_help(const char *exe) {
	fprintf(stderr, "Usage: %s [-pP] [-sSk] [-n NICK] [-j CHAN] HOST [PORT]\n", exe);
}

sock_t irc_connect(const char *host, const char *port, const int tls, const char *ca_file) {
	sock_t sock;
	struct addrinfo *results, *r;
	struct timeval timeout;

	int err = getaddrinfo(host, port, NULL, &results); OR_DIE_gai(err); /*unable to resolve*/

	timeout.tv_sec = SOCKET_TIMEOUT / 1000;
	timeout.tv_usec = (SOCKET_TIMEOUT % 1000) * 1000000;

	for (r = results; r != NULL; r = r->ai_next) {
		sock.fd = socket(r->ai_family, SOCK_STREAM, 0);
		if (sock.fd < 0) continue;

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
	do {
		/* skip over prefix (servername): */
		if (line[0] == ':')
			while (*line && *line++ != ' ');

		/* look for command responses or relevant error numerics: */
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
			int n = strlen(line);
			int crlf = line[n+1] == '\n'; /* strtok only removes first delimeter */
			/*^XXX: this causes 1byte out-of-bounds read if buffer was completely full. however, we only expect pings in a buffer of their own (after a period of radio silence), so in practise this won't matter */
			line[1] = 'O'; /* PING :foo -> PONG :foo */
			line[n] = crlf ? '\r' : '\n'; /* re-terminate after strtok */
			WRITE(sock, line, n+crlf+1);
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

long irc_time(void) {
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t) OR_DIE;
	return t.tv_sec*1000 + t.tv_nsec / 1000000; /* milliseconds */
}

void *irc_memrchr(const void *s, int c, size_t n) {
	while (n--)
		if (((unsigned char *)s)[n] == (unsigned char)c)
			return (void *)(((unsigned char *)s)+n);
	return NULL;
}

void irc_terminate_buffer(buf_t *b, int n) {
	char *eol = irc_memrchr(BUF(b), '\n', n);
	if (eol == NULL) {
		fprintf(stderr, PROGNAME": line length exceeds %d bytes, aborting.", BUFSIZ);
		exit(-1); /* todo: return code? */
	}
	b->nextbuf = eol + 1; /* next buffer starts *after* newline */
	b->nextoff = (BUF(b) + n - 1) - eol; /* points to beginning of final unterminated line */
	if (eol > b->buf && eol[-1] == '\r') eol--;
	*eol = '\0';
}

void irc_rewind_buffer(buf_t *b) {
	memmove(b->buf, b->nextbuf, b->nextoff);
	b->off = b->nextoff;
}

int irc_wait(const sock_t sock, const int outfd, buf_t *b, int cmd) {
	int n;
	long start = irc_time();
	struct pollfd fds[1];
	fds[0].fd = sock.fd;
	fds[0].events = POLLIN;

	for (;;) {
		if (poll(fds, 1, POLL_TIMEOUT)) {
			n = READ(sock, BUF(b), SIZ(b));
			if (n == 0) return -1; /* server closed connection */
			if (n == TLS_WANT_POLLIN) continue;
			write(outfd, BUF(b), n);

			irc_terminate_buffer(b, n);
			n = irc_answer(sock, BUF(b), cmd);
			irc_rewind_buffer(b);

			if (n & cmd) return 0;
			if (irc_time() - start > SETUP_TIMEOUT) {
				fprintf(stderr, "IRC setup timeout\n");
				exit(1);
			}
		}
	}
}

int irc_setup(const sock_t sock, const int outfd, buf_t *b, const char *nick, const char *pass, int pass_type, const char *chan) {
	char buf[BUFSIZ];
	int n;

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
		/* note: should assert strlen(pass) < 300 for spec compliance */
		/* should wait for 'CAP <nick|*> ACK :<...>' */
		WRITE(sock, "AUTHENTICATE PLAIN\r\n", 20);
		/* server sends 'AUTHENTICATE +' */
		n = snprintf(buf, BUFSIZ, "AUTHENTICATE %s%c%s%c%s", nick, 0, nick, 0, pass);
		n = irc_base64(buf+13, n-13)+13; /*13==strlen("AUTHENTICATE ")*/
		n += snprintf(buf+n, BUFSIZ-n, "\r\n");
		WRITE(sock, buf, n);
		/* wait for response 900+903 (ok) or 902/904 (err) */
		WRITE(sock, "CAP END\r\n", 9);
	}

	/* block until we get a RPL_WELCOME or an error: */
	n = irc_wait(sock, outfd, b, NICK);
	if (n < 0) return n;

	if (chan) {
		n = snprintf(buf, BUFSIZ, "JOIN %s\r\n", chan);
		WRITE(sock, buf, n);

		/* block until we get a JOIN response or an error: */
		n = irc_wait(sock, outfd, b, JOIN);
		if (n < 0) return n;
	}

	return 0;
}

int irc_poll(const sock_t sock, const int infd, const int outfd, buf_t *b) {
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

		/* todo: should retry on EINTR, EAGAIN */
		if (fds[IRC].revents & POLLIN) {
			n = READ(sock, BUF(b), SIZ(b));
			if (n == 0) return -1; /* server closed connection */
			fds[IRC].events = POLLIN | (n==TLS_WANT_POLLOUT?POLLOUT:0);
			write(outfd, BUF(b), n);
			irc_terminate_buffer(b, n);
			if (irc_answer(sock, BUF(b), want_pong?PING:NO_CMD) & PING)
				want_pong = 0;
			irc_rewind_buffer(b);
			recv_ts = irc_time();
		}
		if (fds[CLI].revents & POLLIN) {
			n = read(infd, buf, BUFSIZ);
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
			fprintf(stderr, "PONG timeout\n");
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
	if (sock.tls) {
		tls_close(sock.tls);
		tls_free(sock.tls);
	}
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

	int rv, opt;
	struct sigaction act;

	buf_t b; b.off = 0;

	pass = getenv("IRC_PASSWD");
	ca_file = getenv("IRC_CAFILE");

	opterr = 0;
	while ((opt = getopt(argc, argv, "n:j:pPsSkhV")) != -1) {
		switch (opt) {
		case 'n': nick = optarg; break;
		case 'p': pass_type = SERVER_PASSWD; break;
		case 'P': pass_type = SASL_PLAIN_PASSWD; break;
		case 's': tls = USE_TLS; break;
		case 'S': tls = NO_TLS; break;
		case 'k': tls = INSECURE_TLS; break;
		case 'j': chan = optarg; break;
		case 'V': printf(PROGNAME " " VERSION "\n"); return 0;
		case 'h': irc_help(argv[0]); return 0;
		default:
			printf("unrecognized argument -%c\n", optopt);
			return 1;
		}
	}

	if (optind < argc) {
		host = argv[optind++];
	} else {
		/* too few positional arguments */
		fprintf(stderr, "missing HOST\n");
		return 1;
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
		return 1;
	}

	if (!nick || !*nick) {
		fprintf(stderr, "must provide a nick with -n\n");
		return 1;
	}

	if (pass_type != NO_PASSWD && pass == NULL) {
		fprintf(stderr, "must set IRC_PASSWD envvar to use -p/-P\n");
		return 1;
	}

	memset(&act, 0, sizeof act);
	act.sa_handler = irc_sighandler;
	sigaction(SIGHUP, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);

	sock = irc_connect(host, port, tls, ca_file); sock.fd OR_DIE;
	irc_setup(sock, 1, &b, nick, pass, pass_type, chan);
	rv = irc_poll(sock, 0, 1, &b);
	irc_cleanup(sock);

	return (rv < 0);
}
