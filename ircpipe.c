#define _POSIX_C_SOURCE 200809L /* getopt(>=2), gethostbyname(>=200809L), dprintf(>=200809L), strtok_r(*) */
#define _DEFAULT_SOURCE /* herror(*) */
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#ifndef NO_TLS
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#define DEFAULT_PORT 6667
#define DEFAULT_PING 60000 /*ms*/
#define DEFAULT_TIMEOUT 2000 /*ms*/
#define DEFAULT_TLS 0 /*off*/

#define POLL_TIMEOUT 100

#define STR_(x) #x
#define STR(x) STR_(x)
#define OR_DIE < 0 && (perror(__FILE__ ":" STR(__LINE__)), exit(1), 0)
#define OR_DIE_h == NULL && (herror(__FILE__ ":" STR(__LINE__)), exit(1), 0)

void irc_help(const char *exe, const int code) {
	fprintf(stderr, "Usage: %s [-n NICK] [-j CHAN] HOST [PORT]\n", exe);
	exit(code);
}

int irc_connect(const char *host, const unsigned short port) {
	int sockfd;
	struct sockaddr_in addr = {0};
	struct hostent *host_e;

	host_e = gethostbyname(host); host_e OR_DIE_h;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr = *((struct in_addr *)host_e->h_addr_list[0]);

	sockfd = socket(AF_INET, SOCK_STREAM, 0); sockfd OR_DIE;
	/* tls here */
	/* connect timeout here */
	connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) OR_DIE;
	return sockfd;
}

enum { /* requested command: */
	NO_CMD = 1<<0,
	NICK = 1<<1,
	PING = 1<<2
};
int irc_answer(const int sockfd, char *buf, const unsigned int command) {
	unsigned int seen = 0;
	char *saveptr;
	char *line = strtok_r(buf, "\n", &saveptr);
	do {
		/* skip over prefix (servername): */
		if (line[0] == ':')
			while (*line++ != ' ');

		printf("\033[92m>>>%s<<<\033[0m\n", line);
		/* look for command responses, if any: */
		switch (command) {
		case PING: seen |= PING * (strncmp(line, "PONG ", 5)==0); break;
		case NICK: seen |= NICK * (strncmp(line, "001 " , 4)==0); break;
		}

		/* reply to pings: */
		if (strncmp(line, "PING ", 5) == 0) {
			line[1] = 'O'; /* PING :foo -> PONG :foo */
			write(sockfd, line, strlen(line));
			write(sockfd, "\r\n", 2);
		}
	} while (line = strtok_r(NULL, "\n", &saveptr));

	printf("\033[91mseen=%d\033[0m\n", seen);
	return seen;
}

int irc_base64(char *buf, int n) {
	const char *b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	int i, o, v, l = ((n+(3-n%3)%3)/3)*4;
	if (l >= 400) return -1; /* lazy */
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

int irc_setup(const int sockfd, const int outfd, const char *nick, const char *pass, const char *chan) {
	char buf[BUFSIZ];
	int n;
	struct pollfd fds[1];
	fds[0].fd = sockfd;
	fds[0].events = POLLIN;

	if (pass) { /* SASL as per IRCv3 */
		dprintf(sockfd, "CAP REQ :sasl\r\n");
	}

	dprintf(sockfd, "NICK %s\r\n", nick);
	dprintf(sockfd, "USER %s 0.0.0.0 %s :%s\r\n", nick, nick, nick);

	/* SASL-PLAIN, IRCv3 */
	if (pass) {
		/* should wait for 'CAP <nick|*> ACK :<...>' */
		dprintf(sockfd, "AUTHENTICATE PLAIN\r\n");
		/* server sends 'AUTHENTICATE +' */
		/* split base64-output into 400 byte chunks; if last is exactly
		   400 bytes, send empty msg ('+') afterwards */
		n = snprintf(buf, BUFSIZ, "%s%c%s%c%s", nick, 0, nick, 0, pass);
		irc_base64(buf, n) OR_DIE;
		dprintf(sockfd, "AUTHENTICATE %s\r\n", buf);
		/* wait for response 900+903 (ok) or 904 (err) */
		dprintf(sockfd, "CAP END\r\n");
	}

	/* block until we get a RPL_WELCOME: */
	for (;;) {
		if (poll(fds, 1, POLL_TIMEOUT)) {
			n = read(sockfd, buf, BUFSIZ);
			write(outfd, buf, n);
			if (irc_answer(sockfd, buf, NICK) & NICK) break;
		}
	}

	if (chan) {
		dprintf(sockfd, "JOIN %s\r\n", chan);
	}

	return 0;
}

int irc_poll(const int sockfd, const int infd, const int outfd) {
	int n;
	char buf[BUFSIZ];
	enum { IRC, CLI };
	struct pollfd fds[2];
	fds[IRC].fd = sockfd;
	fds[IRC].events = POLLIN;
	fds[CLI].fd = sockfd;
	fds[CLI].events = POLLIN;

	for (;;) {
		poll(fds, 2, POLL_TIMEOUT) OR_DIE;

		/* XXX: long responses don't get fully processed until user input */
		if (fds[IRC].revents & POLLIN) {
			n = read(sockfd, buf, BUFSIZ);
			if (n == 0) return -1; /* server closed connection */
			write(outfd, buf, n);
			irc_answer(sockfd, buf, NO_CMD);
			/* update last-msg-rcvd here */
		}
		if (fds[CLI].revents & POLLIN) {
			n = read(infd, buf, BUFSIZ);
			if (n == 0) return 0; /* we closed connection */
			write(sockfd, buf, n);
		}

		/* send ping here */
		/*
		dprintf(sockfd, "PING\r\n");
		// poll-read
		if (irc_answer(sockfd, buf, NICK) & NICK) break;
		*/
	}
}

void irc_cleanup(const int sockfd) {
	write(sockfd, "QUIT :ircpipe\r\n", 15);
	shutdown(sockfd, SHUT_RDWR);
	close(sockfd);
}

int main(int argc, char **argv) {
	char *host = NULL;
	char *nick = NULL;
	char *pass = NULL;
	char *chan = NULL;
	unsigned short port = DEFAULT_PORT;
	size_t ping_iv = DEFAULT_PING;  /* interval between outgoing pings */
	size_t resp_to = DEFAULT_TIMEOUT; /* how long to wait for command response (connect, ping, auth, ...) */
	int tls = DEFAULT_TLS;

	int sockfd;
	int rv;

	int opt; opterr = 0;
	while ((opt = getopt(argc, argv, "n:j:psh")) != -1) {
		switch (opt) {
		case 'n': nick = optarg; break;
		case 'p': pass = getenv("IRC_PASSWD"); break;
		case 's': tls = 1; break;
		case 'S': tls = 0; break;
		case 'j': chan = optarg; break;
		default: irc_help(argv[0], opt != 'h');
		}
	}

	if (optind < argc) {
		host = argv[optind++];
	} else {
		/* too few positional arguments */
		irc_help(argv[0], 1);
	}
	if (optind < argc) {
		port = atoi(argv[optind++]);
	}
	if (optind < argc) {
		/* too many positional arguments */
		irc_help(argv[0], 1);
	}

	printf("\033[91mconnecting to %s:%hd as %s, joining %s\033[0m\n", host, port, nick, chan);
	sockfd = irc_connect(host, port); sockfd OR_DIE;
	printf("\033[91mirc_setup...\033[0m\n", host, port, nick, chan);
	irc_setup(sockfd, 1, nick, pass, chan) OR_DIE;
	printf("\033[91mirc_poll...\033[0m\n", host, port, nick, chan);
	rv = irc_poll(sockfd, 0, 1);
	irc_cleanup(sockfd);

	return (rv < 0);
}
