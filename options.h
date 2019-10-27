#ifndef IPT2SOCKS_OPTIONS_H
#define IPT2SOCKS_OPTIONS_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include "netutils.h"
#include "lrucache.h"
#include "protocol.h"
#undef _GNU_SOURCE

/* option flags */
enum {
    OPTION_TCP      = 0x01 << 0, /* enable tcp */
    OPTION_UDP      = 0x01 << 1, /* enable udp */
    OPTION_IPV4     = 0x01 << 2, /* enable ipv4 */
    OPTION_IPV6     = 0x01 << 3, /* enable ipv6 */
    OPTION_DNAT     = 0x01 << 4, /* use REDIRECT instead of TPROXY (for tcp) */
    OPTION_HFCLS    = 0x01 << 5, /* gracefully close the tcp connection pair */
    OPTION_DEFAULT = OPTION_TCP | OPTION_UDP | OPTION_IPV4 | OPTION_IPV6, /* default behavior */
};

/* if verbose logging */
#define IF_VERBOSE if (g_verbose)

/* number of threads */
#define THREAD_NUMBERS_DEFAULT 1

/* udp idle timeout(sec) */
#define UDP_IDLE_TIMEO_DEFAULT 300

/* tcp socket buffer size */
#define TCP_SKBUFSIZE_MINIMUM 1024
#define TCP_SKBUFSIZE_DEFAULT 8192

/* ipt2socks bind address */
#define BIND_IPV4_DEFAULT IP4STR_LOOPBACK
#define BIND_IPV6_DEFAULT IP6STR_LOOPBACK
#define BIND_PORT_DEFAULT 60080

/* ipt2socks version string */
#define IPT2SOCKS_VERSION "ipt2socks v1.0.1 <https://github.com/zfl9/ipt2socks>"

/* tcp stream context typedef */
typedef struct {
    uv_tcp_t *client_stream;
    uv_tcp_t *socks5_stream;
    void *client_buffer;
    void *socks5_buffer;
    uv_write_t *client_wrtreq;
    uv_write_t *socks5_wrtreq;
    bool is_half_close;
} tcpcontext_t;

/* static global variable definition */
static bool g_verbose = false;
static uint8_t g_options = OPTION_DEFAULT;
static uint8_t g_nthreads = THREAD_NUMBERS_DEFAULT;
static uint32_t g_tcpbufsiz = TCP_SKBUFSIZE_DEFAULT;
static uint16_t g_udpidletmo = UDP_IDLE_TIMEO_DEFAULT;

static char g_bind_ipstr4[IP4STRLEN] = BIND_IPV4_DEFAULT;
static char g_bind_ipstr6[IP6STRLEN] = BIND_IPV6_DEFAULT;
static portno_t g_bind_portno = BIND_PORT_DEFAULT;
static skaddr4_t g_bind_skaddr4 = {0};
static skaddr6_t g_bind_skaddr6 = {0};

static bool g_server_isipv4 = true;
static char g_server_ipstr[IP6STRLEN] = {0};
static portno_t g_server_portno = 0;
static skaddr6_t g_server_skaddr = {0};

static cltcache_t *g_udp_cltcache = NULL;
static svrcache_t *g_udp_svrcache = NULL;
static char g_udp_ipstrbuf[IP6STRLEN] = {0};
static char g_udp_packetbuf[UDP_PACKET_MAXSIZE] = {0};
static char g_udp_socks5buf[SOCKS5_HDR_MAXSIZE] = {0};


static void exit_error();

static void print_command_help();

static void print_help_and_exit();

static char *read_line(FILE *f);


static void parse_option_config(const char *optarg);

static void parse_option_server_addr(const char *optarg);

static void parse_option_server_port(const char *optarg);

static void parse_option_listen_4_addr(const char *optarg);

static void parse_option_listen_6_addr(const char *optarg);

static void parse_option_listen_port(const char *optarg);

static void parse_option_thread(const char *optarg);

static void parse_option_file_limit(const char *optarg);

static void parse_option_udp_timeout(const char *optarg);

static void parse_option_cache_size(const char *optarg);

static void parse_option_buffer_size(const char *optarg);

static void parse_option_redirect();

static void parse_option_graceful();

static void parse_option_tcp_only();

static void parse_option_udp_only();

static void parse_option_ipv4_only();

static void parse_option_ipv6_only();

static void parse_option_verbose();


const char *OPTION_CONFIG = "config";
const char OPTION_SHORT_CONFIG = 'c';

const char *OPTION_SERVER_ADDR = "server-addr";
const char OPTION_SHORT_SERVER_ADDR = 's';

const char *OPTION_SERVER_PORT = "server-port";
const char OPTION_SHORT_SERVER_PORT = 'p';

const char *OPTION_LISTEN_ADDR_4 = "listen-addr4";
const char OPTION_SHORT_LISTEN_ADDR_4 = 'l';

const char *OPTION_LISTEN_ADDR_6 = "listen-addr6";
const char OPTION_SHORT_LISTEN_ADDR_6 = 'L';

const char *OPTION_LISTEN_PORT = "listen-port";
const char OPTION_SHORT_LISTEN_PORT = 'P';

const char *OPTION_THREAD = "thread";
const char OPTION_SHORT_THREAD = 'j';

const char *OPTION_FILE_LIMIT = "file-limit";
const char OPTION_SHORT_FILE_LIMIT = 'n';

const char *OPTION_UDP_TIMEOUT = "udp-timeout";
const char OPTION_SHORT_UDP_TIMEOUT = 'o';

const char *OPTION_CACHE_SIZE = "cache-size";
const char OPTION_SHORT_CACHE_SIZE = 'k';

const char *OPTION_BUFFER_SIZE = "buffer-size";
const char OPTION_SHORT_BUFFER_SIZE = 'b';

const char *OPTION_USER = "user";
const char OPTION_SHORT_USER = 'u';

const char *OPTION_GRACEFUL = "graceful";
const char OPTION_SHORT_GRACEFUL = 'G';

const char *OPTION_REDIRECT = "redirect";
const char OPTION_SHORT_REDIRECT = 'r';

const char *OPTION_TCP_ONLY = "tcp-only";
const char OPTION_SHORT_TCP_ONLY = 'T';

const char *OPTION_UDP_ONLY = "udp-only";
const char OPTION_SHORT_UDP_ONLY = 'U';

const char *OPTION_IPV4_ONLY = "ipv4-only";
const char OPTION_SHORT_IPV4_ONLY = '4';

const char *OPTION_IPV6_ONLY = "ipv6-only";
const char OPTION_SHORT_IPV6_ONLY = '6';

const char *OPTION_VERBOSE = "verbose";
const char OPTION_SHORT_VERBOSE = 'v';

const char *OPTION_VERSION = "version";
const char OPTION_SHORT_VERSION = 'V';

const char *OPTION_HELP = "help";
const char OPTION_SHORT_HELP = 'h';


/* print command help information */
static void print_command_help(void) {
    printf("usage: ipt2socks <options...>. the existing options are as follows:\n \
    -%c, --%-12s <file>    config file\n \
    -%c, --%-12s <addr>    socks5 server ip address, <required>\n \
    -%c, --%-12s <port>    socks5 server port number, <required>\n \
    -%c, --%-12s <addr>    listen ipv4 address, default: 127.0.0.1\n \
    -%c, --%-12s <addr>    listen ipv6 address, default: ::1\n \
    -%c, --%-12s <port>    listen port number, default: 60080\n \
    -%c, --%-12s <num>     number of worker threads, default: 1\n \
    -%c, --%-12s <num>     set nofile limit, may need root privilege\n \
    -%c, --%-12s <sec>     udp socket idle timeout, default: 300\n \
    -%c, --%-12s <size>    max size of udp lruc ache, default: 256\n \
    -%c, --%-12s <size>    buffer size of tcp socket, default: 8192\n \
    -%c, --%-12s <user>    run the ipt2socks with the specified user\n \
    -%c, --%-12s           gracefully close the tcp connection pair\n \
    -%c, --%-12s           use redirect instead of tproxy (for tcp)\n \
    -%c, --%-12s           listen tcp only, aka: disable udp proxy\n \
    -%c, --%-12s           listen udp only, aka: disable tcp proxy\n \
    -%c, --%-12s           listen ipv4 only, aka: disable ipv6 proxy\n \
    -%c, --%-12s           listen ipv6 only, aka: disable ipv4 proxy\n \
    -%c, --%-12s           print verbose log, default: <disabled>\n \
    -%c, --%-12s           print ipt2socks version number and exit\n \
    -%c, --%-12s           print ipt2socks help information and exit\n",
           OPTION_SHORT_CONFIG, OPTION_CONFIG,
           OPTION_SHORT_SERVER_ADDR, OPTION_SERVER_ADDR,
           OPTION_SHORT_SERVER_PORT, OPTION_SERVER_PORT,
           OPTION_SHORT_LISTEN_ADDR_4, OPTION_LISTEN_ADDR_4,
           OPTION_SHORT_LISTEN_ADDR_6, OPTION_LISTEN_ADDR_6,
           OPTION_SHORT_LISTEN_PORT, OPTION_LISTEN_PORT,
           OPTION_SHORT_THREAD, OPTION_THREAD,
           OPTION_SHORT_FILE_LIMIT, OPTION_FILE_LIMIT,
           OPTION_SHORT_UDP_TIMEOUT, OPTION_UDP_TIMEOUT,
           OPTION_SHORT_CACHE_SIZE, OPTION_CACHE_SIZE,
           OPTION_SHORT_BUFFER_SIZE, OPTION_BUFFER_SIZE,
           OPTION_SHORT_GRACEFUL, OPTION_GRACEFUL,
           OPTION_SHORT_USER, OPTION_USER,
           OPTION_SHORT_REDIRECT, OPTION_REDIRECT,
           OPTION_SHORT_TCP_ONLY, OPTION_TCP_ONLY,
           OPTION_SHORT_UDP_ONLY, OPTION_UDP_ONLY,
           OPTION_SHORT_IPV4_ONLY, OPTION_IPV4_ONLY,
           OPTION_SHORT_IPV6_ONLY, OPTION_IPV6_ONLY,
           OPTION_SHORT_VERBOSE, OPTION_VERBOSE,
           OPTION_SHORT_VERSION, OPTION_VERSION,
           OPTION_SHORT_HELP, OPTION_HELP);
}

static void exit_error() {
    exit(1);
}

static void print_help_and_exit() {
    print_command_help();
    exit_error();
};

#define LINE_LEN 512
//static const int LINE_LEN = 512;

char *read_line(FILE *f) {
    static char line[LINE_LEN];
    int len = 0;
    char ch = 0;
    while ((ch = (char) fgetc(f)) != '\n' && ch != EOF) {
        if (len == LINE_LEN) {//too long, ignore
            printf("line too long: %s", line);
            exit_error();
            return NULL;
        }
        *(line + len) = ch;
        len++;
    }
    *(line + len) = 0;
    if (len) {
        if (*(line + len - 1) == '\r') {//cut \r for \r\n
            *(line + len - 1) = 0;
        }
        return line;
    } else {
        return ch == EOF ? NULL : "";
    }
}

static void parse_option_server_addr(const char *optarg) {
    if (strlen(optarg) + 1 > IP6STRLEN) {
        printf("[parse_command_args] ip address max length is 45: %s\n", optarg);
        print_help_and_exit();
    }
    if (get_ipstr_family(optarg) == -1) {
        printf("[parse_command_args] invalid server ip address: %s\n", optarg);
        print_help_and_exit();
    }
    g_server_isipv4 = get_ipstr_family(optarg) == AF_INET;
    strcpy(g_server_ipstr, optarg);
}


static void parse_option_server_port(const char *optarg) {
    if (strlen(optarg) + 1 > PORTSTRLEN) {
        printf("[parse_command_args] port number max length is 5: %s\n", optarg);
        print_help_and_exit();
    }
    g_server_portno = strtol(optarg, NULL, 10);
    if (g_server_portno == 0) {
        printf("[parse_command_args] invalid server port number: %s\n", optarg);
        print_help_and_exit();
    }
}

void parse_option_listen_4_addr(const char *optarg) {
    if (strlen(optarg) + 1 > IP4STRLEN) {
        printf("[parse_command_args] ipv4 address max length is 15: %s\n", optarg);
        print_help_and_exit();
    }
    if (get_ipstr_family(optarg) != AF_INET) {
        printf("[parse_command_args] invalid listen ipv4 address: %s\n", optarg);
        print_help_and_exit();
    }
    strcpy(g_bind_ipstr4, optarg);
}

void parse_option_listen_6_addr(const char *optarg) {
    if (strlen(optarg) + 1 > IP6STRLEN) {
        printf("[parse_command_args] ipv6 address max length is 45: %s\n", optarg);
        print_help_and_exit();
    }
    if (get_ipstr_family(optarg) != AF_INET6) {
        printf("[parse_command_args] invalid listen ipv6 address: %s\n", optarg);
        print_help_and_exit();
    }
    strcpy(g_bind_ipstr6, optarg);
}

void parse_option_listen_port(const char *optarg) {
    if (strlen(optarg) + 1 > PORTSTRLEN) {
        printf("[parse_command_args] port number max length is 5: %s\n", optarg);
        print_help_and_exit();
    }
    g_bind_portno = strtol(optarg, NULL, 10);
    if (g_bind_portno == 0) {
        printf("[parse_command_args] invalid listen port number: %s\n", optarg);
        print_help_and_exit();
    }
}

void parse_option_thread(const char *optarg) {
    g_nthreads = strtol(optarg, NULL, 10);
    if (g_nthreads == 0) {
        printf("[parse_command_args] invalid number of worker threads: %s\n", optarg);
        print_help_and_exit();
    }
}

void parse_option_file_limit(const char *optarg) {
    set_nofile_limit(strtol(optarg, NULL, 10));
}

void parse_option_udp_timeout(const char *optarg) {
    g_udpidletmo = strtol(optarg, NULL, 10);
    if (g_udpidletmo == 0) {
        printf("[parse_command_args] invalid udp socket idle timeout: %s\n", optarg);
        print_help_and_exit();
    }
}

void parse_option_cache_size(const char *optarg) {
    if (strtol(optarg, NULL, 10) == 0) {
        printf("[parse_command_args] invalid maxsize of udp lrucache: %s\n", optarg);
        print_help_and_exit();
    }
    lrucache_set_maxsize(strtol(optarg, NULL, 10));
}

void parse_option_buffer_size(const char *optarg) {
    g_tcpbufsiz = strtol(optarg, NULL, 10);
    if (g_tcpbufsiz < TCP_SKBUFSIZE_MINIMUM) {
        printf("[parse_command_args] buffer should have at least 1024B: %s\n", optarg);
        print_help_and_exit();
    }
}

void parse_option_redirect() {
    g_options |= OPTION_DNAT;
    strcpy(g_bind_ipstr4, IP4STR_WILDCARD);
    strcpy(g_bind_ipstr6, IP6STR_WILDCARD);
}

void parse_option_graceful() {
    g_options |= OPTION_HFCLS;
}

void parse_option_tcp_only() {
    g_options &= ~OPTION_UDP;
}

void parse_option_udp_only() {
    g_options &= ~OPTION_TCP;
}

void parse_option_ipv4_only() {
    g_options &= ~OPTION_IPV6;
}

void parse_option_ipv6_only() {
    g_options &= ~OPTION_IPV4;
}


void parse_option_config(const char *optarg) {
    FILE *f = fopen(optarg, "r");
    if (f == NULL) {
        printf("[parse_command_args] cannot open config file %s\n", optarg);
        exit_error();
    }
    const char *line = read_line(f);
    while (line) {
        if (*line && *line != '#') {
            char *str = strdup(line);
            char *value = str;
            char *key = strsep(&value, " ");
            if (!strcmp(key, OPTION_SERVER_ADDR)) {
                parse_option_server_addr(value);
            } else if (!strcmp(key, OPTION_SERVER_PORT)) {
                parse_option_server_port(value);
            } else if (!strcmp(key, OPTION_LISTEN_ADDR_4)) {
                parse_option_listen_4_addr(value);
            } else if (!strcmp(key, OPTION_LISTEN_ADDR_6)) {
                parse_option_listen_6_addr(value);
            } else if (!strcmp(key, OPTION_LISTEN_PORT)) {
                parse_option_listen_port(value);
            } else if (!strcmp(key, OPTION_THREAD)) {
                parse_option_thread(value);
            } else if (!strcmp(key, OPTION_FILE_LIMIT)) {
                parse_option_file_limit(value);
            } else if (!strcmp(key, OPTION_UDP_TIMEOUT)) {
                parse_option_udp_timeout(value);
            } else if (!strcmp(key, OPTION_CACHE_SIZE)) {
                parse_option_cache_size(value);
            } else if (!strcmp(key, OPTION_BUFFER_SIZE)) {
                parse_option_buffer_size(value);
            } else if (!strcmp(key, OPTION_REDIRECT)) {
                parse_option_redirect();
            } else if (!strcmp(key, OPTION_GRACEFUL)) {
                parse_option_graceful();
            } else if (!strcmp(key, OPTION_TCP_ONLY)) {
                parse_option_tcp_only();
            } else if (!strcmp(key, OPTION_UDP_ONLY)) {
                parse_option_udp_only();
            } else if (!strcmp(key, OPTION_IPV4_ONLY)) {
                parse_option_ipv4_only();
            } else if (!strcmp(key, OPTION_IPV6_ONLY)) {
                parse_option_ipv6_only();
            } else if (!strcmp(key, OPTION_VERBOSE)) {
                parse_option_verbose();
            }
            free(str);
        }
        line = read_line(f);
    }
}

void parse_option_verbose() {
    g_verbose = true;
}

/* parsing command line arguments */
static void parse_command_args(int argc, char *argv[]) {
    const struct option options[] = {
            {OPTION_CONFIG,        required_argument, NULL, OPTION_SHORT_CONFIG},
            {OPTION_SERVER_ADDR,   required_argument, NULL, OPTION_SHORT_SERVER_ADDR},
            {OPTION_SERVER_PORT,   required_argument, NULL, OPTION_SHORT_SERVER_PORT},
            {OPTION_LISTEN_ADDR_4, required_argument, NULL, OPTION_SHORT_LISTEN_ADDR_4},
            {OPTION_LISTEN_ADDR_6, required_argument, NULL, OPTION_SHORT_LISTEN_ADDR_6},
            {OPTION_LISTEN_PORT,   required_argument, NULL, OPTION_SHORT_LISTEN_PORT},
            {OPTION_THREAD,        required_argument, NULL, OPTION_SHORT_THREAD},
            {OPTION_FILE_LIMIT,    required_argument, NULL, OPTION_SHORT_FILE_LIMIT},
            {OPTION_UDP_TIMEOUT,   required_argument, NULL, OPTION_SHORT_UDP_TIMEOUT},
            {OPTION_CACHE_SIZE,    required_argument, NULL, OPTION_SHORT_CACHE_SIZE},
            {OPTION_BUFFER_SIZE,   required_argument, NULL, OPTION_SHORT_BUFFER_SIZE},
            {OPTION_USER,          required_argument, NULL, OPTION_SHORT_USER},
            {OPTION_REDIRECT,      no_argument,       NULL, OPTION_SHORT_REDIRECT},
            {OPTION_TCP_ONLY,      no_argument,       NULL, OPTION_SHORT_TCP_ONLY},
            {OPTION_UDP_ONLY,      no_argument,       NULL, OPTION_SHORT_UDP_ONLY},
            {OPTION_IPV4_ONLY,     no_argument,       NULL, OPTION_SHORT_IPV4_ONLY},
            {OPTION_IPV6_ONLY,     no_argument,       NULL, OPTION_SHORT_IPV6_ONLY},
            {OPTION_VERBOSE,       no_argument,       NULL, OPTION_SHORT_VERBOSE},
            {OPTION_VERSION,       no_argument,       NULL, OPTION_SHORT_VERSION},
            {OPTION_HELP,          no_argument,       NULL, OPTION_SHORT_HELP},
            {NULL, 0,                                 NULL, 0},
    };

    const char *optstr = ":c:s:p:l:L:P:j:n:o:k:b:u:GRTU46vVh";
    opterr = 0;
    int optindex = -1;
    int shortopt;
    while ((shortopt = getopt_long(argc, argv, optstr, options, &optindex)) != -1) {
        switch (shortopt) {
            case 'c':
                parse_option_config(optarg);
                break;
            case 's':
                parse_option_server_addr(optarg);
                break;
            case 'p':
                parse_option_server_port(optarg);
                break;
            case 'l':
                parse_option_listen_4_addr(optarg);
                break;
            case 'L':
                parse_option_listen_6_addr(optarg);
                break;
            case 'P':
                parse_option_listen_port(optarg);
                break;
            case 'j':
                parse_option_thread(optarg);
                break;
            case 'n':
                parse_option_file_limit(optarg);
                break;
            case 'o':
                parse_option_udp_timeout(optarg);
                break;
            case 'k':
                parse_option_cache_size(optarg);
                break;
            case 'b':
                parse_option_buffer_size(optarg);
                break;
            case 'u':
                run_as_user(optarg, argv);
            case 'G':
                parse_option_graceful();
                break;
            case 'R':
                parse_option_redirect();
                break;
            case 'T':
                parse_option_tcp_only();
                break;
            case 'U':
                parse_option_udp_only();
                break;
            case '4':
                parse_option_ipv4_only();
                break;
            case '6':
                parse_option_ipv6_only();
                break;
            case 'v':
                parse_option_verbose();
                break;
            case 'V':
                printf(IPT2SOCKS_VERSION"\n");
                exit(0);
            case 'h':
                print_command_help();
                exit(0);
            case ':':
                printf("[parse_command_args] missing optarg: '%s'\n", argv[optind - 1]);
                print_help_and_exit();
            case '?':
                if (optopt) {
                    printf("[parse_command_args] unknown option: '-%c'\n", optopt);
                } else {
                    char *longopt = argv[optind - 1];
                    char *equalsign = strchr(longopt, '=');
                    if (equalsign) *equalsign = 0;
                    printf("[parse_command_args] unknown option: '%s'\n", longopt);
                }
                print_help_and_exit();
        }
    }

    if (strlen(g_server_ipstr) == 0) {
        printf("[parse_command_args] missing option: '-%c/--%s'\n", OPTION_SHORT_SERVER_ADDR, OPTION_SERVER_ADDR);
        print_help_and_exit();
    }
    if (g_server_portno == 0) {
        printf("[parse_command_args] missing option: '-%c/--%s'\n", OPTION_SHORT_SERVER_PORT, OPTION_SERVER_PORT);
        print_help_and_exit();
    }

    if (!(g_options & (OPTION_TCP | OPTION_UDP))) {
        printf("[parse_command_args] both tcp and udp are disabled, nothing to do\n");
        print_help_and_exit();
    }
    if (!(g_options & (OPTION_IPV4 | OPTION_IPV6))) {
        printf("[parse_command_args] both ipv4 and ipv6 are disabled, nothing to do\n");
        print_help_and_exit();
    }

    if (!(g_options & OPTION_TCP)) g_nthreads = 1;

    build_ipv4_addr(&g_bind_skaddr4, g_bind_ipstr4, g_bind_portno);
    build_ipv6_addr(&g_bind_skaddr6, g_bind_ipstr6, g_bind_portno);

    if (g_server_isipv4) {
        build_ipv4_addr((void *) &g_server_skaddr, g_server_ipstr, g_server_portno);
    } else {
        build_ipv6_addr((void *) &g_server_skaddr, g_server_ipstr, g_server_portno);
    }
}

#endif //IPT2SOCKS_OPTIONS_H
