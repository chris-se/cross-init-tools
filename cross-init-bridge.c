#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/time.h>
#include <getopt.h>
#include <stdint.h>
#include <fcntl.h>

#include <dbus/dbus.h>

#ifndef UNIX_MAX_PATH
#define UNIX_MAX_PATH 108
#endif

#define CROSS_INIT_BRIDGE_VERSION   "0.1"

#define SYSTEMD_UNIT_PATH         "/run/systemd/system/"
#define UPSTART_ABSTRACT_SOCKET   "/com/ubuntu/upstart"

#define SD_LISTEN_FDS_START       3

typedef enum {
  INIT_SYSTEMD = 0,
  INIT_UPSTART = 1,
  INIT_OTHER   = 2,
} init_system_t;

static volatile int caught_sigterm = 0;

static int bridge_systemd_to_upstart(int notify, char *unit, char **argv);
static int bridge_upstart_to_systemd(int notify, int end_after_ready, char **argv);
static int setup_sigstop_waiter(char *notify_socket);
static int setup_sd_notify_waiter(int end_after_ready);

static void setup_sighandlers();

static void handle_sigterm(int);

static void show_help(const char *progname)
{
  printf("Usage: %s -t TARGET [-N] -- COMMAND\n\n", progname);
  printf("Bridge different init system interfaces.\n\n");
  printf("Options:\n");
  printf("  -t TARGET          The target init system ('systemd', 'upstart')\n");
  printf("                     The currently running init system is autodetected.\n");
  printf("  -N                 Also enable readiness notifications.\n");
  printf("  --end-after-ready  If daemon supporting systemd style readiness\n");
  printf("                     has signaled once, stop helper process. This assumes\n");
  printf("                     that the daemon will only signal readiness and not use\n");
  printf("                     the systemd notification interface further. If that is not\n");
  printf("                     the case and the daemon signals multiple times, this might\n");
  printf("                     pose the threat of a minor denial of service.\n");
}

static void show_version(const char *progname)
{
  printf("%s Version %s\n", progname, CROSS_INIT_BRIDGE_VERSION);
}

static int detect_init()
{
  /* currently, systemd only runs on linux (and will so for the forseeable future),
   * and while upstart is a bit more likely to run somewhere else, the method of
   * detecting, i.e. abstract local sockets, is linux-specific, so even if at some
   * point upstart might run on some other kernel, this code will have to be
   * touched regardless, so just keep it linux specific for now... */
#if defined(__linux__)
  struct stat st;

  /* sd_booted(3) does essentially the same thing */
  if (lstat(SYSTEMD_UNIT_PATH, &st) == 0) {
    if (S_ISDIR(st.st_mode))
      return INIT_SYSTEMD;
  }

  /* we detect upstart by the presence of the /com/ubuntu/upstart abstract socket */
  {
    int s;
    int r;
    struct sockaddr_un addr;

    s = socket(PF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0)
      /* strictly speaking, if this fails, we technically didn't rule out upstart;
       * however, this call should basically always work unless something is *really*
       * wrong */
      goto other;

    addr.sun_family = AF_LOCAL;
    addr.sun_path[0] = '\0';
    strcpy(addr.sun_path+1, UPSTART_ABSTRACT_SOCKET);

    /* we don't use non-block here, because we assume that it won't hang for too
     * long at this point... */
    r = connect(s , (struct sockaddr *)&addr, sizeof(sa_family_t) + 1 + strlen(UPSTART_ABSTRACT_SOCKET));

    /* immediately close the socket, since we don't want to do
     * anything with it */
    close(s);
    
    /* connection worked, we're running upstart (probably) */
    if (r == 0)
      return INIT_UPSTART;
  }
#endif /* defined(__linux__) */

other:
  return INIT_OTHER;
}

static char *get_systemd_unit(pid_t pid_)
{
  DBusError error;
  DBusConnection *conn;
  DBusMessage *msg;
  DBusMessage *reply;
  DBusMessageIter iter, subiter;
  char *result = NULL;
  char *object = NULL;
  static const char *iface_name = "org.freedesktop.systemd1.Unit";
  static const char *property_name = "Id";
  
  uint32_t pid = (uint32_t)pid_;

  dbus_error_init(&error);
  conn = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
  if (conn == NULL)
    return NULL;

  if (!dbus_bus_name_has_owner(conn, "org.freedesktop.systemd1", &error) || dbus_error_is_set(&error))
    goto unref_conn;

  msg = dbus_message_new_method_call("org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "GetUnitByPID");
  if (!msg)
    goto unref_conn;

  dbus_message_append_args(msg, DBUS_TYPE_UINT32, &pid, DBUS_TYPE_INVALID);

  reply = dbus_connection_send_with_reply_and_block(conn, msg, DBUS_TIMEOUT_USE_DEFAULT, &error);
  if (!reply || dbus_error_is_set(&error))
    goto unref_msg;

  dbus_message_get_args(reply, &error, DBUS_TYPE_OBJECT_PATH, &object, DBUS_TYPE_INVALID);
  if (!object || dbus_error_is_set(&error))
    goto unref_reply;

  object = strdup(object);
  
  dbus_message_unref(reply);
  dbus_message_unref(msg);
  
  msg = dbus_message_new_method_call("org.freedesktop.systemd1", object, "org.freedesktop.DBus.Properties", "Get");
  if (!msg)
    goto unref_conn;

  dbus_message_append_args(msg, DBUS_TYPE_STRING, &iface_name, DBUS_TYPE_STRING, &property_name, DBUS_TYPE_INVALID);

  reply = dbus_connection_send_with_reply_and_block(conn, msg, DBUS_TIMEOUT_USE_DEFAULT, &error);
  if (!reply || dbus_error_is_set(&error))
    goto unref_msg;

  /* org.freedesktop.DBus.Properties.Get packs stuff in a variant,
   * so this is a bit ugly... */
  dbus_message_iter_init(reply, &iter);
  dbus_message_iter_recurse(&iter, &subiter);
  if (DBUS_TYPE_STRING == dbus_message_iter_get_arg_type(&subiter))
    dbus_message_iter_get_basic(&subiter, &result);

  if (result)
    result = strdup(result);

unref_reply:
  dbus_message_unref(reply);
unref_msg:
  dbus_message_unref(msg);
unref_conn:
  free(object);
  dbus_connection_unref(conn);
  return result;
}

int main(int argc, char **argv)
{
  int init_system = -1;
  int target_init_system = -1;
  int notify = 0;
  int end_after_ready = 0;
  char *unit = NULL;

  init_system = detect_init();

  if (init_system == INIT_OTHER) {
    fprintf(stderr, "%s: requires systemd or upstart is init system to work, neither detected\n", argv[0]);
    return 1;
  }

  while (1) {
    int option_index = 0;
    int c;

    enum {
      END_AFTER_READY = 512,
    };

    static struct option long_options[] = {
      { "help",            no_argument,       0,   'h'             },
      { "version",         no_argument,       0,   'V'             },
      { "target",          required_argument, 0,   't'             },
      { "notify",          no_argument,       0,   'N'             },
      { "end-after-ready", no_argument,       0,   END_AFTER_READY },
      { NULL,              0,                 0,   0               }
    };

    c = getopt_long(argc, argv, "hVt:N", long_options, &option_index);
    if (c == -1)
      break;

    switch (c) {
      case 'h':
        show_help(argv[0]);
        return 0;
      case 'V':
        show_version(argv[0]);
        return 0;
      case 'N':
        notify = 1;
        break;
      case END_AFTER_READY:
        end_after_ready = 1;
        break;
      case 't':
        if (strcmp(optarg, "upstart") == 0) {
          target_init_system = INIT_UPSTART;
        } else if (strcmp(optarg, "systemd") == 0) {
          target_init_system = INIT_SYSTEMD;
        } else {
          fprintf(stderr, "%s: invalid target '%s', valid targets are 'upstart' and 'systemd'\n", argv[0], optarg);
          return 1;
        }
        break;
      default:
        fprintf(stderr, "%s: internal option paring error, getopt returned %d ('%c')\n", argv[0], c, (char) c);
        return 1;
    }
  }
  
  if (optind == argc) {
    fprintf(stderr, "%s: no command specified; usage: %s -t target -- command\n", argv[0], argv[0]);
    return 1;
  }

  if (target_init_system < 0) {
    fprintf(stderr, "%s: no target specified; usage: %s -t target -- command\n", argv[0], argv[0]);
    return 1;
  }

  /* some sanity checks, in case somebody tries something as stupid as
   * cross-init-bridge -t upstart -- cross-init-bridge -t systemd -- exectuable
   * on a systemd system... */
  if (init_system == INIT_UPSTART && !getenv("UPSTART_JOB")) {
    fprintf(stderr, "%s: init system is upstart, but we were apparently not called from upstart (UPSTART_JOB not set), aborting\n", argv[0]);
    return 1;
  }
  if (init_system == INIT_SYSTEMD && getenv("UPSTART_JOB")) {
    fprintf(stderr, "%s: init system is systemd, but we were apparently called from upstart context (UPSTART_JOB set), i.e. via this same bridge, aborting\n", argv[0]);
    return 1;
  }

  if (target_init_system == init_system) {
    /* it is kind of stupid that we're called this way, but whatever,
     * just make it a no-op */
    execv(argv[optind], &argv[optind]);
    fprintf(stderr, "%s: could not execute %s: %s\n", argv[0], argv[optind], strerror(errno));
    return 1;
  }

  /* try to get systemd unit for our own PID */
  if (init_system == INIT_SYSTEMD)
    unit = get_systemd_unit(getpid());

  /* different cases */
  if (init_system == INIT_SYSTEMD && target_init_system == INIT_UPSTART)
    return bridge_systemd_to_upstart(notify, unit, &argv[optind]);
  else if (init_system == INIT_UPSTART && target_init_system == INIT_SYSTEMD)
    return bridge_upstart_to_systemd(notify, end_after_ready, &argv[optind]);

  /* this code path should NEVER be reached, but just in case... */
  fprintf(stderr, "%s: can only translate between upstart <-> systemd at the moment\n", argv[0]);
  fprintf(stderr, "(detected init system = %d, target init system = %d)\n", init_system, target_init_system);
  fprintf(stderr, "(systemd == %d, upstart == %d, other == %d)\n", INIT_SYSTEMD, INIT_UPSTART, INIT_OTHER);
  return 1;
}

int bridge_systemd_to_upstart(int notify, char *unit, char **argv)
{
  /* running system: systemd, target == upstart */

  char *p_ = getenv("LISTEN_PID");
  char *f_ = getenv("LISTEN_FDS");
  char *n_ = getenv("NOTIFY_SOCKET");
  char *endptr = NULL;
  unsigned long value;
  char buf[4096];
  struct sockaddr_storage ss;
  socklen_t socklen;
  int r;

  if (p_)
    p_ = strdup(p_);
  if (f_)
    f_ = strdup(f_);
  if (n_)
    n_ = strdup(n_);

  unsetenv("LISTEN_PID");
  unsetenv("LISTEN_FDS");
  unsetenv("NOTIFY_SOCKET");

  if (!p_)
    goto done_sockets;

  endptr = NULL;
  value = strtoul(p_, &endptr, 10);
  if (!*p_ || !endptr || *endptr) {
    fprintf(stderr, "[systemd -> upstart bridge] invalid LISTEN_PID passed from systemd: '%s'\n", p_);
    return 1;
  }

  if (value != (unsigned long)getpid())
    goto done_sockets;

  if (!f_) {
    fprintf(stderr, "[systemd -> upstart bridge] LISTEN_PID set but LISTEN_FDS is not\n");
    return 1;
  }

  endptr = NULL;
  value = strtoul(f_, &endptr, 10);
  if (!*f_ || !endptr || *endptr) {
    fprintf(stderr, "[systemd -> upstart bridge] invalid LISTEN_FDS passed from systemd: '%s'\n", f_);
    return 1;
  }

  if (value == 0)
    goto done_sockets;

  if (value > 1) {
    fprintf(stderr, "[systemd -> upstart bridge] upstart's protocol currently only supports passing of one socket, %d passed from systemd\n", (int)value);
    return 1;
  }

  /* try to determine socket type */
  socklen = sizeof(ss);
  r = getsockname(SD_LISTEN_FDS_START, (struct sockaddr *)&ss, &socklen);
  if (r < 0) {
    /* systemd also supports FIFOs, so if the FD passed is not a socket, check if
     * that is the case, so the user gets a better error message. */
    if (errno == ENOTSOCK) {
      struct stat st;
      r = fstat((int)value, &st);
      if (r == 0 && S_ISFIFO(st.st_mode)) {
        fprintf(stderr, "[systemd -> upstart bridge] upstart's protocols only supports sockets, but FIFO handed from systemd\n");
        return 1;
      }
      errno = ENOTSOCK;
    }
    fprintf(stderr, "[systemd -> upstart bridge] could not getsockname() of socket passed from systemd: %s\n", strerror(errno));
    return 1;
  }

  /* FIXME: maybe we should just silently let AF_INET6 sockets pass, so that
   *        upstart-enabled daemons may actually work better under systemd..
   *        But for now, stick to the specs. */
  if (ss.ss_family != AF_INET && ss.ss_family != AF_LOCAL) {
    fprintf(stderr, "[systemd -> upstart bridge] socket passed from systemd is not IPv4 or UNIX, but upstart protocol doesn't support anything else.\n");
    return 1;
  }

  /* we pass the listening socket to the daemon upstart-style */
  snprintf(buf, sizeof(buf), "%d", SD_LISTEN_FDS_START);
  setenv("UPSTART_FDS", buf, /* overwrite = */ 1);

done_sockets:
  free(p_);
  free(f_);

  if (!notify || !n_)
    goto done_notify;

  if (n_[0] != '@' && n_[0] != '/') {
    fprintf(stderr, "[systemd -> upstart bridge] notify socket passed from systemd is not an absolute path or an abstract socket: '%s'\n", n_);
    return 1;
  }
  if (strlen(n_) >= UNIX_MAX_PATH) {
    fprintf(stderr, "[systemd -> upstart bridge] notify socket passed from systemd is too long: '%s' (max %d allowed)\n", n_, UNIX_MAX_PATH);
    return 1;
  }

  r = setup_sigstop_waiter(n_);
  if (r < 0) {
    fprintf(stderr, "[systemd -> upstart bridge] internal error\n");
    return 1;
  }
  
done_notify:
  free(n_);

  if (unit) {
    /* remove ending (i.e. ".service" etc.) */
    p_ = strrchr(unit, '.');
    if (p_)
      *p_ = '\0';
    setenv("UPSTART_JOB", unit, /* overwrite = */ 1);
  } else {
    /* well, it beats not setting it, but it's strange that we didn't get
     * a unit from systemd (although if some restrictions in the unit file
     * were made, such as namespacing, this is in the realm of possibilities) */
    char *p = strrchr(argv[0], '/');
    if (p)
      p++;
    else
      p = argv[0];
    setenv("UPSTART_JOB", p, /* overwrite = */ 1);
  }

  execv(argv[0], &argv[0]);
  fprintf(stderr, "[systemd -> upstart bridge] could not execute %s: %s\n", argv[0], strerror(errno));
  return 1;
}

int setup_sigstop_waiter(char *notify_socket)
{
  pid_t child_pid, pid;
  int status;
  int s;
  struct sockaddr_un addr;
  ssize_t sent;
  char buf[256];

  /* create a child process that we'll wait on */
  child_pid = fork();
  if (child_pid < 0)
    return -1;

  if (child_pid == 0) {
    /* we are the child, which will execute the daemon itself, so return
     * to the caller */
    return 0;
  }

  /* we are now the parent, so we will wait for the child either
   * dying (failure) or raising SIGSTOP, which will then cause us
   * to notify systemd of success. afterwards, we will exit */
retry:
  pid = waitpid(child_pid, &status, WUNTRACED);
  if (pid < 0) {
    if (errno == EINTR)
      goto retry;
    /* oh, this is really weird, this shouldn't happen...
     * oh well, kill the child and exit ourselves */
    kill(child_pid, SIGTERM);
    exit(1);
  }

  /* child is now either in stopped state (upstart notification protocol)
   * or it has exited for some reason. first, deal with the error case */

  if (WIFEXITED(status))
    exit(WEXITSTATUS(status));
  if (WIFSIGNALED(status)) {
    /* shouldn't be the case, but you never know... */
    if (WTERMSIG(status) != SIGSTOP)
      raise(WTERMSIG(status));

    /* just in case something weird happened */
    raise(SIGTERM);
    exit(1);
  }

  if (!WIFSTOPPED(status))
    goto kill_child_if_internal_error;

  /* child is now stopped, so they are signaling us that they
   * are finished with initialization, so go on to signal systemd */
  s = socket(AF_LOCAL, SOCK_DGRAM, 0);
  if (s < 0)
    goto kill_child_if_internal_error;

  snprintf(buf, sizeof(buf), "READY=1\nMAINPID=%lu", (unsigned long) child_pid);

  addr.sun_family = AF_LOCAL;
  snprintf(addr.sun_path, UNIX_MAX_PATH, "%s", notify_socket);
  if (notify_socket[0] == '@')
    addr.sun_path[0] = '\0';

retry_signal:
  sent = sendto(s, buf, strlen(buf), MSG_NOSIGNAL, (struct sockaddr *)&addr, sizeof(sa_family_t) + strlen(notify_socket));
  if (sent < 0) {
    if (errno == -EINTR)
      goto retry_signal;
    fprintf(stderr, "[systemd -> upstart bridge] could not send readiness signal to systemd: %s\n", strerror(errno));
    close(s);
    goto kill_child_if_internal_error;
  }
  close(s);

  /* now that systemd knows that the service is running, send SIGCONT, so that 
   * it may continue */
  kill(child_pid, SIGCONT);

  /* just for good measure, wait a bit before we terminate, just in case
   * events aren't ordered properly */
  sleep(1);

  exit(0);
  return 0; /* to keep compiler happy */
  
kill_child_if_internal_error:
  /* we hope this doesn't happen at all, but just to be safe,
   * we have to get rid of the child if something in our code
   * fails... */
  kill(child_pid, SIGTERM);
  kill(child_pid, SIGCONT);
  exit(1);
  return 1;
}

int bridge_upstart_to_systemd(int notify, int end_after_ready, char **argv)
{
  char *f_ = getenv("UPSTART_FDS");
  char *endptr = NULL;
  unsigned long value;
  char buf[4096];
  struct sockaddr_storage ss;
  socklen_t socklen;
  int r;

  if (f_)
    f_ = strdup(f_);

  /* unfortunately, we have no way of emulating systemd's method of determining
   * the unit for a given PID... */
  unsetenv("UPSTART_JOB");
  unsetenv("UPSTART_FDS");

  if (!f_)
    goto done_sockets;

  endptr = NULL;
  value = strtoul(f_, &endptr, 10);
  if (!*f_ || !endptr || *endptr) {
    fprintf(stderr, "[upstart -> systemd bridge] invalid UPSTART_FDS passed from systemd: '%s'\n", f_);
    return 1;
  }

  if (value <= 2) {
    fprintf(stderr, "[upstart -> systemd bridge] UPSTART_FDS must be a file descriptor >= 3, got %d instead\n", (int)value);
    return 1;
  }

  /* try to determine socket type */
  socklen = sizeof(ss);
  r = getsockname((int)value, (struct sockaddr *)&ss, &socklen);
  if (r < 0) {
    fprintf(stderr, "[upstart -> systemd bridge] could not getsockname() of socket passed from upstart: %s\n", strerror(errno));
    return 1;
  }

  if (ss.ss_family != AF_INET && ss.ss_family != AF_LOCAL) {
    fprintf(stderr, "[upstart -> systemd bridge] socket passed from upstart is not IPv4 or UNIX, that shouldn't happen.\n");
    return 1;
  }

  /* we have to move the file descriptor around */
  if ((int)value != SD_LISTEN_FDS_START) {
    /* first check that target fd is empty, it should be... */
    struct stat st;
    r = fstat(SD_LISTEN_FDS_START, &st);
    if (r == 0) {
      fprintf(stderr, "[upstart -> systemd bridge] systemd's protocol requires fd #%d to be the first socket passed to the daemon, but upstart already put some other thing there, aboting.\n", SD_LISTEN_FDS_START);
      return 1;
    }
    if (r < 0 && errno != EBADF) {
      fprintf(stderr, "[upstart -> systemd bridge] internal error determining if fd #%d is free: %s.\n", SD_LISTEN_FDS_START, strerror(errno));
      return 1;
    }
    /* now dup the fd */
    r = dup2((int)value, SD_LISTEN_FDS_START);
    if (r != SD_LISTEN_FDS_START) {
      fprintf(stderr, "[upstart -> systemd bridge] error calling dup2(%d, %d): %s.\n", (int)value, SD_LISTEN_FDS_START, strerror(errno));
      return 1;
    }
    /* close the old one, don't leak anything */
    close((int)value);
  }

  /* we pass the listening socket to the daemon systemd-style */
  snprintf(buf, sizeof(buf), "%lu", (unsigned long)getpid());
  setenv("LISTEN_PID", buf, /* overwrite = */ 1);
  setenv("LISTEN_FDS", "1", /* overwrite = */ 1);

done_sockets:
  free(f_);

  if (!notify)
    goto done_notify;

  r = setup_sd_notify_waiter(end_after_ready);
  if (r < 0) {
    fprintf(stderr, "[upstart -> systemd bridge] internal error\n");
    return 1;
  }

done_notify:
  execv(argv[0], &argv[0]);
  fprintf(stderr, "[upstart -> systemd bridge] could not execute %s: %s\n", argv[0], strerror(errno));
  return 1;
}

int setup_sd_notify_waiter(int end_after_ready)
{
  pid_t waiter_pid;
  pid_t orig_pid;
  pid_t pid;
  int s;
  int r;
  int exit_status = 0;
  int notified = 0;
  int flags;
  char template[] = "/run/cross-init-bridge-XXXXXX";
  char *p;
  struct sockaddr_un addr;
  sigset_t origmask;
  sigset_t allblocked;

  orig_pid = getpid();
  
  /* before forking, setup the listening socket for systemd events,
   * only then we can guarantee that
   *    a) it's not racy
   *    b) we know what it's going to be called
   *       in the parent process
   */
  s = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (s < 0) {
    fprintf(stderr, "[upstart -> systemd bridge] could not create socket: %s\n", strerror(errno));
    return -1;
  }

  /* make the socket nonblocking, so we don't block on related
   * syscalls later */
  flags = fcntl(s, F_GETFL, 0);
  if (flags < 0) {
    fprintf(stderr, "[upstart -> systemd bridge] fcntl(new socket, F_GETFL) failed: %s\n", strerror(errno));
    return -1;
  }
  r = fcntl(s, F_SETFL, flags | O_NONBLOCK);
  if (r < 0) {
    fprintf(stderr, "[upstart -> systemd bridge] fcntl(new socket, F_SETFL, O_NONBLOCK) failed: %s\n", strerror(errno));
    return -1;
  }

  /* before we create the temp directory, block all signals,
   * so we get a chance to clean up */
  sigfillset(&allblocked);
  sigprocmask(SIG_BLOCK, &allblocked, &origmask);

  /* First, try to add the socket to /run; but if we are not root (upstart specified a user),
   * we may not be able to put it there... If that fails, try /run... If that fails, abort,
   * because this won't work anyway... */
  p = mkdtemp(template);
  if (!p) {
    /* /run didn't work, for whatever reason, try /tmp (both strings have the same length) */
    snprintf(template, sizeof(template), "%s", "/tmp/cross-init-bridge-XXXXXX");
    p = mkdtemp(template);
  }
  if (!p) {
    fprintf(stderr, "[upstart -> systemd bridge] mkdtemp failed: %s\n", strerror(errno));
    return -1;
  }

  /* Try to bind there */
  addr.sun_family = AF_LOCAL;
  snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/notify.sock", p);
  r = bind(s, (struct sockaddr *)&addr, sizeof(sa_family_t) + strlen(addr.sun_path));
  if (r < 0) {
    close(s);
    unlink(addr.sun_path);
    rmdir(p);
    fprintf(stderr, "[upstart -> systemd bridge] bind(, \"%s\", ...) failed: %s\n", addr.sun_path, strerror(errno));
    return -1;
  }

  /* We want to receive credentials to check we are getting information
   * from the right process. We have to do this AFTER the bind, else
   * we will get a random abstract name assigned to us... */
  flags = 1;
  r = setsockopt(s, SOL_SOCKET, SO_PASSCRED, &flags, sizeof(flags));
  if (r < 0) {
    fprintf(stderr, "[upstart -> systemd bridge] setsockopt(SO_PASSCRED) failed: %s\n", strerror(errno));
    return -1;
  }

  /* Set environment for daemon process */
  setenv("NOTIFY_SOCKET", addr.sun_path, /* overwrite = */ 1);

  waiter_pid = fork();
  if (waiter_pid < 0) {
    fprintf(stderr, "[upstart -> systemd bridge] fork() failed: %s\n", strerror(errno));
    return -1;
  }

  /* we are still the original process that is going to be the daemon,
   * so let's close the socket we just created (the daemon isn't supposed
   * to listen there), and unblock all signals. This might mean that we
   * might immediately die, but the child still has all signals blocked
   * and will install appropriate handlers to make sure cleanup happens. */
  if (waiter_pid > 0) {
    /* if end_after_ready is set, reap the child, because
     * we double-fork and don't use PDEATHSIG */
    if (end_after_ready) {
    retry_orig_wait:
      pid = waitpid(waiter_pid, &exit_status, 0);
      if (pid < 0) {
        if (errno == EINTR)
          goto retry_orig_wait;
        fprintf(stderr, "[upstart -> systemd bridge] waitpid failed: %s\n", strerror(errno));
        /* should not happen */
        return -1;
      }
    }

    close(s);
    r = sigprocmask(SIG_SETMASK, &origmask, NULL);
    /* should NOT happen, but just in case, don't start the daemon,
     * since having all signals blocked is definitely not expected */
    if (r < 0)
      return -1;
    return 0;
  }

  if (end_after_ready) {
    /* double-fork, so the waiter process is child of init and can
     * be reaped immediately */
    waiter_pid = fork();
    if (waiter_pid < 0) {
      fprintf(stderr, "[upstart -> systemd bridge] double-fork failed: %s\n", strerror(errno));
      goto error_cleanup;
    }

    if (waiter_pid > 0)
      exit(0);
  }

  /* just in case we were passed a socket, don't keep it in the babysitting
   * process... */
  if (getenv("LISTEN_FDS"))
    close(SD_LISTEN_FDS_START);

  /* setup signal handlers */
  setup_sighandlers();
  
  /* child process: try to set PDEATHSIG (but don't fail if it doesn't work) */
  if (!end_after_ready)
    prctl(PR_SET_PDEATHSIG, SIGTERM);

  /* if parent already died in the mean time... */
  if ((!end_after_ready && getppid() != orig_pid) || (end_after_ready && kill(orig_pid, 0) < 0))
    goto error_cleanup;
  
  /* close standard fds, to make sure we don't keep something open the daemon
   * might want to close themselves */
  if (s != 0)
    close(0);
  if (s != 1)
    close(1);
  if (s != 2)
    close(2);

  for (;;) {
    fd_set read_fds;
    struct timespec timeout = { 60, 0 };
    FD_ZERO(&read_fds);
    FD_SET(s, &read_fds);

    /* restore original non-blocked mask for the duration of the pselect(),
     * so that SIGTERM is received */
    r = pselect(s + 1, &read_fds, NULL, NULL, &timeout, &origmask);
    if (r < 0 && errno != EINTR)
      goto error_cleanup;

    /* we're done */
    if (caught_sigterm) {
      if (!notified)
        exit_status = 1;
      goto cleanup;
    }

    /* This happens if we had a timeout. This might occur if the daemon
     * dropps privileges after starting, so PDEATHSIG logic doesn't work
     * because the kernel won't allow an unprivileged process to kill a
     * privileged one. The timeout of 60s will ensure that we will not
     * stay around for too long in that case, but also that we don't poll
     * constantly and use up resources. */
    if ((!end_after_ready && getppid() != orig_pid) || (end_after_ready && kill(orig_pid, 0) < 0)) {
      if (!notified)
        exit_status = 1;
      goto cleanup;
    }

    if (r < 0)
      /* interrupted by some other signal, we don't care */
      continue;

    if (r == 0)
      /* this may happen on occasion with select */
      continue;

    /* we have something to read on the socket */
    {
      struct msghdr msg;
      struct iovec iov[1];
      char buf[4096]; /* should be enough to hold anything that gets sent to us... */
      union {
        struct cmsghdr cmh;
        char control[CMSG_SPACE(sizeof(struct ucred))];
      } control;
      struct cmsghdr *header;
      struct ucred *u;
      char *saveptr;
      char *token;

      memset(&msg, 0, sizeof(msg));
      memset(iov, 0, sizeof(iov));
      memset(&control, 0, sizeof(control));
      memset(buf, 0, sizeof(buf));

      iov[0].iov_base = buf;
      /* we want to make sure this is always zero-terminated */
      iov[0].iov_len  = sizeof(buf) - 1;
      control.cmh.cmsg_len = CMSG_LEN(sizeof(struct ucred));
      control.cmh.cmsg_level = SOL_SOCKET;
      control.cmh.cmsg_type = SCM_CREDENTIALS;

      msg.msg_iov = iov;
      msg.msg_iovlen = 1;
      msg.msg_control = &control;
      msg.msg_controllen = sizeof(control);

      r = recvmsg(s, &msg, MSG_DONTWAIT);
      if (r < 0) {
        /* just try again, we had bad luck */
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
          continue;
        /* we won't be able to recover from anything else... */
        goto error_cleanup;
      }

      /* if we are alreeady notified, just eat up the message, don't
       * care about its contents, upstart doesn't support this */
      if (notified)
        continue;

      /* we got a message where we couldn't extract the origin => ignore it */
      header = CMSG_FIRSTHDR(&msg);
      if (header == NULL || header->cmsg_len != CMSG_LEN(sizeof(struct ucred)) || header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_CREDENTIALS)
        continue;

      u = (struct ucred *)CMSG_DATA(header);
      /* nope, process id wrong, not parsing any of that data */
      if (u->pid != orig_pid)
        continue;

      /* parse message */
      saveptr = NULL;
      while ((token = strtok_r(buf, "\n", &saveptr)) != NULL) {
        if (strcmp(token, "READY=1") == 0) {
          /* we got the readiness signal, so remember we had that
           * AND kill the parent process with SIGSTOP to notify
           * upstart of the result */
          notified = 1;
          kill(orig_pid, SIGSTOP);
          if (end_after_ready)
            goto cleanup;
          break;
        }
      }
    }

  }

error_cleanup:
  exit_status = 1;
cleanup:
  close(s);
  unlink(addr.sun_path);
  rmdir(p);
  exit(exit_status);
}

void setup_sighandlers()
{
   struct sigaction term_action;
   memset(&term_action, 0, sizeof(struct sigaction));

   sigfillset(&term_action.sa_mask);
   term_action.sa_handler = handle_sigterm;

   /* FIXME: we should probably check return values... */
   sigaction(SIGTERM, &term_action, NULL);
   sigaction(SIGHUP, &term_action, NULL);
   sigaction(SIGINT, &term_action, NULL);
   sigaction(SIGQUIT, &term_action, NULL);
   sigaction(SIGUSR1, &term_action, NULL);
   sigaction(SIGUSR2, &term_action, NULL);
}

void handle_sigterm(int signum)
{
  (void)signum;
  caught_sigterm = 1;
}
