#include "packet_capture.h"

#include <crt_externs.h>
#include <dispatch/dispatch.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <servers/bootstrap.h>
#include <xpc/xpc.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/bpf.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <unistd.h>

int tattle_capture_open(const char *ifname) {
    int fd = -1;
    char path[16];
    for (int i = 0; i < 256; i++) {
        snprintf(path, sizeof path, "/dev/bpf%d", i);
        // Close-on-exec, so no program this process starts holds the capture.
        fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) break;
        if (errno != EBUSY) return -1;
    }
    if (fd < 0) return -1;

    // Must precede BIOCSETIF and cannot change after it; the kernel clamps to its maximum.
    unsigned int want = 1 << 20;
    ioctl(fd, BIOCSBLEN, &want);

    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strlcpy(ifr.ifr_name, ifname, sizeof ifr.ifr_name);
    if (ioctl(fd, BIOCSETIF, &ifr) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

int tattle_capture_prepare(int fd, int timeout_ms, unsigned int *buflen, unsigned int *dlt) {
    unsigned int on = 1;
    if (ioctl(fd, BIOCIMMEDIATE, &on) < 0) return -1;
    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    if (ioctl(fd, BIOCSRTIMEOUT, &tv) < 0) return -1;
    if (ioctl(fd, BIOCGBLEN, buflen) < 0) return -1;
    if (ioctl(fd, BIOCGDLT, dlt) < 0) return -1;
    return 0;
}

int tattle_capture_set_filter(int fd, const tattle_filter_insn *insns, unsigned int count) {
    struct bpf_program program;
    program.bf_len = count;
    program.bf_insns = (struct bpf_insn *)insns;
    return ioctl(fd, BIOCSETF, &program);
}

int tattle_capture_next(const void *buf, size_t len, size_t offset, double *timestamp,
                        size_t *data_offset, unsigned int *caplen, size_t *next_offset) {
    if (offset + sizeof(struct bpf_hdr) > len) return 0;
    const struct bpf_hdr *h = (const struct bpf_hdr *)((const char *)buf + offset);
    if (offset + h->bh_hdrlen + h->bh_caplen > len) return 0;
    // A record that would not advance the walk, which only a kernel bug writes, ends it. Not
    // bh_hdrlen < sizeof(struct bpf_hdr): on Ethernet bh_hdrlen is 18 and the struct is 20.
    if (h->bh_hdrlen + h->bh_caplen == 0) return 0;
    *timestamp = (double)h->bh_tstamp.tv_sec + (double)h->bh_tstamp.tv_usec / 1e6;
    *data_offset = offset + h->bh_hdrlen;
    *caplen = h->bh_caplen;
    *next_offset = offset + BPF_WORDALIGN(h->bh_hdrlen + h->bh_caplen);
    return 1;
}

int tattle_interface_mac(const char *ifname, uint8_t mac[6]) {
    struct ifaddrs *list = NULL;
    if (getifaddrs(&list) != 0) return -1;
    int found = -1;
    for (struct ifaddrs *entry = list; entry != NULL; entry = entry->ifa_next) {
        if (entry->ifa_addr == NULL || entry->ifa_addr->sa_family != AF_LINK) continue;
        if (strcmp(entry->ifa_name, ifname) != 0) continue;
        const struct sockaddr_dl *dl = (const struct sockaddr_dl *)entry->ifa_addr;
        if (dl->sdl_alen != 6) continue;
        memcpy(mac, LLADDR(dl), 6);
        found = 0;
        break;
    }
    freeifaddrs(list);
    return found;
}

int tattle_neighbor_mac(const char *ifname, const uint8_t *address, size_t length, uint8_t mac[6]) {
    if (length != 4 && length != 16) return -1;
    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) return -1;
    // The routes that hold a link address, which is the table `arp -a` and `ndp -a` print.
    int mib[6] = { CTL_NET, PF_ROUTE, 0, length == 4 ? AF_INET : AF_INET6, NET_RT_FLAGS, RTF_LLINFO };
    size_t needed = 0;
    if (sysctl(mib, 6, NULL, &needed, NULL, 0) != 0 || needed == 0) return -1;
    // The table can grow between the two calls; the slack covers a few new entries.
    needed += 1024;
    char *table = malloc(needed);
    if (table == NULL) return -1;
    int found = -1;
    if (sysctl(mib, 6, table, &needed, NULL, 0) == 0) {
        const char *end = table + needed;
        for (const char *next = table; next + sizeof(struct rt_msghdr) <= end;) {
            const struct rt_msghdr *message = (const struct rt_msghdr *)next;
            if (message->rtm_msglen < sizeof(struct rt_msghdr) || next + message->rtm_msglen > end) break;
            next += message->rtm_msglen;
            // The destination, then the link address it resolves to, each padded to 4 bytes.
            const struct sockaddr *destination = (const struct sockaddr *)(message + 1);
            if ((const char *)destination + sizeof(struct sockaddr) > next || destination->sa_len == 0) continue;
            const struct sockaddr_dl *link = (const struct sockaddr_dl *)((const char *)destination + ((destination->sa_len + 3u) & ~3u));
            if ((const char *)link + sizeof(struct sockaddr_dl) > next) continue;
            // An entry still being resolved has no address yet.
            if (link->sdl_family != AF_LINK || link->sdl_alen != 6 || link->sdl_index != ifindex) continue;
            if ((const char *)LLADDR(link) + 6 > next) continue;
            if (length == 4) {
                if (destination->sa_family != AF_INET || destination->sa_len < sizeof(struct sockaddr_in)) continue;
                if (memcmp(&((const struct sockaddr_in *)destination)->sin_addr, address, 4) != 0) continue;
            } else {
                if (destination->sa_family != AF_INET6 || destination->sa_len < sizeof(struct sockaddr_in6)) continue;
                uint8_t entry[16];
                memcpy(entry, &((const struct sockaddr_in6 *)destination)->sin6_addr, 16);
                // The kernel keeps a link-local address's interface in its third and fourth bytes.
                if (entry[0] == 0xfe && (entry[1] & 0xc0) == 0x80) entry[2] = entry[3] = 0;
                if (memcmp(entry, address, 16) != 0) continue;
            }
            memcpy(mac, LLADDR(link), 6);
            found = 0;
            break;
        }
    }
    free(table);
    return found;
}

// One request on a fresh connection, answered by `deadline` or abandoned. Sets *interrupted when
// the broker went away before answering, which an idle exit racing the request also does.
static int broker_request_once(const char *service, int privileged, const char *ifname, dispatch_time_t deadline,
                               int *status, int *err, int *interrupted) {
    *status = -1;
    *err = 0;
    *interrupted = 0;
    xpc_connection_t connection = xpc_connection_create_mach_service(service, NULL, privileged ? XPC_CONNECTION_MACH_SERVICE_PRIVILEGED : 0);
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) { (void)event; });
    xpc_connection_activate(connection);
    xpc_object_t request = xpc_dictionary_create_empty();
    xpc_dictionary_set_string(request, "interface", ifname);
    dispatch_semaphore_t answered = dispatch_semaphore_create(0);
    __block xpc_object_t reply = NULL;
    xpc_connection_send_message_with_reply(connection, request, NULL, ^(xpc_object_t object) {
        reply = xpc_retain(object);
        dispatch_semaphore_signal(answered);
    });
    xpc_release(request);
    int fd = -1;
    if (dispatch_semaphore_wait(answered, deadline) != 0) {
        // Cancelling delivers the reply handler its error at once, so this wait is short.
        xpc_connection_cancel(connection);
        dispatch_semaphore_wait(answered, DISPATCH_TIME_FOREVER);
        *err = ETIMEDOUT;
    } else if (xpc_get_type(reply) == XPC_TYPE_ERROR) {
        if (reply == XPC_ERROR_CONNECTION_INTERRUPTED) {
            *interrupted = 1;
            *err = ECONNRESET;
        } else {
            *err = ECONNREFUSED;  // no job serves the name
        }
    } else {
        *status = (int)xpc_dictionary_get_int64(reply, "status");
        if (*status == 0) {
            fd = xpc_dictionary_dup_fd(reply, "descriptor");
            if (fd < 0) { *status = -1; *err = EPROTO; }
            // XPC does not document whether the descriptor it makes is close-on-exec: set it, as at open.
            else fcntl(fd, F_SETFD, FD_CLOEXEC);
        } else if (*status == 3) {
            *err = (int)xpc_dictionary_get_int64(reply, "errno");
        }
    }
    if (reply != NULL) xpc_release(reply);
    dispatch_release(answered);
    xpc_connection_cancel(connection);
    xpc_release(connection);
    return fd;
}

// The header of the image this file is linked into, defined by the linker for every image.
extern const struct mach_header __dso_handle;

static int launch_exception_ports_dropped = -1;

int tattle_launch_exception_ports_dropped(void) { return launch_exception_ports_dropped; }

// Whoever launched this program chose the task exception ports it inherited, and a trap would
// hand them its task: code running as Tattle, which can ask the broker for a descriptor. The
// broker cannot see them (ADR-0003), and a launcher can force a trap at startup, through an
// inherited stack limit for one, so they go before any of the program's own code runs, not
// just before it first asks. EXC_MASK_ALL leaves out EXC_CRASH, which hands over the dying
// task with its memory still writable. EXC_CORPSE_NOTIFY stays, because macOS's crash reports
// arrive through it: it hands over the dead process, whose memory can be read but which holds
// no descriptor and runs no code.
//
// Only in a program that has this file in its own executable: the app, and the test probe that
// stands in for it. A test runner loads it inside a test bundle and keeps its ports.
__attribute__((constructor))
static void drop_inherited_exception_ports(void) {
    if ((const void *)&__dso_handle != (const void *)_NSGetMachExecuteHeader()) return;
    exception_mask_t masks[EXC_TYPES_COUNT];
    mach_port_t ports[EXC_TYPES_COUNT];
    exception_behavior_t behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t flavors[EXC_TYPES_COUNT];
    mach_msg_type_number_t count = EXC_TYPES_COUNT;
    if (task_swap_exception_ports(mach_task_self(), EXC_MASK_ALL | EXC_MASK_CRASH, MACH_PORT_NULL, EXCEPTION_DEFAULT,
                                  THREAD_STATE_NONE, masks, &count, ports, behaviors, flavors) != KERN_SUCCESS) {
        launch_exception_ports_dropped = -2;
        return;
    }
    int dropped = 0;
    for (mach_msg_type_number_t i = 0; i < count; i++) {
        if (!MACH_PORT_VALID(ports[i])) continue;
        dropped++;
        mach_port_deallocate(mach_task_self(), ports[i]);
    }
    launch_exception_ports_dropped = dropped;
}

int tattle_broker_request(const char *service, int privileged, const char *ifname, int *status, int *err) {
    if (launch_exception_ports_dropped == -2) {
        *status = -1;
        *err = EPERM;
        return -1;
    }
    // One deadline for both attempts, so a retry never doubles the wait a caller plans for.
    dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW, (int64_t)TATTLE_BROKER_TIMEOUT_MS * NSEC_PER_MSEC);
    int interrupted = 0;
    int fd = broker_request_once(service, privileged, ifname, deadline, status, err, &interrupted);
    if (fd < 0 && interrupted) fd = broker_request_once(service, privileged, ifname, deadline, status, err, &interrupted);
    return fd;
}

int tattle_broker_is_registered(const char *service) {
    mach_port_t port = MACH_PORT_NULL;
    if (bootstrap_look_up(bootstrap_port, service, &port) != KERN_SUCCESS) return 0;
    mach_port_deallocate(mach_task_self(), port);
    return 1;
}
