#include <errno.h>
#include <fcntl.h>
#include <linux/nvme_ioctl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#define NVME_CMD_INSTALL_POLICY    0x95
#define NVME_CMD_ACTIVATE_POLICY   0x96
#define NVME_CMD_DEACTIVATE_POLICY 0x97

static int do_install(const char *device, const char *policy_path,
                      uint32_t policy_id, uint32_t policy_version)
{
    struct nvme_passthru_cmd cmd = {0};
    struct stat st;
    int fd = -1;
    int policy_fd = -1;
    void *buffer = NULL;
    ssize_t read_rc;
    int rc = -1;

    if (stat(policy_path, &st) != 0 || st.st_size <= 0 || st.st_size > UINT32_MAX) {
        fprintf(stderr, "Invalid policy image: %s\n", policy_path);
        return -1;
    }

    policy_fd = open(policy_path, O_RDONLY);
    if (policy_fd < 0) {
        perror("open policy");
        return -1;
    }

    buffer = malloc((size_t)st.st_size);
    if (!buffer) {
        goto cleanup;
    }

    read_rc = read(policy_fd, buffer, (size_t)st.st_size);
    if (read_rc != st.st_size) {
        perror("read policy");
        goto cleanup;
    }

    fd = open(device, O_RDWR);
    if (fd < 0) {
        perror("open device");
        goto cleanup;
    }

    cmd.opcode = NVME_CMD_INSTALL_POLICY;
    cmd.nsid = 1;
    cmd.addr = (uintptr_t)buffer;
    cmd.data_len = (uint32_t)st.st_size;
    cmd.cdw10 = policy_id;
    cmd.cdw11 = policy_version;
    cmd.cdw12 = (uint32_t)st.st_size;

    if (ioctl(fd, NVME_IOCTL_IO_CMD, &cmd) != 0) {
        perror("ioctl install");
        goto cleanup;
    }

    rc = 0;

cleanup:
    if (fd >= 0) {
        close(fd);
    }
    if (policy_fd >= 0) {
        close(policy_fd);
    }
    free(buffer);
    return rc;
}

static int do_simple_opcode(const char *device, uint8_t opcode, uint32_t policy_id)
{
    struct nvme_passthru_cmd cmd = {0};
    int fd;

    fd = open(device, O_RDWR);
    if (fd < 0) {
        perror("open device");
        return -1;
    }

    cmd.opcode = opcode;
    cmd.nsid = 1;
    cmd.cdw10 = policy_id;

    if (ioctl(fd, NVME_IOCTL_IO_CMD, &cmd) != 0) {
        perror("ioctl");
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr,
                "Usage:\n"
                "  %s install <device> <policy.so> <policy_id> <version>\n"
                "  %s activate <device> <policy_id>\n"
                "  %s deactivate <device> <policy_id>\n",
                argv[0], argv[0], argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "install") == 0) {
        if (argc != 6) {
            return 1;
        }
        return do_install(argv[2], argv[3],
                          (uint32_t)strtoul(argv[4], NULL, 0),
                          (uint32_t)strtoul(argv[5], NULL, 0)) == 0 ? 0 : 1;
    }

    if (strcmp(argv[1], "activate") == 0) {
        if (argc != 4) {
            return 1;
        }
        return do_simple_opcode(argv[2], NVME_CMD_ACTIVATE_POLICY,
                                (uint32_t)strtoul(argv[3], NULL, 0)) == 0 ? 0 : 1;
    }

    if (strcmp(argv[1], "deactivate") == 0) {
        if (argc != 4) {
            return 1;
        }
        return do_simple_opcode(argv[2], NVME_CMD_DEACTIVATE_POLICY,
                                (uint32_t)strtoul(argv[3], NULL, 0)) == 0 ? 0 : 1;
    }

    fprintf(stderr, "Unknown command: %s\n", argv[1]);
    return 1;
}
