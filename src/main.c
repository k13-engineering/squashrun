#define _GNU_SOURCE
#include <sched.h>

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mount.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/loop.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <signal.h>
#include <sys/signalfd.h>

pid_t safe_fork() {
    pid_t ppid_before_fork = getpid();
    pid_t pid = fork();

    if (pid == 0) {
        int r = prctl(PR_SET_PDEATHSIG, SIGKILL);
        if (r < 0) {
            perror("prctl(PR_SET_PDEATHSIG)");
            exit(-1);
        }

        // TODO: fix race hazard
    }

    return pid;
}

int main(int argc, char *argv[])
{
    char app_data_path[256] = "/data/app";
    char app_image_path[256] = "/data/app.squashfs";
    int app_image_fd;
    int loop_ctl_fd;
    char loop_device_path[256];
    int loop_fd;
    int loop_dev_num;
    struct loop_config loop_cfg;
    int rc;
    pid_t child;
    int sfd;
    struct signalfd_siginfo fdsi;
    sigset_t mask;

    rc = mkdir(app_data_path, 0755);
    if (rc != 0) {
        if (errno == EEXIST) {
            fprintf(stderr, "directory '%s' already exists\n", app_data_path);
        } else {
            fprintf(stderr, "mkdir '%s' failed: %s\n", app_data_path, strerror(errno));
            return -1;
        }
    }

    app_image_fd = open(app_image_path, O_RDONLY);
    if (app_image_fd < 0) {
        if (errno == ENOENT) {
            fprintf(stderr, "file '%s' does not exist\n", app_image_path);
            fprintf(stderr, "going to sleep forever...\n");

            while (1) {
                sleep(1);
            }

            return -1;
        }

        fprintf(stderr, "open '%s' failed: %s\n", app_image_path, strerror(errno));
        return -1;
    }

    fprintf(stderr, "searching free loop device...\n");

    loop_ctl_fd = open("/dev/loop-control", O_RDWR);
    if (loop_ctl_fd < 0) {
        fprintf(stderr, "open '/dev/loop-control' failed: %s\n", strerror(errno));
        return -1;
    }

    loop_dev_num = ioctl(loop_ctl_fd, LOOP_CTL_GET_FREE);
    if (loop_dev_num < 0) {
        fprintf(stderr, "ioctl LOOP_CTL_GET_FREE failed: %s\n", strerror(errno));
        return -1;
    }

    snprintf(loop_device_path, sizeof(loop_device_path), "/dev/loop%i", loop_dev_num);
    fprintf(stderr, "using loop device: %s\n", loop_device_path);
    
    loop_fd = open(loop_device_path, O_RDWR);
    if (loop_fd < 0) {
        fprintf(stderr, "open '%s' failed: %s\n", loop_device_path, strerror(errno));
        return -1;
    }

    fprintf(stderr, "configuring '%s' to be backed by '%s' (autoclear)...\n", loop_device_path, app_image_path);

    memset(&loop_cfg, 0, sizeof(loop_cfg));
    loop_cfg.fd = app_image_fd;
    loop_cfg.block_size = 512;
    loop_cfg.info.lo_flags = LO_FLAGS_READ_ONLY | LO_FLAGS_AUTOCLEAR;

    rc = ioctl(loop_fd, LOOP_CONFIGURE, &loop_cfg);
    if (rc < 0) {
        fprintf(stderr, "ioctl LOOP_CONFIGURE failed: %s\n", strerror(errno));
        return -1;
    }

    close(loop_ctl_fd);
    close(app_image_fd);

    fprintf(stderr, "loop device '%s' ready\n", loop_device_path);

    rc = unshare(CLONE_NEWPID);
    if (rc < 0) {
        fprintf(stderr, "unshare failed: %s\n", strerror(errno));
        return -1;
    }

    // Create a signal set including SIGINT and SIGTERM
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGCHLD);

    sfd = signalfd(-1, &mask, 0);
    if (sfd == -1) {
        perror("signalfd");
        return 1;
    }

    sigaddset(&mask, SIGINT);

    rc = sigprocmask(SIG_BLOCK, &mask, NULL);
    if (rc < 0) {
        fprintf(stderr, "sigprocmask failed: %s\n", strerror(errno));
        return -1;
    }

    child = safe_fork();
    if (child < 0) {
        fprintf(stderr, "fork failed: %s\n", strerror(errno));
        return -1;
    } else if (child == 0) {
        rc = unshare(CLONE_NEWNS);
        if (rc < 0) {
            fprintf(stderr, "unshare failed: %s\n", strerror(errno));
            return -1;
        }

        rc = mount("/", "/", NULL, MS_REC | MS_PRIVATE, NULL);
        if (rc < 0) {
            fprintf(stderr, "mount '/' failed: %s\n", strerror(errno));
            return -1;
        }

        rc = mount("tmpfs", "/tmp", "tmpfs", 0, NULL);
        if (rc < 0) {
            fprintf(stderr, "mount tmpfs failed: %s\n", strerror(errno));
            return -1;
        }

        rc = mkdir("/tmp/app", 0755);
        if (rc < 0) {
            fprintf(stderr, "mkdir '/tmp/app' failed: %s\n", strerror(errno));
            return -1;
        }

        rc = mount(loop_device_path, "/tmp/app", "squashfs", MS_RDONLY, NULL);
        if (rc < 0) {
            fprintf(stderr, "mount '%s' failed: %s\n", loop_device_path, strerror(errno));
            return -1;
        }

        rc = mount("/dev", "/tmp/app/dev", NULL, MS_BIND | MS_REC, NULL);
        if (rc < 0) {
            fprintf(stderr, "mount '/dev' failed: %s\n", strerror(errno));
            return -1;
        }

        rc = mount("proc", "/tmp/app/proc", "proc", 0, NULL);
        if (rc < 0) {
            fprintf(stderr, "mount 'proc' failed: %s\n", strerror(errno));
            return -1;
        }

        rc = mount("sysfs", "/tmp/app/sys", "sysfs", 0, NULL);
        if (rc < 0) {
            fprintf(stderr, "mount 'sysfs' failed: %s\n", strerror(errno));
            return -1;
        }

        rc = mount("tmpfs", "/tmp/app/tmp", "tmpfs", 0, NULL);
        if (rc < 0) {
            fprintf(stderr, "mount 'tmpfs' failed: %s\n", strerror(errno));
            return -1;
        }

        rc = mount(app_data_path, "/tmp/app/data", NULL, MS_BIND | MS_REC, NULL);
        if (rc < 0) {
            fprintf(stderr, "mount '/data' failed: %s\n", strerror(errno));
            return -1;
        }

        rc = chdir("/tmp/app");
        if (rc < 0) {
            fprintf(stderr, "chdir '/tmp/app' failed: %s\n", strerror(errno));
            return -1;
        }

        rc = chroot(".");
        if (rc < 0) {
            fprintf(stderr, "chroot failed: %s\n", strerror(errno));
            return -1;
        }


        char *argv_init[] = {"/init", NULL};
        rc = execve("/init", argv_init, NULL);
        fprintf(stderr, "execve failed: %s\n", strerror(errno));
        return -1;
    }

    fprintf(stderr, "forked off, child pid = %i\n", child);

    int done = 0;

    while (!done)
    {
        ssize_t res;

        res = read(sfd, &fdsi, sizeof(fdsi));
        if (res != sizeof(fdsi)) {
            perror("read");
            return 1;
        }

        fprintf(stderr, "got signal %d\n", fdsi.ssi_signo);
        
        switch(fdsi.ssi_signo) {
            case SIGTERM: {
                fprintf(stderr, "got SIGTERM, relaying...\n");
                kill(child, SIGTERM);
                break;
            }

            case SIGCHLD: {
                pid_t p;

                p = waitpid(child, NULL, 0);
                if (p < 0) {
                    fprintf(stderr, "waitpid failed: %s\n", strerror(errno));
                    return -1;
                } else if (p == child) {
                    done = 1;
                    // fprintf(stderr, "child exited\n");
                    break;
                } else {
                    fprintf(stderr, "waitpid returned unexpected pid %i\n", p);
                    return -1;
                }

                break;
            }
        }
    }

    close(sfd);
    close(loop_fd);

    return 0;
}
