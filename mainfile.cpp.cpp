#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/statvfs.h>
#include<climits>
#include <dirent.h>     // For directory operations
#include <sys/socket.h> // For network operations
#include <netinet/in.h>
#include <arpa/inet.h>
#define HISTORY_SIZE 5  // For EMA
// Synchronization mutex for thread safety
pthread_mutex_t lock;
// Function prototypes
void monitor_resources();
void trigger_alerts();
void log_resource_usage();
void control_process();
void set_process_priority(int pid, int priority);
void monitor_disk_io();
void apply_sstf_scheduling(int disk_requests[], int n);
void apply_fcfs_scheduling(int disk_requests[], int n);
float calculate_ema(int history[], int size);
void profile_process();
void cpu_scheduling_round_robin(int processes[], int n, int quantum);
void create_child_process_and_monitor();
void monitor_network_usage();
void analyze_system_performance();
void monitor_process_tree();
void set_resource_limits();
void monitor_file_descriptors(int pid);
void analyze_memory_details();
void monitor_tcp_connections();
void check_system_security();
void analyze_process_resources();

// Thresholds for alerts
int cpu_threshold = 90;
int memory_threshold = 80;
int disk_io_threshold = 70;

// Historical CPU usage for EMA
int cpu_usage_history[HISTORY_SIZE] = {0};
int history_index = 0;

// Main program: Initialization and menu options
int main() {
    int choice;

    // Initialize mutex
    pthread_mutex_init(&lock, NULL);

    while (1) {
        printf("\nProSysMonitor - System Monitoring Tool\n");
        printf("1. Monitor Resources (CPU, Memory, Disk)\n");
        printf("2. Set Thresholds and Check Alerts\n");
        printf("3. Log Resource Usage\n");
        printf("4. Control Processes (Kill, Pause, Reprioritize)\n");
        printf("5. Monitor Disk I/O\n");
        printf("6. Profile a Process\n");   // New Option for Process Profiling
        printf("7. CPU Scheduling (Round Robin)\n");
        printf("8. Disk Scheduling (FCFS)\n");
        printf("9. Create Child Process and Monitor\n");
        printf("10. Monitor Network Usage\n");
        printf("11. Analyze System Performance\n");
        printf("12. Monitor Process Tree\n");
        printf("13. Set Resource Limits\n");
        printf("14. Monitor File Descriptors\n");
        printf("15. Detailed Memory Analysis\n");
        printf("16. Monitor TCP Connections\n");
        printf("17. Security Check\n");
        printf("18. Analyze Process Resource Usage\n");
        printf("19. Exit\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                monitor_resources();
                break;
            case 2:
                trigger_alerts();
                break;
            case 3:
                log_resource_usage();
                break;
            case 4:
                control_process();
                break;
            case 5:
                monitor_disk_io();
                break;
            case 6:
                profile_process();    // Call the profiling function
                break;
            case 7:
                cpu_scheduling_round_robin(NULL, 0, 4);  // Round Robin Scheduling Example
                break;
            case 8:
                apply_fcfs_scheduling(NULL, 0);  // FCFS Disk Scheduling Example
                break;
            case 9:
                create_child_process_and_monitor();  // Create Child Process
                break;
            case 10:
                monitor_network_usage();
                break;
            case 11:
                analyze_system_performance();
                break;
            case 12:
                monitor_process_tree();
                break;
            case 13:
                set_resource_limits();
                break;
            case 14:
                {
                    int pid;
                    printf("Enter PID to monitor: ");
                    scanf("%d", &pid);
                    monitor_file_descriptors(pid);
                }
                break;
            case 15:
                analyze_memory_details();
                break;
            case 16:
                monitor_tcp_connections();
                break;
            case 17:
                check_system_security();
                break;
            case 18:
                analyze_process_resources();
                break;
            case 19:
                printf("Exiting...\n");
                pthread_mutex_destroy(&lock);
                return 0;
            default:
                printf("Invalid choice! Try again.\n");
        }
    }
    return 0;
}

// Function to monitor CPU, memory, and disk usage with EMA
void monitor_resources() {
    printf("Monitoring system resources...\n");

    // Get real-time CPU usage using 'top' command
    FILE *fp = popen("top -b -n1 | grep 'Cpu(s)' | awk '{print $2 + $4}'", "r");  // CPU usage as a percentage
    if (fp == NULL) {
        printf("Failed to run top command\n");
        exit(1);
    }
    float current_cpu = 0;
    fscanf(fp, "%f", &current_cpu);
    pclose(fp);

    // Get real-time memory usage using 'free' command
    fp = popen("free | grep Mem | awk '{print $3/$2 * 100.0}'", "r");  // Memory usage as percentage
    if (fp == NULL) {
        printf("Failed to run free command\n");
        exit(1);
    }
    float current_memory = 0;
    fscanf(fp, "%f", &current_memory);
    pclose(fp);

    // Get real-time disk usage using 'df' command
    fp = popen("df / | grep / | awk '{ print $5 }'", "r");  // Disk usage as percentage
    if (fp == NULL) {
        printf("Failed to run df command\n");
        exit(1);
    }
    int current_disk_io = 0;
    fscanf(fp, "%d", &current_disk_io);
    pclose(fp);

    // Update CPU usage history and calculate EMA
    cpu_usage_history[history_index] = current_cpu;
    history_index = (history_index + 1) % HISTORY_SIZE;
    float smoothed_cpu = calculate_ema(cpu_usage_history, HISTORY_SIZE);

    printf("\nSmoothed CPU Usage (EMA): %.2f%%\n", smoothed_cpu);
    printf("Current CPU Usage: %.2f%%\n", current_cpu);
    printf("Current Memory Usage: %.2f%%\n", current_memory);
    printf("Current Disk Usage: %d%%\n", current_disk_io);
}

// Function to calculate EMA for CPU usage
float calculate_ema(int history[], int size) {
    float alpha = 0.5; // Smoothing factor
    float ema = history[0];  // Initialize with the first value
    for (int i = 1; i < size; i++) {
        ema = alpha * history[i] + (1 - alpha) * ema;
    }
    return ema;
}

// Function to set thresholds and check CPU, memory, and disk usage
void trigger_alerts() {
    printf("Setting thresholds for resource monitoring...\n");

    printf("Enter CPU usage threshold (current: %d%%): ", cpu_threshold);
    scanf("%d", &cpu_threshold);
    printf("Enter memory usage threshold (current: %d%%): ", memory_threshold);
    scanf("%d", &memory_threshold);
    printf("Enter disk I/O usage threshold (current: %d%%): ", disk_io_threshold);
    scanf("%d", &disk_io_threshold);

    // Get real-time CPU usage using 'top' command
    FILE *fp = popen("top -b -n1 | grep 'Cpu(s)' | awk '{print $2 + $4}'", "r");
    if (fp == NULL) {
        printf("Failed to run top command\n");
        exit(1);
    }
    float current_cpu = 0;
    fscanf(fp, "%f", &current_cpu);
    pclose(fp);

    // Get real-time memory usage using 'free' command
    fp = popen("free | grep Mem | awk '{print $3/$2 * 100.0}'", "r");
    if (fp == NULL) {
        printf("Failed to run free command\n");
        exit(1);
    }
    float current_memory = 0;
    fscanf(fp, "%f", &current_memory);
    pclose(fp);

    // Get real-time disk usage using 'df' command
    fp = popen("df / | grep / | awk '{ print $5 }'", "r");
    if (fp == NULL) {
        printf("Failed to run df command\n");
        exit(1);
    }
    int current_disk_io = 0;
    fscanf(fp, "%d", &current_disk_io);
    pclose(fp);

    if (current_cpu > cpu_threshold) {
        printf("CPU usage alert: %.2f%% (Threshold: %d%%)\n", current_cpu, cpu_threshold);
    } else {
        printf("CPU usage is normal: %.2f%%\n", current_cpu);
    }

    if (current_memory > memory_threshold) {
        printf("Memory usage alert: %.2f%% (Threshold: %d%%)\n", current_memory, memory_threshold);
    } else {
        printf("Memory usage is normal: %.2f%%\n", current_memory);
    }

    if (current_disk_io > disk_io_threshold) {
        printf("Disk I/O usage alert: %d%% (Threshold: %d%%)\n", current_disk_io, disk_io_threshold);
    } else {
        printf("Disk I/O usage is normal: %d%%\n", current_disk_io);
    }
}

// Function to log CPU, memory, and disk usage to a file
void log_resource_usage() {
    FILE *log_file = fopen("resource_log.txt", "a");
    if (log_file == NULL) {
        printf("Error opening log file!\n");
        return;
    }

    // Get current time
    time_t now;
    time(&now);

    // Get real-time CPU usage using 'top' command
    FILE *fp = popen("top -b -n1 | grep 'Cpu(s)' | awk '{print $2 + $4}'", "r");
    if (fp == NULL) {
        printf("Failed to run top command\n");
        exit(1);
    }
    float cpu_usage = 0;
    fscanf(fp, "%f", &cpu_usage);
    pclose(fp);

    // Get real-time memory usage using 'free' command
    fp = popen("free | grep Mem | awk '{print $3/$2 * 100.0}'", "r");
    if (fp == NULL) {
        printf("Failed to run free command\n");
        exit(1);
    }
    float memory_usage = 0;
    fscanf(fp, "%f", &memory_usage);
    pclose(fp);

    // Get real-time disk usage using 'df' command
    fp = popen("df / | grep / | awk '{ print $5 }'", "r");
    if (fp == NULL) {
        printf("Failed to run df command\n");
        exit(1);
    }
    int disk_usage = 0;
    fscanf(fp, "%d", &disk_usage);
    pclose(fp);

    // Log the current resource usage to the log file
    fprintf(log_file, "Time: %s", ctime(&now));
    fprintf(log_file, "CPU Usage: %.2f%%\n", cpu_usage);
    fprintf(log_file, "Memory Usage: %.2f%%\n", memory_usage);
    fprintf(log_file, "Disk Usage: %d%%\n", disk_usage);
    fprintf(log_file, "--------------------------\n");

    fclose(log_file);
    printf("Resource usage logged successfully.\n");
}

// Function to control processes (kill, pause, or reprioritize)
void control_process() {
    int pid, action, priority;

    printf("Enter the process ID (PID) to control: ");
    scanf("%d", &pid);

    printf("Select an action: \n1. Kill Process\n2. Pause Process\n3. Reprioritize Process\n");
    scanf("%d", &action);

    if (action == 1) {
        // Kill the process
        if (kill(pid, SIGKILL) == 0) {
            printf("Process %d terminated successfully.\n", pid);
        } else {
            perror("Failed to terminate process");
        }
    } else if (action == 2) {
        // Pause the process
        if (kill(pid, SIGSTOP) == 0) {
            printf("Process %d paused successfully.\n", pid);
        } else {
            perror("Failed to pause process");
        }
    } else if (action == 3) {
        // Reprioritize the process
        printf("Enter the new priority (lower number = higher priority): ");
        scanf("%d", &priority);
        set_process_priority(pid, priority);
    } else {
        printf("Invalid action selected.\n");
    }
}

// Function to set process priority (higher = less important)
void set_process_priority(int pid, int priority) {
    if (setpriority(PRIO_PROCESS, pid, priority) == 0) {
        printf("Priority of process %d set to %d.\n", pid, priority);
    } else {
        perror("Failed to set process priority");
    }
}

// Function to monitor disk I/O using iotop and apply SSTF scheduling
void monitor_disk_io() {
    printf("Monitoring disk I/O (requires sudo privileges)...\n");

    // First, let's monitor disk I/O using iotop
    FILE *fp = popen("sudo iotop -b -n 1 | head -10", "r");
    if (fp == NULL) {
        printf("Failed to run iotop command\n");
        exit(1);
    }

    char line[256];
    while (fgets(line, sizeof(line), fp) != NULL) {
        printf("%s", line);
    }
    pclose(fp);

    // Example disk requests (block positions)
    int disk_requests[] = {98, 183, 37, 122, 14, 124, 65, 67};
    int n = sizeof(disk_requests) / sizeof(disk_requests[0]);

    // Apply SSTF disk scheduling
    apply_sstf_scheduling(disk_requests, n);
}

// FCFS disk scheduling algorithm
void apply_fcfs_scheduling(int disk_requests[], int n) {
    int current_position = 0;  // Start at the initial disk head position
    int total_seek_time = 0;

    printf("FCFS Disk Scheduling:\n");
    for (int i = 0; i < n; i++) {
        int seek_time = abs(disk_requests[i] - current_position);
        total_seek_time += seek_time;
        current_position = disk_requests[i];
        printf("Moved to position %d, seek time: %d\n", current_position, seek_time);
    }

    printf("Total seek time: %d\n", total_seek_time);
}

// Round Robin CPU Scheduling Algorithm
void cpu_scheduling_round_robin(int processes[], int n, int quantum) {
    if (n == 0) return;

    int remaining_time[n];
    for (int i = 0; i < n; i++) {
        remaining_time[i] = processes[i];  // Initialize remaining time
    }

    int time = 0;
    while (1) {
        int all_done = 1;
        for (int i = 0; i < n; i++) {
            if (remaining_time[i] > 0) {
                all_done = 0;
                int time_to_run = remaining_time[i] > quantum ? quantum : remaining_time[i];
                remaining_time[i] -= time_to_run;
                time += time_to_run;
                printf("Process %d ran for %d units. Total time: %d\n", i, time_to_run, time);
            }
        }
        if (all_done) break;
    }
}

// Function to create a child process and monitor resources
void create_child_process_and_monitor() {
    pid_t pid = fork();
    if (pid == 0) {
        // Child process: Monitor CPU usage
        while (1) {
            printf("Child process: Monitoring CPU usage...\n");
            sleep(2);
        }
    } else if (pid > 0) {
        // Parent process: Continue with main tasks
        printf("Parent process: Monitoring resources.\n");
        wait(NULL);  // Wait for the child process to finish
    } else {
        perror("Fork failed");
    }
}
void profile_process() {
    int pid;
    printf("Enter the PID of the process to profile: ");
    scanf("%d", &pid);

    // Get process statistics using /proc filesystem
    char stat_path[256];
    sprintf(stat_path, "/proc/%d/stat", pid);
    
    FILE *stat_file = fopen(stat_path, "r");
    if (stat_file == NULL) {
        printf("Unable to open process statistics. Check if PID exists.\n");
        return;
    }

    // Variables to store process statistics
    char comm[256];
    char state;
    unsigned long utime, stime, vsize;
    long rss;

    // Read process statistics
    fscanf(stat_file, "%*d (%[^)]) %c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu %*d %*d %*d %*d %*d %*d %*u %lu %ld",
           comm, &state, &utime, &stime, &vsize, &rss);
    fclose(stat_file);

    // Calculate CPU usage time in seconds
    float cpu_time = (utime + stime) / (float)sysconf(_SC_CLK_TCK);

    // Get memory information
    char status_path[256];
    sprintf(status_path, "/proc/%d/status", pid);
    FILE *status_file = fopen(status_path, "r");
    
    long vm_peak = 0, vm_size = 0, vm_rss = 0;
    char line[256];
    
    if (status_file != NULL) {
        while (fgets(line, sizeof(line), status_file)) {
            if (strncmp(line, "VmPeak:", 7) == 0) sscanf(line, "VmPeak: %ld", &vm_peak);
            if (strncmp(line, "VmSize:", 7) == 0) sscanf(line, "VmSize: %ld", &vm_size);
            if (strncmp(line, "VmRSS:", 6) == 0) sscanf(line, "VmRSS: %ld", &vm_rss);
        }
        fclose(status_file);
    }

    // Print profiling results
    printf("\nProcess Profile for PID %d:\n", pid);
    printf("Name: %s\n", comm);
    printf("State: %c\n", state);
    printf("CPU Time: %.2f seconds\n", cpu_time);
    printf("Virtual Memory Size: %lu bytes\n", vsize);
    printf("RSS (Resident Set Size): %ld pages\n", rss);
    printf("Peak Virtual Memory: %ld kB\n", vm_peak);
    printf("Current Virtual Memory: %ld kB\n", vm_size);
    printf("Current RSS: %ld kB\n", vm_rss);
}

// Function to apply SSTF (Shortest Seek Time First) disk scheduling
void apply_sstf_scheduling(int disk_requests[], int n) {
    if (n == 0) {
        printf("No disk requests to process.\n");
        return;
    }

    int current_pos = 0;  // Starting position of disk head
    int *completed = (int *)calloc(n, sizeof(int));  // Track completed requests
    int total_seek_time = 0;
    
    printf("\nSSTF Disk Scheduling Sequence:\n");
    printf("Starting position: %d\n", current_pos);

    // Process all requests
    for (int i = 0; i < n; i++) {
        int shortest_seek = INT_MAX;
        int next_request = -1;

        // Find the request with shortest seek time from current position
        for (int j = 0; j < n; j++) {
            if (!completed[j]) {
                int seek_time = abs(disk_requests[j] - current_pos);
                if (seek_time < shortest_seek) {
                    shortest_seek = seek_time;
                    next_request = j;
                }
            }
        }

        if (next_request != -1) {
            // Process the selected request
            printf("Move from %d to %d, seek time: %d\n", 
                   current_pos, disk_requests[next_request], shortest_seek);
            total_seek_time += shortest_seek;
            current_pos = disk_requests[next_request];
            completed[next_request] = 1;
        }
    }

    printf("\nTotal seek time: %d\n", total_seek_time);
    printf("Average seek time: %.2f\n", (float)total_seek_time / n);
    
    free(completed);
}

void monitor_network_usage() {
    printf("Monitoring network interfaces...\n");
    
    FILE *fp = popen("ifconfig | grep 'bytes' | awk '{print $3 $7}'", "r");
    if (fp == NULL) {
        printf("Failed to get network statistics\n");
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        printf("Network traffic: %s", line);
    }
    pclose(fp);
}

void analyze_system_performance() {
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        printf("\nSystem Performance Analysis:\n");
        printf("Uptime: %ld days, %ld hours, %ld minutes\n", 
               si.uptime/86400, (si.uptime%86400)/3600, (si.uptime%3600)/60);
        printf("Load Averages: %.2f (1 min), %.2f (5 min), %.2f (15 min)\n",
               si.loads[0]/65536.0, si.loads[1]/65536.0, si.loads[2]/65536.0);
        printf("Total RAM: %lu MB\n", si.totalram/1024/1024);
        printf("Free RAM: %lu MB\n", si.freeram/1024/1024);
        printf("Process count: %d\n", si.procs);
    }
}

void monitor_process_tree() {
    printf("\nProcess Tree:\n");
    system("pstree -p");
}

void set_resource_limits() {
    struct rlimit rlim;
    int pid;
    
    printf("Enter PID to set limits for: ");
    scanf("%d", &pid);
    
    printf("Set max CPU time (seconds): ");
    scanf("%ld", &rlim.rlim_max);
    rlim.rlim_cur = rlim.rlim_max;
    
    if (setrlimit(RLIMIT_CPU, &rlim) == 0) {
        printf("CPU time limit set successfully\n");
    } else {
        perror("Failed to set CPU limit");
    }
}

void monitor_file_descriptors(int pid) {
    char fd_path[256];
    sprintf(fd_path, "/proc/%d/fd", pid);
    
    DIR *dir = opendir(fd_path);
    if (!dir) {
        printf("Cannot open file descriptor directory for PID %d\n", pid);
        return;
    }

    struct dirent *entry;
    int fd_count = 0;
    
    printf("\nOpen File Descriptors for PID %d:\n", pid);
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] != '.') {
            char fd_link[256];
            char target[1024];
            sprintf(fd_link, "%s/%s", fd_path, entry->d_name);
            
            ssize_t len = readlink(fd_link, target, sizeof(target)-1);
            if (len != -1) {
                target[len] = '\0';
                printf("FD %s -> %s\n", entry->d_name, target);
                fd_count++;
            }
        }
    }
    
    printf("Total open file descriptors: %d\n", fd_count);
    closedir(dir);
}

void analyze_memory_details() {
    FILE *meminfo = fopen("/proc/meminfo", "r");
    if (!meminfo) {
        printf("Cannot open memory information\n");
        return;
    }

    printf("\nDetailed Memory Analysis:\n");
    char line[256];
    while (fgets(line, sizeof(line), meminfo)) {
        // Print specific memory metrics
        if (strstr(line, "MemTotal") || 
            strstr(line, "MemFree") || 
            strstr(line, "MemAvailable") ||
            strstr(line, "Buffers") ||
            strstr(line, "Cached") ||
            strstr(line, "SwapTotal") ||
            strstr(line, "SwapFree") ||
            strstr(line, "Dirty") ||
            strstr(line, "Writeback")) {
            printf("%s", line);
        }
    }
    fclose(meminfo);

    // Get memory page size
    long page_size = sysconf(_SC_PAGESIZE);
    printf("Memory Page Size: %ld bytes\n", page_size);
}

void monitor_tcp_connections() {
    FILE *fp = popen("netstat -tn", "r");
    if (!fp) {
        printf("Failed to run netstat command\n");
        return;
    }

    printf("\nActive TCP Connections:\n");
    printf("Proto Local Address           Foreign Address         State\n");
    
    char line[256];
    int connection_count = 0;
    // Skip header lines
    for (int i = 0; i < 2; i++) {
        fgets(line, sizeof(line), fp);
    }
    
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "tcp")) {
            printf("%s", line);
            connection_count++;
        }
    }
    
    printf("\nTotal TCP connections: %d\n", connection_count);
    pclose(fp);
}

void check_system_security() {
    printf("\nSystem Security Check:\n");

    // Check for ASLR (Address Space Layout Randomization)
    FILE *aslr = fopen("/proc/sys/kernel/randomize_va_space", "r");
    if (aslr) {
        char value;
        fscanf(aslr, "%c", &value);
        printf("ASLR Status: %s (value=%c)\n", 
               value != '0' ? "Enabled" : "Disabled", value);
        fclose(aslr);
    }

    // Check core dump settings
    FILE *core = fopen("/proc/sys/kernel/core_pattern", "r");
    if (core) {
        char pattern[256];
        fgets(pattern, sizeof(pattern), core);
        printf("Core dump pattern: %s", pattern);
        fclose(core);
    }

    // Check for running security services
    printf("\nSecurity Services Status:\n");
    system("systemctl is-active --quiet apparmor && "
           "echo 'AppArmor: Running' || echo 'AppArmor: Not Running'");
    system("systemctl is-active --quiet selinux && "
           "echo 'SELinux: Running' || echo 'SELinux: Not Running'");
    system("systemctl is-active --quiet ufw && "
           "echo 'UFW Firewall: Running' || echo 'UFW Firewall: Not Running'");

    // Check for open ports
    printf("\nOpen Ports:\n");
    system("ss -tuln | grep LISTEN");
}

// New function implementation
void analyze_process_resources() {
    printf("\nAnalyzing Process Resource Usage...\n");

    // Structure to hold process information
    struct ProcessInfo {
        pid_t pid;
        char name[256];
        float cpu_usage;
        long memory_usage;
        long read_bytes;
        long write_bytes;
    };

    // Arrays to store top and bottom processes
    ProcessInfo top_cpu[5];
    ProcessInfo bottom_cpu[5];
    ProcessInfo top_memory[5];
    ProcessInfo bottom_memory[5];

    // Initialize arrays
    for (int i = 0; i < 5; i++) {
        top_cpu[i].cpu_usage = -1;
        bottom_cpu[i].cpu_usage = 101;
        top_memory[i].memory_usage = -1;
        bottom_memory[i].memory_usage = LONG_MAX;
    }

    DIR *dir = opendir("/proc");
    if (!dir) {
        perror("Failed to open /proc");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        // Check if the entry is a process directory (numeric name)
        if (entry->d_type == DT_DIR) {
            char *endptr;
            pid_t pid = strtol(entry->d_name, &endptr, 10);
            if (*endptr != '\0') continue;  // Not a number

            char stat_path[256];
            char status_path[256];
            char io_path[256];
            sprintf(stat_path, "/proc/%d/stat", pid);
            sprintf(status_path, "/proc/%d/status", pid);
            sprintf(io_path, "/proc/%d/io", pid);

            // Get process information
            FILE *stat_file = fopen(stat_path, "r");
            FILE *status_file = fopen(status_path, "r");
            FILE *io_file = fopen(io_path, "r");

            if (stat_file && status_file) {
                ProcessInfo current;
                current.pid = pid;

                // Read process name and CPU usage from stat
                char state;
                unsigned long utime, stime;
                fscanf(stat_file, "%*d (%[^)]) %c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu",
                       current.name, &state, &utime, &stime);

                // Calculate CPU usage percentage
                current.cpu_usage = ((float)(utime + stime) / sysconf(_SC_CLK_TCK)) * 100;

                // Read memory usage from status
                char line[256];
                while (fgets(line, sizeof(line), status_file)) {
                    if (strncmp(line, "VmRSS:", 6) == 0) {
                        sscanf(line, "VmRSS: %ld", &current.memory_usage);
                        break;
                    }
                }

                // Read I/O statistics if available
                if (io_file) {
                    while (fgets(line, sizeof(line), io_file)) {
                        if (strncmp(line, "read_bytes:", 11) == 0)
                            sscanf(line, "read_bytes: %ld", &current.read_bytes);
                        else if (strncmp(line, "write_bytes:", 12) == 0)
                            sscanf(line, "write_bytes: %ld", &current.write_bytes);
                    }
                    fclose(io_file);
                }

                // Update top and bottom CPU usage arrays
                for (int i = 0; i < 5; i++) {
                    if (current.cpu_usage > top_cpu[i].cpu_usage) {
                        memmove(&top_cpu[i + 1], &top_cpu[i], sizeof(ProcessInfo) * (4 - i));
                        top_cpu[i] = current;
                        break;
                    }
                    if (current.cpu_usage < bottom_cpu[i].cpu_usage && current.cpu_usage > 0) {
                        memmove(&bottom_cpu[i + 1], &bottom_cpu[i], sizeof(ProcessInfo) * (4 - i));
                        bottom_cpu[i] = current;
                        break;
                    }
                }

                // Update top and bottom memory usage arrays
                for (int i = 0; i < 5; i++) {
                    if (current.memory_usage > top_memory[i].memory_usage) {
                        memmove(&top_memory[i + 1], &top_memory[i], sizeof(ProcessInfo) * (4 - i));
                        top_memory[i] = current;
                        break;
                    }
                    if (current.memory_usage < bottom_memory[i].memory_usage && current.memory_usage > 0) {
                        memmove(&bottom_memory[i + 1], &bottom_memory[i], sizeof(ProcessInfo) * (4 - i));
                        bottom_memory[i] = current;
                        break;
                    }
                }

                fclose(stat_file);
                fclose(status_file);
            }
        }
    }
    closedir(dir);

    // Print results
    printf("\nTop 5 CPU-Intensive Processes:\n");
    printf("PID\tCPU%%\tMEM(KB)\tPROCESS\n");
    for (int i = 0; i < 5 && top_cpu[i].cpu_usage > 0; i++) {
        printf("%d\t%.1f\t%ld\t%s\n", 
               top_cpu[i].pid, 
               top_cpu[i].cpu_usage, 
               top_cpu[i].memory_usage, 
               top_cpu[i].name);
    }

    printf("\nBottom 5 CPU-Usage Processes:\n");
    printf("PID\tCPU%%\tMEM(KB)\tPROCESS\n");
    for (int i = 0; i < 5 && bottom_cpu[i].cpu_usage < 100; i++) {
        printf("%d\t%.1f\t%ld\t%s\n", 
               bottom_cpu[i].pid, 
               bottom_cpu[i].cpu_usage, 
               bottom_cpu[i].memory_usage, 
               bottom_cpu[i].name);
    }

    printf("\nTop 5 Memory-Intensive Processes:\n");
    printf("PID\tMEM(KB)\tCPU%%\tPROCESS\n");
    for (int i = 0; i < 5 && top_memory[i].memory_usage > 0; i++) {
        printf("%d\t%ld\t%.1f\t%s\n", 
               top_memory[i].pid, 
               top_memory[i].memory_usage, 
               top_memory[i].cpu_usage, 
               top_memory[i].name);
    }

    printf("\nBottom 5 Memory-Usage Processes:\n");
    printf("PID\tMEM(KB)\tCPU%%\tPROCESS\n");
    for (int i = 0; i < 5 && bottom_memory[i].memory_usage < LONG_MAX; i++) {
        printf("%d\t%ld\t%.1f\t%s\n", 
               bottom_memory[i].pid, 
               bottom_memory[i].memory_usage, 
               bottom_memory[i].cpu_usage, 
               bottom_memory[i].name);
    }

    // Additional system-wide statistics
    printf("\nSystem-wide Resource Usage Summary:\n");
    system("echo 'CPU Usage:' && top -bn1 | grep 'Cpu(s)' | awk '{print $2 + $4}' | tr -d '\n' && echo '%'");
    system("echo 'Memory Usage:' && free -m | grep 'Mem:' | awk '{print $3/$2 * 100.0}' | tr -d '\n' && echo '%'");
    system("echo 'Swap Usage:' && free -m | grep 'Swap:' | awk '{print $3/$2 * 100.0}' | tr -d '\n' && echo '%'");
}