# System Resource Monitoring and Management Tool

## Overview

This C++ project is a comprehensive system monitoring and resource management tool designed to provide in-depth insights into system performance, resource utilization, and process management.

## Features

### Resource Monitoring
- CPU Usage Tracking
- Memory Utilization Analysis
- Disk I/O Monitoring
- Network Usage Tracking
- Process Tree Monitoring

### Advanced Scheduling Algorithms
- Round Robin CPU Scheduling
- SSTF (Shortest Seek Time First) Disk Scheduling
- FCFS (First-Come, First-Served) Disk Scheduling

### System Management Capabilities
- Resource Usage Logging
- Automatic Alerting System
- Process Priority Control
- Resource Limit Setting
- System Security Checks

## Key Functions

- `monitor_resources()`: Comprehensive system resource monitoring
- `trigger_alerts()`: Set and check resource usage thresholds
- `log_resource_usage()`: Log system resource consumption
- `control_process()`: Process management and control
- `set_process_priority()`: Dynamically adjust process priorities
- `analyze_system_performance()`: In-depth system performance analysis

## Prerequisites

- Linux/Unix-based Operating System
- GCC/G++ Compiler
- POSIX Threads (pthread) Support
- System Monitoring Utilities

## Compilation

```bash
g++ -o system_monitor mainfile.cpp -lpthread
```

## Usage

Run the compiled binary with appropriate permissions:

```bash
./system_monitor
```

## Dependencies

- `<pthread.h>`: Thread management
- `<sys/resource.h>`: Resource limit and usage
- `<sys/sysinfo.h>`: System information
- `<sys/statvfs.h>`: File system information
- `<dirent.h>`: Directory operations
- `<sys/socket.h>`: Network operations

## Configuration

Adjust thresholds in the source code:
- `cpu_threshold`: CPU usage alert level
- `memory_threshold`: Memory usage alert level
- `disk_io_threshold`: Disk I/O usage alert level
