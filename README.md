# CIP-B105 – Morris Worm Controlled Attack Observation and Forensic Reconstruction

**Student:** Fuseini Imoru Kantuogaa  
**Course:** CIP-B105 – Cybersecurity and Digital Forensics  
**Laboratory:** Morris Worm Investigation  
**Environment:** Linux, Docker, Python, and virtual machines

## Overview

This laboratory investigates the behaviour of the Morris Worm in a controlled virtual environment. The exercise focuses on process execution, network services, file-system artefacts, timestamp analysis, and forensic reconstruction.

The investigation examines the execution of `worm.py`, the listener associated with port `9999`, and the creation of `badfile`. It applies Linux process-management commands, network inspection utilities, file metadata tools, and MD5 hashing to establish a sequence of events.

## Objectives

- Investigate Linux processes and process hierarchies.
- Identify worm-related processes and network listeners.
- Examine TCP port `9999` and associated services.
- Analyse `worm.py` and `badfile`.
- Examine modification, access, and metadata-change timestamps.
- Calculate MD5 hashes for examined files.
- Construct a forensic timeline.
- Identify discrepancies between server time and the expected investigation time.
- Correlate process, network, and file-system evidence.

## Tools and Environment

| Tool | Purpose |
|---|---|
| Linux virtual machines | Controlled malware investigation |
| Docker | Containerised laboratory environment |
| Python | Worm simulation and process investigation |
| `ps` | Process listing |
| `pstree` | Process hierarchy |
| `netstat` | Network and listening-port inspection |
| `nc` | Network listener investigation |
| `stat` | File metadata examination |
| `ls` | File listing and timestamps |
| `md5sum` | MD5 hash calculation |
| `date` and `timedatectl` | System time and time-zone inspection |

## 1. Memory and Process Investigation

A process is an instance of a program being executed by the operating system. Process analysis helps identify suspicious execution, determine the process owner, and examine relationships between processes.

### List processes in the current terminal

```bash
ps
```

This displays processes associated with the current terminal session.

Important fields include:

- **PID:** Process identifier.
- **TTY:** Associated terminal.
- **TIME:** Accumulated CPU time.
- **CMD:** Command that launched the process.

### List processes belonging to all users

```bash
ps aux
```

The output provides a broader view of running processes, including their owners, CPU and memory usage, status, and command lines.

### Examine process hierarchy

```bash
pstree -p
```

This displays processes in a tree structure and includes process identifiers. It helps investigators identify parent-child relationships.

### Locate the worm process

```bash
ps aux | grep '[w]orm.py'
```

The output should be examined for the process owner, PID, start time, and command line.

Process-state indicators such as `S` and `s` can provide additional information about a process's current state and role.

**Forensic significance:** Process inspection provides evidence of running activity, but a process listing is only a snapshot. Findings should be correlated with network and file-system evidence.

## 2. Investigating Network Ports Used by the Worm

The laboratory guide identifies `worm.py` as a process of interest and describes a listener associated with TCP port `9999`.

Network investigation helps establish which services were listening during the simulation.

### List listening services

```bash
netstat -tulpn | grep LISTEN
```

The command displays TCP and UDP listening sockets, numeric addresses and ports, and process information where permissions permit.

An alternative is:

```bash
ss -lntup
```

### Examine port 9999

```bash
ss -lntup | grep ':9999'
```

The results should be recorded with the listening address, port, protocol, and associated process.

### Investigate Netcat

The laboratory guide uses the `nc` command to demonstrate a listener on port `9999`. Netcat can create network connections and listen for incoming connections.

The investigator should compare the listener's details with the process listing to determine whether the network service corresponds to the observed laboratory activity.

**Forensic significance:** A listening port does not independently prove malicious activity. Process information, network observations, and file artefacts must be considered together.

## 3. Analysing Worm-Related Files

The investigation examines two important artefacts:

- `worm.py` — The Python file associated with the simulated worm.
- `badfile` — A file whose creation was associated with the observed execution sequence.

### Examine file details

```bash
ls -l worm.py badfile
```

This provides a file listing, including permissions, ownership, sizes, and modification times.

### Examine detailed metadata

```bash
stat worm.py
stat badfile
```

The `stat` command reports detailed file metadata, including access, modification, and status-change timestamps.

### Understanding timestamps

| Timestamp | Description | Investigative use |
|---|---|---|
| `mtime` | Last modification of file contents | Helps establish when file content was last changed |
| `ctime` | Last change to inode metadata | Helps identify changes to file contents or metadata |
| `atime` | Last access time | May indicate when a file was read or accessed |

The laboratory guide notes that changing a file can also affect other timestamps. Timestamp interpretation must therefore account for the operating system and file-system behaviour.

## 4. File Hash Analysis

Hashing provides a repeatable way to identify the contents of an examined file.

### Calculate MD5 hashes

```bash
md5sum worm.py badfile
```

The resulting hash values should be recorded alongside the filenames.

| File | Hash | Purpose |
|---|---|---|
| `worm.py` | Actual output to be recorded | File identification and comparison |
| `badfile` | Actual output to be recorded | File identification and comparison |

The original hash values must be obtained from the actual laboratory files; they should not be estimated.

**Forensic significance:** Matching hashes support the conclusion that two files have identical content, subject to the limitations of the hash algorithm. MD5 is included because it is part of the laboratory exercise; SHA-256 is preferable for stronger modern integrity verification.

## 5. Creating a Forensic Timeline

The investigation uses file timestamps to reconstruct the sequence of activities involving `worm.py` and `badfile`.

The guide records the following observations:

| Time recorded in the guide | Event | Interpretation |
|---|---|---|
| 08:09:23 AM, 3 August 2022 | `worm.py` was modified | A change to the file contents was recorded |
| 08:10:18 AM | `worm.py` was accessed | The file was accessed approximately 55 seconds after the recorded modification |
| 08:18:15 AM | `badfile` was created | The guide associates the creation with execution of `worm.py` |
| Approximately 09:36 AM | Later worm-related activity | The guide describes another receipt, execution, or stopping event |

These times are based on the laboratory guide and should be verified against the original terminal outputs when available.

### Investigating time-zone discrepancies

The guide highlights a server clock that was approximately one hour behind the expected time.

Check the current system time and time-zone configuration using:

```bash
date
timedatectl
```

Where a particular time zone is required for interpreting evidence, record the original time zone and any conversion applied.

The guide also demonstrates examining file listings under an explicitly selected time zone:

```bash
TZ="EST" ls -l
```

The selected time zone must be appropriate to the evidence being examined. A time-zone setting changes how timestamps are displayed; it does not repair an incorrect system clock.

**Forensic significance:** Clock discrepancies can produce an inaccurate reconstruction if timestamps from different systems are compared without normalisation. Investigators should preserve original timestamps and document any corrections or conversions.

## 6. Correlating the Attack and Victim Machines

The laboratory guide distinguishes an attack machine from a victim machine. The relationship between the machines is relevant to understanding how the simulated worm was received, executed, and associated with subsequent artefacts.

The investigation should correlate:

1. The execution of `worm.py`.
2. The listener associated with port `9999`.
3. The creation and modification of relevant files.
4. The timestamps recorded on each machine.
5. Any differences between the machines' clock settings.

The guide's timeline indicates an initial worm-related event at approximately 08:18 AM and later activity around 09:36 AM. These observations require careful interpretation because the server clock was reported to be incorrect.

**Forensic significance:** Comparing evidence from multiple machines can strengthen a reconstruction, but timestamps must be normalised and supported by other observations before a definitive sequence is claimed.

## 7. Key Findings

The investigation demonstrates the following forensic principles:

- Process listings can identify running programs and provide details about their execution.
- Process trees help reveal parent-child relationships.
- Listening-port inspection can identify network services associated with suspicious activity.
- File metadata can provide useful evidence for reconstructing events.
- MD5 hashes support file identification and comparison.
- Timestamp analysis must distinguish file-content changes, metadata changes, and file access.
- Time-zone differences and inaccurate clocks can affect event reconstruction.
- Correlating process, network, and file-system evidence produces a more reliable analysis than relying on a single artefact.

## 8. Limitations

The reliability of the reconstruction depends on the completeness of the recorded command outputs, the accuracy of the system clocks, and the availability of the original files.

A process listing cannot establish the complete history of a process. File timestamps can change, and the creation of a file alone does not conclusively establish which process created it. Hash values also need to be calculated from the actual evidence.

The reported events should therefore be treated as laboratory observations and supported by screenshots, terminal outputs, and the original investigation artefacts.

## 9. Safety and Evidence Handling

All activities must be conducted within an authorised, isolated laboratory environment.

- Do not execute the simulated worm on production systems or public networks.
- Preserve original evidence and use working copies for examination.
- Record the commands and their actual outputs.
- Document system time and time-zone settings.
- Calculate and record file hashes.
- Keep screenshots and reports organised.
- Distinguish observed facts from interpretations.

## Conclusion

The Morris Worm investigation provided practical experience in Linux process analysis, network-service investigation, file metadata examination, hashing, and forensic timeline reconstruction.

The examination of `worm.py`, `badfile`, and the listener associated with port `9999` demonstrated how process, network, and file-system evidence can be correlated to understand simulated malware activity.

The exercise also emphasised the importance of accurate timestamps, time-zone verification, file integrity, and careful documentation. These techniques are valuable in malware analysis, incident response, and digital forensic investigations.

## Author

**Fuseini Imoru Kantuogaa**

Cybersecurity and Digital Forensics
