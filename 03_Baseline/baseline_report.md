# Phase 2 — OT Baseline Report

Project: OT Network Monitoring & Detection Lab
Builds on: Project 1 — Aviation Fuel Farm OT Security

## 1. Purpose

A baseline describes what normal Modbus/TCP communication looks like in this lab.
We need it because detection depends on comparison: without knowing what is normal,
we cannot recognize what is suspicious.

The baseline records:
- who talks to whom, and on which port
- function codes and registers
- polling frequency
- normal reads and writes
- operator actions: START, STOP, active transfer and completion
- errors and exceptions

Artifacts: baseline PCAP files and a baseline table.

## 2. Capture details

- Sensor: ot-monitor (192.168.56.103), passive, not part of the Modbus conversation
- Interface: enp0s8
- Tool and filter: tcpdump, `port 502`
- Files:
  - `phase1_visibility.pcap`: 200 packets of idle polling
  - `phase2_baseline.pcap`: 5 minutes, 710 packets (PLC start + one full operator transfer)
- Date: 8 November 2026

## 3. Assets and roles

| IP             | Device     | Role                                  | Modbus access to PLC        |
|----------------|------------|---------------------------------------|-----------------------------|
| 192.168.56.101 | Ubuntu VM  | PLC (OpenPLC), Modbus/TCP server :502 | n/a (it is the PLC)         |
| 192.168.56.102 | Kali Linux | Attacker (testing only)               | No: blocked by UFW          |
| 192.168.56.103 | ot-monitor | Passive sensor (tcpdump, Suricata)    | No: listens only            |
| 192.168.56.104 | FUXA HMI   | HMI, Modbus/TCP client                | Yes: the only allowed host  |

## 4. Normal polling behavior

| Item              | Normal value                                           |
|-------------------|--------------------------------------------------------|
| Client → Server   | 192.168.56.104 (FUXA) → 192.168.56.101 (PLC), TCP/502  |
| Function code     | FC3 (Read Holding Registers) only, no writes when idle |
| Registers         | Start 1024, count 17 (1024–1040, 0-based)              |
| Polling interval  | ~1 query per second (~3,600 per hour)                  |
| Unused register   | 1024 (%MW0) is not used by the PLC program, always 0   |
| Exceptions        | None observed during normal operation                  |

Note: Wireshark shows 0-based protocol addresses. mbpoll uses 1-based
references, so mbpoll register = packet address + 1
(e.g. Tank Quantity: mbpoll 1026 = packet 1025).

## 5. Normal operator activity

A normal transfer is a sequence of FC6 (Write Single Register) writes
from 192.168.56.104 to 192.168.56.101. No other host writes.

| Packet addr (0-based) | mbpoll ref (1-based) | Variable                   | Normal write             |
|-----------------------|----------------------|----------------------------|--------------------------|
| 1025                  | 1026                 | tank_quantity              | value set by operator    |
| 1026                  | 1027                 | truck_current_qty          | value set by operator    |
| 1027                  | 1028                 | truck_max_capacity         | value set by operator    |
| 1028                  | 1029                 | requested_qty              | e.g. 500 (0x01F4)        |
| 1034                  | 1035                 | truck_connected_sim        | 1                        |
| 1035                  | 1036                 | truck_grounded_sim         | 1                        |
| 1036                  | 1037                 | fuel_quality_released_sim  | 1                        |
| 1037                  | 1038                 | e_stop_clear_sim           | 1                        |
| 1038                  | 1039                 | truck_full_sim             | 0                        |
| 1039                  | 1040                 | START                      | 0, then 1 (rising edge)  |
| 1040                  | 1041                 | STOP                       | 1, then 0 (reset)        |

Sequence: values → permissives → START (0 → 1) → transfer runs → STOP (1 → 0).
Observed in phase2_baseline.pcap: 13 write requests, each acknowledged by the PLC.

## 6. Availability observations

When the PLC runtime was not running, FUXA's connection attempts were refused:
each SYN from 192.168.56.104 was answered with RST, ACK from 192.168.56.101.
FUXA retried about every 5 seconds until the PLC was started (~85 s into the
capture). Then the normal TCP handshake completed and FC3 polling began.

- RST (not a timeout) shows the firewall allowed .104; the Modbus service
  simply was not listening yet.
- During this period the operator had no view and no control of the process.
- Detection idea: repeated RST from PLC port 502 = Modbus service down.
  RST sent to an unknown host = possible Modbus scanning.

## 7. Lab simplifications

- The HMI writes simulated sensor values (truck_connected_sim,
  truck_grounded_sim, fuel_quality_released_sim, e_stop_clear_sim,
  truck_full_sim). In a real fuel farm these come from field sensors through
  PLC inputs. An HMI writing them in production would indicate process data
  manipulation.
- Analysis tools run on the PLC VM for simplicity. In production they would
  run on a separate engineering workstation.
- This baseline covers one 5-minute session with one HMI and one PLC. A real
  baseline would cover days or weeks, including shift changes and maintenance.

## 8. What this means for detection

| Detection | Based on baseline fact | Alert when...                                              |
|-----------|------------------------|------------------------------------------------------------|
| DET-01    | Section 3, 4           | Any host other than .104 connects to 192.168.56.101:502    |
| DET-02    | Section 4, 5           | An FC6/FC16 write comes from a source outside the allowlist |
| DET-03    | Section 4, 5           | A write targets a register never written in the baseline (PLC-calculated values, unused 1024), even from the otherwise trusted HMI |
| DET-04    | Section 5              | A write to START (1039) or STOP (1040) comes from any source other than .104 |
| DET-05    | Section 4, 6           | Traffic differs from the baseline pattern: much faster than ~1 query/s, new function codes (e.g. FC8, FC43), reads outside 1024–1040, or repeated RSTs |
