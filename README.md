# OT Network Monitoring & Detection Engineering Lab

Hands-on OT/ICS detection lab: network visibility, Modbus/TCP baseline,
Suricata detections and validation.

**Builds on:** [Project 1 — Aviation Fuel Farm OT Security](https://github.com/alexmpamis/Aviation-Fuel-Farm-OT-Security)

> The goal is not to build a SIEM. The goal is to learn how an OT defender thinks.

## Progress

- [x] Phase 1 — Visibility
- [x] Phase 2 — Baseline ([report](03_Baseline/baseline_report.md))
- [ ] Phase 3 — Detection (Suricata)
- [ ] Phase 4 — Validation & Tuning

## Phase 2 summary

In this phase, I created an OT baseline report. Its purpose is to describe
normal Modbus/TCP behavior, so that new traffic can be compared against it
and anything suspicious can be recognized. To build it, I captured traffic
with tcpdump on a passive sensor (ot-monitor) and analyzed it in Wireshark.
I documented the assets and their roles, the normal polling behavior, and
normal operator activity: a complete transfer made of a sequence of FC6
writes from 192.168.56.104 to 192.168.56.101.

### Key findings

- FUXA polls the PLC about once per second, using FC3 only, reading one
  block of 17 registers starting at address 1024.
- Register 1024 is not used by the PLC program and always stays 0.
- To start a transfer, the HMI writes START as 0 and then 1 (a rising edge).
  STOP is written as 1 and then reset to 0.
- When the PLC runtime was not running, FUXA's connection attempts were
  refused (SYN → RST) and retried about every 5 seconds.
