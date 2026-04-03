# H298A V1.0 Root Enabler (CLI)

A simplified Windows CLI tool for enabling root access on **ZTE ZXHN H298A V1.0**.

## What this does

- Starts local DHCP + ARP + ACS services
- Handles CWMP Inform/response flow
- Runs strict H298A precheck
- Applies fixed H298A root parameter set
- Stops services and performs cleanup when done

## Requirements

- Windows
- Run terminal as Administrator
- [Npcap](https://npcap.com/) installed

## Dependencies

Install Python package dependency:

```bash
pip install scapy
```

Use Npcap with WinPcap-compatible mode enabled.

## Network setup
- Connect the pc with the router's WAN port with an ethernet cable.


## Usage

```bash
python h298a.py -p Passwd123
```

Password option:

- `-p <value>` short form for password
- `--password <value>` long form for password

The tool now shows an interactive adapter menu at startup. Pick the adapter number and continue.

Expected runtime flow:

1. Adapter selection
2. Services start and wait for DHCP/CWMP traffic
3. CWMP `Inform` received
4. Parameter injection (`GetParameterValues` then `SetParameterValues`)
5. Success message


The logs for the app can be found under:

- `C:/temp/h298/console.log` for runtime events
- `C:/temp/h298/sessions/<serial>/` for CWMP request/response XML captures


After success, output includes:

- `Device successfully rooted`
- `Username: root`
- `Password: <your inputted password>`
- `Enable SSH under Easy Menu -> Local Access -> SSH Port`

Then enable SSH in router UI:

- `Easy Menu -> Local Access -> SSH Port`

## Password format

- Minimum 8 characters
- At least one number
- Blocks: `pass`, `password`, `root`, `admin`
- `Passwd123` is explicitly allowed

## Notes

- This tool is for **H298A V1.0** only.
- Use only on devices/networks you own or are authorized to test.


## Technical description

- The tool binds local services used by the device provisioning flow: DHCP, ARP handling, and an HTTP ACS endpoint.
- DHCP and ARP behavior are used to place the router on a predictable local path so CWMP requests are sent to the local ACS.
- The ACS service processes TR-069/CWMP RPCs (including `Inform`) and returns SOAP responses expected by the H298A V1.0 flow.
- During the CWMP exchange, the app submits the root-enabling parameter set and requested root password via `SetParameterValues`.
- Session state is tracked until the workflow reaches completion, then all services are stopped and local network settings are cleaned up.
- Adapter selection is explicit and validated for Scapy usability to avoid binding to non-functional virtual interfaces.
