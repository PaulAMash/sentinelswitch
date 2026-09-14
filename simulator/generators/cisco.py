"""Write Cisco IOS artifacts: running configuration and `show` transcripts before/after quarantine."""

from __future__ import annotations

from pathlib import Path

from sentinelswitch.simulator import cli_render
from sentinelswitch.simulator.twin import SwitchTwin
from simulator.canonical import Environment

SHOW_FILES = {
    "show-version.txt": "show version",
    "show-vlan-brief.txt": "show vlan brief",
    "show-interfaces-status.txt": "show interfaces status",
    "show-interfaces-trunk.txt": "show interfaces trunk",
    "show-mac-address-table.txt": "show mac address-table",
    "show-ip-dhcp-snooping.txt": "show ip dhcp snooping",
    "show-ip-dhcp-snooping-binding.txt": "show ip dhcp snooping binding",
    "show-ip-arp-inspection.txt": "show ip arp inspection",
    "show-port-security.txt": "show port-security",
    "show-port-security-interface-gi1-0-23.txt": "show port-security interface Gi1/0/23",
    "show-spanning-tree-summary.txt": "show spanning-tree summary",
    "show-errdisable-recovery.txt": "show errdisable recovery",
    "show-monitor-session-1.txt": "show monitor session 1",
    "show-logging.txt": "show logging",
    "show-authentication-sessions.txt": "show authentication sessions",
    "show-authentication-sessions-interface-gi1-0-23.txt": "show authentication sessions interface Gi1/0/23",
    "show-interfaces-gi1-0-23-switchport.txt": "show interfaces Gi1/0/23 switchport",
    "show-running-config-interface-gi1-0-23.txt": "show running-config interface Gi1/0/23",
    "show-mac-address-table-interface-gi1-0-23.txt": "show mac address-table interface Gi1/0/23",
    "show-vlan-id-50.txt": "show vlan id 50",
}


def _transcript(twin: SwitchTwin, command: str) -> str:
    return f"{twin.hostname}#{command}\n{cli_render.run_show(twin, command)}\n{twin.hostname}#\n"


def write_show_outputs(twin: SwitchTwin, out_dir: Path, label: str) -> list[str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for fname, cmd in SHOW_FILES.items():
        text = (
            f"! SentinelSwitch digital twin - simulated transcript ({label})\n! captured at {twin.now.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} UTC\n"
            + _transcript(twin, cmd)
        )
        (out_dir / fname).write_text(text, encoding="utf-8")
        written.append(fname)
    return written


def write_configs(env: Environment, observed: SwitchTwin, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "SW01-running-config.txt").write_text(
        "! SentinelSwitch digital twin - `show running-config` as observed at the dataset baseline\n"
        "! Secrets are placeholders. Includes the deliberate configuration drift on Gi1/0/22, Gi1/0/35 and Gi1/0/41.\n"
        + cli_render.render_running_config(observed)
        + "\n",
        encoding="utf-8",
    )
    desired = SwitchTwin.baseline(env, now=observed.now, apply_drift=False)
    (out_dir / "SW01-baseline.cfg").write_text(
        "! SentinelSwitch digital twin - desired configuration rendered from simulator/fixtures/environment.yaml\n"
        "! This is the configuration-as-code source of truth used by the drift engine.\n"
        + cli_render.render_running_config(desired, header=False)
        + "\n",
        encoding="utf-8",
    )
