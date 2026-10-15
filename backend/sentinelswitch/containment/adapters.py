"""Switch adapter abstraction.

The response engine never touches switch state directly; it calls a `SwitchAdapter`. The shipped
implementation drives the digital twin. A production `IOSSSHAdapter` would implement the same
methods with the IOS command sequences in automation/adapters/simulated-cisco-2960x.yaml.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sentinelswitch.simulator import cli_render
from sentinelswitch.simulator.twin import SwitchTwin
from simulator.canonical import short_ifname


class ProtectedInterfaceError(PermissionError):
    """Raised when an action targets an interface the adapter refuses to change."""


@dataclass
class AdapterResult:
    ok: bool
    interface: str
    action: str
    commands: list[str]
    before: dict[str, Any]
    after: dict[str, Any]
    transcript: str
    ts: str
    notes: list[str] = field(default_factory=list)


class SwitchAdapter(ABC):
    hostname: str

    @abstractmethod
    def get_interface(self, interface: str) -> dict[str, Any]: ...

    @abstractmethod
    def get_mac_table(self, mac: str | None = None) -> list[dict[str, Any]]: ...

    @abstractmethod
    def get_dhcp_bindings(self) -> list[dict[str, Any]]: ...

    @abstractmethod
    def set_access_vlan(
        self, interface: str, vlan: int, *, reason: str, workflow: str, at: datetime
    ) -> AdapterResult: ...

    @abstractmethod
    def shutdown(self, interface: str, *, reason: str, workflow: str, at: datetime) -> AdapterResult: ...

    @abstractmethod
    def restore(self, interface: str, *, actor: str, reason: str, at: datetime) -> AdapterResult: ...

    @abstractmethod
    def show(self, command: str) -> str: ...

    @abstractmethod
    def verify_vlan(self, interface: str, vlan: int) -> tuple[bool, str]: ...

    @abstractmethod
    def verify_shutdown(self, interface: str) -> tuple[bool, str]: ...


class SimulatedCisco2960XAdapter(SwitchAdapter):
    """Adapter that operates on the deterministic digital twin."""

    def __init__(self, twin: SwitchTwin, protected: list[str] | None = None):
        self.twin = twin
        self.hostname = twin.hostname
        self.protected = set(protected or [i.name for i in twin.interfaces.values() if i.protected])

    # ---- guards -----------------------------------------------------------------------------
    def _guard(self, interface: str) -> None:
        name = short_ifname(interface)
        iface = self.twin.interfaces.get(name)
        if iface is None:
            raise KeyError(f"unknown interface {interface}")
        if name in self.protected or iface.protected:
            raise ProtectedInterfaceError(
                f"{name} is a protected infrastructure interface; adapter refuses to modify it"
            )
        if iface.is_trunk:
            raise ProtectedInterfaceError(f"{name} is a trunk; adapter refuses to modify trunk interfaces")
        if iface.span_destination:
            raise ProtectedInterfaceError(f"{name} is the SPAN destination; adapter refuses to modify it")

    # ---- reads ------------------------------------------------------------------------------
    def get_interface(self, interface: str) -> dict[str, Any]:
        i = self.twin.interfaces[short_ifname(interface)]
        return {
            "name": i.name,
            "description": i.description,
            "mode": i.mode,
            "access_vlan": i.access_vlan,
            "oper_vlan": i.oper_vlan,
            "admin_status": i.admin_status,
            "oper_status": i.oper_status,
            "protected": i.protected,
            "quarantined": i.quarantined,
            "port_class": i.port_class,
        }

    def get_mac_table(self, mac: str | None = None) -> list[dict[str, Any]]:
        entries = self.twin.find_mac(mac) if mac else self.twin.mac_table
        return [e.__dict__ for e in entries]

    def get_dhcp_bindings(self) -> list[dict[str, Any]]:
        return [b.__dict__ for b in self.twin.dhcp_bindings]

    def show(self, command: str) -> str:
        return cli_render.run_show(self.twin, command)

    # ---- writes -----------------------------------------------------------------------------
    def set_access_vlan(self, interface: str, vlan: int, *, reason: str, workflow: str, at: datetime) -> AdapterResult:
        name = short_ifname(interface)
        self._guard(name)
        before = self.get_interface(name)
        change = self.twin.quarantine(name, vlan, reason=reason, workflow=workflow, at=at)
        after = self.get_interface(name)
        commands = [
            "configure terminal",
            f"interface {self.twin.interfaces[name].long_name}",
            f" switchport access vlan {vlan}",
            "end",
            "write memory",
        ]
        transcript = self._transcript(commands, at)
        return AdapterResult(
            True,
            name,
            "set_access_vlan",
            commands,
            before,
            after,
            transcript,
            at.isoformat(),
            notes=[f"VLAN {change['from_vlan']} -> {vlan}"],
        )

    def shutdown(self, interface: str, *, reason: str, workflow: str, at: datetime) -> AdapterResult:
        name = short_ifname(interface)
        self._guard(name)
        before = self.get_interface(name)
        self.twin.shutdown(name, actor="sentinel", reason=reason, at=at, hold=True, workflow=workflow)
        after = self.get_interface(name)
        commands = [
            "configure terminal",
            f"interface {self.twin.interfaces[name].long_name}",
            " shutdown",
            "end",
            "write memory",
        ]
        return AdapterResult(
            True, name, "shutdown", commands, before, after, self._transcript(commands, at), at.isoformat()
        )

    def restore(self, interface: str, *, actor: str, reason: str, at: datetime) -> AdapterResult:
        name = short_ifname(interface)
        self._guard(name)
        before = self.get_interface(name)
        result = self.twin.restore(name, actor=actor, reason=reason, at=at)
        after = self.get_interface(name)
        if result.get("action") == "restore_vlan":
            commands = [
                "configure terminal",
                f"interface {self.twin.interfaces[name].long_name}",
                f" switchport access vlan {result['to_vlan']}",
                "end",
                "write memory",
            ]
        elif result.get("action") == "no_shutdown":
            commands = [
                "configure terminal",
                f"interface {self.twin.interfaces[name].long_name}",
                " no shutdown",
                "end",
                "write memory",
            ]
        else:
            commands = []
        return AdapterResult(
            bool(commands),
            name,
            "restore",
            commands,
            before,
            after,
            self._transcript(commands, at) if commands else "",
            at.isoformat(),
            notes=[result.get("action", "none")],
        )

    # ---- remediation ------------------------------------------------------------------------
    def apply_baseline(
        self, interface: str, settings: list[str], *, intent, reason: str, actor: str, at: datetime
    ) -> tuple[str, list[str]]:
        """Re-apply the named settings from the port intent and return (transcript, commands)."""
        name = short_ifname(interface)
        self._guard(name)
        lines = self.twin.apply_intent(
            name, settings, intent.settings, intent.description, actor=actor, reason=reason, at=at
        )
        commands = ["configure terminal"] + lines + ["end", "write memory"]
        return self._transcript(commands, at), commands

    def add_span_source(self, vlan: int, *, reason: str, actor: str, at: datetime) -> tuple[str, list[str]]:
        lines = self.twin.add_span_source(vlan, actor=actor, reason=reason, at=at)
        commands = ["configure terminal"] + [f" {ln}" for ln in lines] + ["end", "write memory"]
        return self._transcript(commands, at), commands

    def reauthenticate(self, interface: str, *, reason: str, actor: str, at: datetime) -> dict[str, Any]:
        name = short_ifname(interface)
        self._guard(name)
        events = self.twin.reauthenticate(name, actor=actor, reason=reason, at=at)
        cmd = f"clear authentication sessions interface {self.twin.interfaces[name].long_name}"
        transcript = f"{self.twin.hostname}#{cmd}\n{self.twin.hostname}#"
        return {"transcript": transcript, "commands": [cmd], "auth_events": events}

    # ---- verification -----------------------------------------------------------------------
    def verify_vlan(self, interface: str, vlan: int) -> tuple[bool, str]:
        name = short_ifname(interface)
        out = self.show(f"show interfaces {name} switchport")
        ok = f"Access Mode VLAN: {vlan} " in out
        mac_out = self.show(f"show mac address-table interface {name}")
        ok = ok and all(e.vlan == vlan for e in self.twin.macs_on_interface(name))
        return ok, out + "\n\n" + mac_out

    def verify_shutdown(self, interface: str) -> tuple[bool, str]:
        name = short_ifname(interface)
        out = self.show(f"show interfaces {name} status")
        i = self.twin.interfaces[name]
        ok = i.admin_status == "down" and i.oper_status == "disabled" and not self.twin.macs_on_interface(name)
        return ok, out

    def _transcript(self, commands: list[str], at: datetime) -> str:
        host = self.twin.hostname
        lines = [f"{host}#configure terminal", "Enter configuration commands, one per line.  End with CNTL/Z."]
        prompt = f"{host}(config)#"
        for c in commands[1:]:
            c = c.strip()
            if c == "end":
                lines.append(f"{prompt}end")
                prompt = f"{host}#"
            elif c.startswith("interface "):
                lines.append(f"{prompt}{c}")
                prompt = f"{host}(config-if)#"
            elif c == "write memory":
                lines.append(f"{host}#write memory")
                lines.append("Building configuration...")
                lines.append("[OK]")
            else:
                lines.append(f"{prompt}{c}")
        return "\n".join(lines)
