import subprocess
import json
import datetime
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ContainerFinding:
    check: str
    status: str
    severity: str
    detail: str
    recommendation: str


@dataclass
class ScanResult:
    container_id: str
    image: str
    findings: List[ContainerFinding] = field(default_factory=list)
    healthy: bool = True

    def add(self, finding: ContainerFinding):
        self.findings.append(finding)
        if finding.severity in ("HIGH", "CRITICAL"):
            self.healthy = False


def _run(cmd: List[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout.strip()
    except Exception:
        return ""


def _run_json(cmd: List[str]) -> list:
    out = _run(cmd)
    if not out:
        return []
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return []


def _parse_ports(ports_str: str) -> List[str]:
    exposed = []
    for line in ports_str.splitlines():
        parts = line.split()
        if len(parts) >= 5:
            exposed.append(parts[6] if len(parts) > 6 else parts[4])
    return exposed


def scan_container(container_id: str) -> ScanResult:
    inspect = _run_json(["docker", "inspect", container_id])
    if not inspect:
        return ScanResult(container_id=container_id, image="unknown", healthy=False)

    info = inspect[0]
    state = info.get("State", {})
    config = info.get("Config", {})
    host_config = info.get("HostConfig", {})
    image_name = config.get("Image", "unknown")
    result = ScanResult(container_id=container_id[:12], image=image_name)

    if state.get("Status") != "running":
        result.add(ContainerFinding(
            check="container_status", status="STOPPED",
            severity="LOW", detail=f"Container status: {state.get('Status', 'unknown')}",
            recommendation="Start the container if it should be running."))
        return result

    result.add(ContainerFinding(
        check="container_status", status="RUNNING", severity="INFO",
        detail="Container is running", recommendation=""))

    user = config.get("User", "")
    if not user or user == "" or user == "0":
        result.add(ContainerFinding(
            check="running_as_root", status="ROOT", severity="HIGH",
            detail=f"Container runs as root (user: {user or 'default root'})",
            recommendation="Use USER directive in Dockerfile to run as non-root user."))
    else:
        result.add(ContainerFinding(
            check="running_as_root", status="NON-ROOT", severity="PASS",
            detail=f"Container runs as user '{user}'", recommendation=""))

    privileged = host_config.get("Privileged", False)
    if privileged:
        result.add(ContainerFinding(
            check="privileged_mode", status="PRIVILEGED", severity="CRITICAL",
            detail="Container runs in privileged mode - full host access granted",
            recommendation="Remove --privileged flag. Use specific capabilities instead."))
    else:
        result.add(ContainerFinding(
            check="privileged_mode", status="NOT PRIVILEGED", severity="PASS",
            detail="Container runs without privileged mode", recommendation=""))

    net_mode = host_config.get("NetworkMode", "default")
    if net_mode == "host":
        result.add(ContainerFinding(
            check="host_network", status="HOST NET", severity="HIGH",
            detail="Container uses host network mode - no network isolation",
            recommendation="Use bridge network instead of --network=host."))
    else:
        result.add(ContainerFinding(
            check="host_network", status="ISOLATED", severity="PASS",
            detail=f"Network mode: {net_mode}", recommendation=""))

    cap_add = host_config.get("CapAdd", [])
    dangerous_caps = {"SYS_ADMIN", "NET_ADMIN", "SYS_MODULE", "SYS_PTRACE", "ALL"}
    added = set(cap_add)
    dangerous = added & dangerous_caps
    if dangerous:
        result.add(ContainerFinding(
            check="capabilities", status="DANGEROUS CAPS", severity="HIGH",
            detail=f"Dangerous capabilities added: {', '.join(sorted(dangerous))}",
            recommendation=f"Drop dangerous capabilities with --cap-drop={','.join(sorted(dangerous))}"))
    elif added:
        result.add(ContainerFinding(
            check="capabilities", status="EXTRA CAPS", severity="MEDIUM",
            detail=f"Extra capabilities added: {', '.join(sorted(added))}",
            recommendation="Review if all added capabilities are necessary."))
    else:
        result.add(ContainerFinding(
            check="capabilities", status="DEFAULT CAPS", severity="PASS",
            detail="No extra capabilities added", recommendation=""))

    binds = host_config.get("Binds") or []
    if binds:
        result.add(ContainerFinding(
            check="volume_mounts", status="VOLUMES", severity="MEDIUM",
            detail=f"Host paths mounted: {', '.join(binds)}",
            recommendation="Mount read-only when possible. Avoid mounting sensitive host paths like /var/run/docker.sock."))
    else:
        result.add(ContainerFinding(
            check="volume_mounts", status="NO VOLUMES", severity="LOW",
            detail="No host volumes mounted", recommendation=""))

    mem_limit = host_config.get("Memory", 0)
    if mem_limit == 0:
        result.add(ContainerFinding(
            check="memory_limit", status="UNLIMITED", severity="MEDIUM",
            detail="No memory limit set - container can exhaust host memory",
            recommendation="Set memory limits with --memory."))
    else:
        result.add(ContainerFinding(
            check="memory_limit", status="LIMITED", severity="PASS",
            detail=f"Memory limit: {mem_limit / (1024*1024):.0f}MB", recommendation=""))

    cpu_shares = host_config.get("CpuShares", 0)
    cpu_quota = host_config.get("CpuQuota", 0)
    if cpu_shares == 0 and cpu_quota == 0:
        result.add(ContainerFinding(
            check="cpu_limit", status="UNLIMITED", severity="LOW",
            detail="No CPU limit set",
            recommendation="Set CPU limits with --cpus or --cpu-quota."))
    else:
        result.add(ContainerFinding(
            check="cpu_limit", status="LIMITED", severity="PASS",
            detail=f"CPU shares: {cpu_shares}, quota: {cpu_quota}", recommendation=""))

    restart_policy = host_config.get("RestartPolicy", {}).get("Name", "")
    if restart_policy == "always":
        result.add(ContainerFinding(
            check="restart_policy", status="ALWAYS", severity="INFO",
            detail="Restart policy is 'always'",
            recommendation="Consider 'unless-stopped' instead of 'always' to avoid unwanted restarts."))
    else:
        result.add(ContainerFinding(
            check="restart_policy", status="OK", severity="PASS",
            detail=f"Restart policy: {restart_policy or 'none'}", recommendation=""))

    ports = host_config.get("PortBindings", {})
    if ports:
        exposed = [f"{k.split('/')[0]}->{v[0]['HostPort'] if v else '?'}" for k, v in ports.items()]
        result.add(ContainerFinding(
            check="exposed_ports", status="PORTS", severity="INFO",
            detail=f"Published ports: {', '.join(exposed)}",
            recommendation="Review if all ports need to be publicly exposed."))
    else:
        result.add(ContainerFinding(
            check="exposed_ports", status="NO PORTS", severity="PASS",
            detail="No ports published", recommendation=""))

    return result


def scan_all_containers() -> List[ScanResult]:
    ids = _run(["docker", "ps", "-aq"]).splitlines()
    if not ids or ids == [""]:
        return []
    return [scan_container(cid) for cid in ids]


def check_image_age(image_name: str) -> Optional[ContainerFinding]:
    out = _run_json(["docker", "images", image_name, "--format", "{{json .}}"])
    if not out:
        return None
    created_str = out[0].get("CreatedAt", "") if isinstance(out, list) else out.get("CreatedAt", "")
    if not created_str:
        return None
    try:
        created = datetime.datetime.strptime(created_str[:19], "%Y-%m-%dT%H:%M:%S")
        age_days = (datetime.datetime.now() - created).days
    except (ValueError, IndexError):
        return None
    if age_days > 90:
        return ContainerFinding(
            check="image_age", status="OLD", severity="MEDIUM",
            detail=f"Image {image_name} is {age_days} days old",
            recommendation="Rebuild images regularly to pick up security patches.")
    return ContainerFinding(
        check="image_age", status="FRESH", severity="PASS",
        detail=f"Image age: {age_days} days", recommendation="")
