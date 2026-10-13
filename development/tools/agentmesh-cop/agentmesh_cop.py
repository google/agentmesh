"""agentmesh-cop: a mesh member that watches the mesh and alerts on trouble.

It joins with the native Python SDK and, every poll, pulls the control plane
(signing keys, routers, bans), checks which listed routers admit it, and looks
the services up in the DHT. It holds a session with every router that admits
it and reserves no relay slot, since nothing needs to reach it.

Env: AGENTMESH_CONTROL_PLANE_URL; AGENTMESH_BOOTSTRAP_TOKEN_PATH or
AGENTMESH_JWT_PATH (first run only, see the SDK); AGENTMESH_STATE_DIR;
AGENTMESH_INSECURE_CONTROL_PLANE; POLL_INTERVAL, MISS_THRESHOLD; and the
channel settings in channels.py.
"""

import json
import logging
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import trio
from agent_mesh.session import canonical_peer_ids

from channels import Channel, build_channels

logger = logging.getLogger("agentmesh-cop")


@dataclass
class AgentMeshCopConfig:
    poll_interval: float
    miss_threshold: int


def load_config(env) -> AgentMeshCopConfig:
    return AgentMeshCopConfig(
        poll_interval=float(env.get("POLL_INTERVAL", "30")),
        miss_threshold=int(env.get("MISS_THRESHOLD", "3")),
    )


@dataclass
class Alert:
    severity: str
    title: str
    description: str
    peer_id: str = ""
    service: str = ""


SEVERITY_EMOJI = {"critical": "🚨", "warning": "⚠️", "info": "ℹ️"}

CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]+")


def sanitize_alert_text(text: str, limit: int = 200) -> str:
    """Strips control chars (incl. newlines) so attacker-controlled strings can't forge alert lines."""
    cleaned = CONTROL_CHARS_RE.sub(" ", text).strip()
    if len(cleaned) > limit:
        cleaned = cleaned[:limit].rstrip() + "..."
    return cleaned


def format_alert(alert: Alert, cop_peer_id: str, timestamp: str) -> str:
    title = sanitize_alert_text(alert.title)
    lines = [f"{SEVERITY_EMOJI[alert.severity]} [{alert.severity.upper()}] {title}"]
    if alert.description:
        lines.append(sanitize_alert_text(alert.description))
    if alert.peer_id:
        lines.append(f"peer: {sanitize_alert_text(alert.peer_id)}")
    if alert.service:
        lines.append(f"service: {sanitize_alert_text(alert.service)}")
    lines.append(f"reported by {cop_peer_id} at {timestamp}")
    return "\n".join(lines)


def delivery_error(error: Exception) -> str:
    # Channel URLs carry secrets (the Telegram bot token, the Slack webhook) and httpx errors quote the URL.
    response = getattr(error, "response", None)
    return f"HTTP {response.status_code}" if response is not None else type(error).__name__


async def deliver(channels: List[Channel], message: str) -> None:
    async def deliver_to_channel(channel: Channel) -> None:
        for attempt in range(3):
            try:
                await channel.send(message)
                return
            except Exception as error:
                if attempt == 2:
                    print(f"[-] {channel.name} delivery failed after 3 attempts: {delivery_error(error)}", flush=True)
                else:
                    await trio.sleep(2**attempt)

    # Concurrent so one slow or failing channel's retries don't delay the others.
    async with trio.open_nursery() as nursery:
        for channel in channels:
            nursery.start_soon(deliver_to_channel, channel)


@dataclass
class MeshSnapshot:
    """One poll's view of the mesh. None means that part could not be read this poll."""

    sync_errors: List[str]
    listed_routers: Optional[set]
    signing_keys: set
    banned_peers: Optional[set]
    held_routers: set
    services: Optional[set]


@dataclass
class AgentMeshCopState:
    control_plane_misses: int = 0
    listed_routers: Optional[set] = None
    signing_keys: Optional[set] = None
    banned_peers: Optional[set] = None
    unreachable_polls: dict = field(default_factory=dict)
    unreachable_routers: set = field(default_factory=set)
    isolated_polls: int = 0
    isolation: Optional[str] = None  # title of the isolation alert in force
    baseline: set = field(default_factory=set)
    miss_counts: dict = field(default_factory=dict)
    first_snapshot: bool = True


def diff_alerts(previous: Optional[set], current: set, appeared: Alert, disappeared: Alert,
                describe=lambda item: item) -> List[Alert]:
    """One alert per item added to or dropped from a set; the first sighting is the baseline."""
    if previous is None:
        return []
    alerts = []
    for item in sorted(current - previous):
        alerts.append(Alert(appeared.severity, appeared.title, appeared.description, peer_id=describe(item)))
    for item in sorted(previous - current):
        alerts.append(Alert(disappeared.severity, disappeared.title, disappeared.description, peer_id=describe(item)))
    return alerts


def detect_control_plane(state: AgentMeshCopState, snapshot: MeshSnapshot, miss_threshold: int) -> List[Alert]:
    alerts = []
    if snapshot.sync_errors:
        state.control_plane_misses += 1
        if state.control_plane_misses == miss_threshold:
            alerts.append(Alert("warning", "control plane sync failing",
                                f"{miss_threshold} consecutive pulls failed: {'; '.join(snapshot.sync_errors)}"))
    else:
        if state.control_plane_misses >= miss_threshold:
            alerts.append(Alert("info", "control plane sync recovered",
                                f"pull succeeded after {state.control_plane_misses} failures"))
        state.control_plane_misses = 0

    alerts.extend(diff_alerts(state.signing_keys, snapshot.signing_keys,
                              Alert("critical", "new control-plane signing key", "a key the cop did not trust before"),
                              Alert("warning", "control-plane signing key retired", "a trusted key left /keys"),
                              describe=lambda key: f"key {key[:16]}..."))
    state.signing_keys = snapshot.signing_keys

    if snapshot.listed_routers is not None:
        alerts.extend(diff_alerts(state.listed_routers, snapshot.listed_routers,
                                  Alert("info", "router listed", "the control plane leased a new router"),
                                  Alert("warning", "router delisted", "the router's lease expired or was dropped")))
        state.listed_routers = snapshot.listed_routers

    if snapshot.banned_peers is not None:
        alerts.extend(diff_alerts(state.banned_peers, snapshot.banned_peers,
                                  Alert("critical", "peer banned", "the control plane banned this peer"),
                                  Alert("info", "peer unbanned", "the control plane lifted the ban")))
        state.banned_peers = snapshot.banned_peers
    return alerts


ISOLATION_RECOVERY = {"cop isolated": "cop reconnected", "mesh unreachable": "mesh reachable again"}


def detect_router_reachability(state: AgentMeshCopState, snapshot: MeshSnapshot, miss_threshold: int) -> List[Alert]:
    """Routers the control plane lists against the routers that admit the cop: a listed
    router that refuses a member refuses every new agent too."""
    # Before the first router list any held router counts, so a cop cut off from the start still alerts.
    held = snapshot.held_routers if state.listed_routers is None else snapshot.held_routers & state.listed_routers
    listed = state.listed_routers or set()
    alerts = []
    if not held:
        state.isolated_polls += 1
        if state.isolated_polls >= miss_threshold:
            if state.control_plane_misses >= miss_threshold:
                # Nothing answers the cop at all: its own network is the likelier fault.
                verdict = Alert("warning", "cop isolated",
                                "neither the control plane nor any listed router answers this member")
            else:
                verdict = Alert("critical", "mesh unreachable",
                                f"the control plane lists {len(listed)} router(s) and none admits a member")
            if verdict.title != state.isolation:
                alerts.append(verdict)
                state.isolation = verdict.title
        return alerts
    if state.isolation is not None:
        alerts.append(Alert("info", ISOLATION_RECOVERY[state.isolation],
                            f"{len(held)} router(s) admit a member"))
    state.isolation = None
    state.isolated_polls = 0

    for router in sorted(listed - held):
        polls = state.unreachable_polls.get(router, 0) + 1
        state.unreachable_polls[router] = polls
        if polls == miss_threshold:
            state.unreachable_routers.add(router)
            alerts.append(Alert("warning", "router unreachable",
                                f"listed by the control plane but refused or dropped a member for {polls} polls",
                                peer_id=router))
    for router in sorted(state.unreachable_routers & held):
        alerts.append(Alert("info", "router reachable again", "the router admits a member again", peer_id=router))
    state.unreachable_routers &= listed - held
    state.unreachable_polls = {router: polls for router, polls in state.unreachable_polls.items()
                               if router in listed - held}
    return alerts


def detect_churn(state: AgentMeshCopState, services_snapshot: Optional[set], miss_threshold: int) -> List[Alert]:
    if services_snapshot is None or state.isolation is not None:
        return []
    if state.first_snapshot:
        state.baseline = set(services_snapshot)
        state.miss_counts = {}
        state.first_snapshot = False
        return []

    alerts = []
    for entry in sorted(services_snapshot - state.baseline):
        service_type, service_name, peer_id = entry
        alerts.append(Alert("info", "service appeared", f"{service_type}://{service_name} advertised on the mesh",
                            peer_id=peer_id, service=f"{service_type}://{service_name}"))
        state.baseline.add(entry)
    for entry in list(state.miss_counts):
        if entry in services_snapshot:
            del state.miss_counts[entry]
    for entry in sorted(state.baseline - services_snapshot):
        misses = state.miss_counts.get(entry, 0) + 1
        if misses >= miss_threshold:
            service_type, service_name, peer_id = entry
            alerts.append(Alert("warning", "service disappeared",
                                f"{service_type}://{service_name} missing for {misses} consecutive polls",
                                peer_id=peer_id, service=f"{service_type}://{service_name}"))
            state.baseline.discard(entry)
            state.miss_counts.pop(entry, None)
        else:
            state.miss_counts[entry] = misses
    return alerts


def evaluate_cycle(state: AgentMeshCopState, snapshot: MeshSnapshot, config: AgentMeshCopConfig):
    alerts = []
    alerts.extend(detect_control_plane(state, snapshot, config.miss_threshold))
    alerts.extend(detect_router_reachability(state, snapshot, config.miss_threshold))
    alerts.extend(detect_churn(state, snapshot.services, config.miss_threshold))
    return state, alerts


SERVICE_TYPES = ["mcp", "inference", "a2a", "egress"]
DISCOVERY_LIMIT = 200
# ServiceType numbers in api/agentmesh.proto, as list_local_services renders them.
SERVICE_TYPE_NAMES = {1: "mcp", 2: "inference", 3: "a2a", 4: "egress"}
PROVIDER_QUERY_TIMEOUT = 10.0


async def provider_services(session, provider) -> List[Tuple[str, str]]:
    """The (type, name) pairs a provider registered, from its catalog's list_local_services."""
    result = await session.call_tool(provider, "", "list_local_services", {})
    if result.is_error or not result.text:
        raise RuntimeError(f"list_local_services failed: {result.text}")
    return [(SERVICE_TYPE_NAMES.get(service.get("type")), service.get("name", ""))
            for service in json.loads(result.text[0])]


async def fetch_services(session) -> set:
    # The DHT names the providers of a type, not their services; each provider names its own.
    providers: Dict[str, object] = {}
    advertised_types: Dict[str, set] = {}
    for service_type in SERVICE_TYPES:
        for provider in await session.discover(service_type, limit=DISCOVERY_LIMIT):
            providers[provider.peer_id] = provider
            advertised_types.setdefault(provider.peer_id, set()).add(service_type)
    snapshot = set()
    for peer_id, provider in providers.items():
        try:
            with trio.fail_after(PROVIDER_QUERY_TIMEOUT):
                services = await provider_services(session, provider)
        except Exception as error:
            # Left out of this poll: its services count as missed, so only a lasting silence alerts.
            # Debug only, since a dead provider's DHT record keeps it here for hours.
            logger.debug("provider %s did not list its services: %s", peer_id, error)
            continue
        # A node lists every service it registered, advertised in the DHT or not.
        snapshot.update((service_type, name, peer_id) for service_type, name in services
                        if service_type in advertised_types[peer_id])
    return snapshot


async def take_snapshot(session) -> MeshSnapshot:
    # The SDK keeps away from a failed router for minutes; the cop probes every listed router each poll.
    session.shunned_routers.clear()
    result = await session.sync()
    # Raw wire strings; the session keys its routers on the canonical form, so compare on that.
    listed_routers = (set(canonical_peer_ids([router.peer_id for router in result.routers]))
                      if result.routers is not None else None)
    banned_peers = set(canonical_peer_ids(result.banned_peer_ids)) if result.banned_peer_ids is not None else None
    # session.routers keeps a dead router until its redials run out; count only live connections.
    connected = {str(peer) for peer in session.host.get_connected_peers()}
    held_routers = {router.peer_id for router in session.routers if router.peer_id in connected}
    services = None
    if held_routers:
        try:
            services = await fetch_services(session)
        except Exception as error:
            print(f"[-] service discovery failed: {error}", flush=True)
    return MeshSnapshot(
        sync_errors=list(result.errors),
        listed_routers=listed_routers,
        signing_keys={bytes(key).hex() for key in session.mesh.credential.control_plane_keys},
        banned_peers=banned_peers,
        held_routers=held_routers,
        services=services,
    )


async def alert_all(channels: List[Channel], alerts: List[Alert], cop_peer_id: str) -> None:
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for alert in alerts:
        await deliver(channels, format_alert(alert, cop_peer_id, timestamp))


# More routers than any mesh lists: the session then holds every router that admits it,
# and its own loop redials the ones that drop and retries the ones it shunned.
HOLD_EVERY_ROUTER = 10_000


async def watch(session, channels: List[Channel], config: AgentMeshCopConfig) -> None:
    state = AgentMeshCopState()
    while True:
        try:
            state, alerts = evaluate_cycle(state, await take_snapshot(session), config)
            await alert_all(channels, alerts, session.peer_id)
        except Exception as error:
            print(f"[-] poll cycle failed: {error}", flush=True)
        await trio.sleep(config.poll_interval)


async def run_agentmesh_cop(enroll, config: AgentMeshCopConfig, channels: List[Channel]) -> None:
    mesh = None
    join_failed = False
    while True:
        try:
            if mesh is None:
                # Blocks on HTTP and, without auto-approve, on an operator, so it runs off the trio thread.
                mesh = await trio.to_thread.run_sync(enroll)
            # The cop drives every pull itself; key rotation events still bring one forward.
            async with mesh.join(routers=HOLD_EVERY_ROUTER, reserve=False, control_plane_sync_interval=0) as session:
                print(f"[+] on the mesh as {session.peer_id}, holding {len(session.routers)} router(s)", flush=True)
                if join_failed:
                    await alert_all(channels, [Alert("info", "joined the mesh again", "")], session.peer_id)
                    join_failed = False
                await watch(session, channels, config)
        except Exception as error:
            print(f"[-] cannot join the mesh: {error}", flush=True)
            if not join_failed:
                reporter = mesh.peer_id if mesh is not None else "a cop that is not enrolled yet"
                await alert_all(channels, [Alert("critical", "cannot join the mesh", str(error))], reporter)
                join_failed = True
        await trio.sleep(config.poll_interval)


def main() -> None:
    from agent_mesh import AgentMesh

    # Logs every refused dial, some with a full traceback; the cop reports reachability itself.
    logging.getLogger("libp2p.transport").setLevel(logging.CRITICAL)
    config = load_config(os.environ)
    channels = build_channels(os.environ)
    channel_names = ", ".join(channel.name for channel in channels)
    print(f"[*] agentmesh-cop starting: poll={config.poll_interval}s miss_threshold={config.miss_threshold} "
          f"channels=[{channel_names}]", flush=True)
    control_plane_url = os.environ["AGENTMESH_CONTROL_PLANE_URL"]

    def enroll():
        return AgentMesh.enroll(
            control_plane_url,
            bootstrap_token_path=os.environ.get("AGENTMESH_BOOTSTRAP_TOKEN_PATH"),
            jwt_path=os.environ.get("AGENTMESH_JWT_PATH"),
            state_dir=os.environ.get("AGENTMESH_STATE_DIR", "~/.config/agentmesh/cop"),
            allow_insecure=os.environ.get("AGENTMESH_INSECURE_CONTROL_PLANE") == "true",
        )

    trio.run(run_agentmesh_cop, enroll, config, channels)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
