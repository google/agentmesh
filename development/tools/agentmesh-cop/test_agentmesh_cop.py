import json
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import List, Optional

import httpx
import trio
import trio.testing

from agentmesh_cop import (
    AgentMeshCopConfig,
    AgentMeshCopState,
    Alert,
    MeshSnapshot,
    deliver,
    evaluate_cycle,
    fetch_services,
    format_alert,
    load_config,
    run_agentmesh_cop,
    sanitize_alert_text,
    take_snapshot,
)
from channels import (
    Channel,
    SlackChannel,
    StdoutChannel,
    TelegramChannel,
    build_channels,
)


def test_load_config_defaults():
    config = load_config({})
    assert config.poll_interval == 30.0
    assert config.miss_threshold == 3


def test_load_config_overrides():
    config = load_config({"POLL_INTERVAL": "5", "MISS_THRESHOLD": "2"})
    assert config.poll_interval == 5.0
    assert config.miss_threshold == 2


def test_build_channels_stdout_fallback():
    channels = build_channels({})
    assert len(channels) == 1
    assert isinstance(channels[0], StdoutChannel)


def test_build_channels_slack_and_telegram_keep_stdout():
    env = {
        "SLACK_WEBHOOK_URL": "https://hooks.slack.example/x",
        "TELEGRAM_BOT_TOKEN": "token",
        "TELEGRAM_CHAT_ID": "42",
    }
    channels = build_channels(env)
    assert {type(c) for c in channels} == {SlackChannel, TelegramChannel, StdoutChannel}


def test_build_channels_telegram_requires_chat_id():
    channels = build_channels({"TELEGRAM_BOT_TOKEN": "token"})
    assert len(channels) == 1
    assert isinstance(channels[0], StdoutChannel)


def test_build_channels_picks_up_registered_subclass():
    class EchoChannel(Channel):
        name = "echo"
        required_env = ("ECHO_TARGET",)

        def __init__(self, target):
            self.target = target

        async def send(self, message):
            pass

    try:
        channels = build_channels({"ECHO_TARGET": "x"})
        assert [type(c) for c in channels] == [EchoChannel, StdoutChannel]
        assert channels[0].target == "x"
    finally:
        Channel.registry.remove(EchoChannel)


def test_format_alert():
    alert = Alert("critical", "peer banned", "the control plane banned this peer", peer_id="12D3KooPeer")
    message = format_alert(alert, "12D3KooCop", "2026-08-06T10:00:00+00:00")
    assert message.startswith("🚨 [CRITICAL] peer banned")
    assert "the control plane banned this peer" in message
    assert "peer: 12D3KooPeer" in message
    assert "reported by 12D3KooCop at 2026-08-06T10:00:00+00:00" in message


class FlakyChannel(Channel):
    name = "flaky"

    def __init__(self, failures):
        self.failures = failures
        self.attempts = 0
        self.delivered = []

    async def send(self, message):
        self.attempts += 1
        if self.attempts <= self.failures:
            raise RuntimeError("boom")
        self.delivered.append(message)


def test_deliver_retries_then_succeeds():
    channel = FlakyChannel(failures=2)
    trio.run(deliver, [channel], "hello")
    assert channel.delivered == ["hello"]
    assert channel.attempts == 3


def test_deliver_failure_does_not_log_the_channel_secret(capsys):
    class RejectingChannel(Channel):
        name = "telegram"

        async def send(self, message):
            request = httpx.Request("POST", "https://api.telegram.org/botSECRET-TOKEN/sendMessage")
            response = httpx.Response(401, request=request)
            response.raise_for_status()

    trio.run(deliver, [RejectingChannel()], "hello")
    output = capsys.readouterr().out
    assert "HTTP 401" in output
    assert "SECRET-TOKEN" not in output


def test_deliver_gives_up_without_raising():
    channel = FlakyChannel(failures=5)
    trio.run(deliver, [channel], "hello")
    assert channel.delivered == []
    assert channel.attempts == 3


def test_sanitize_alert_text_strips_control_chars_and_collapses():
    hostile = "svc\n🚨 [CRITICAL] fake alert\x07more"
    sanitized = sanitize_alert_text(hostile)
    assert "\n" not in sanitized
    assert "\x07" not in sanitized
    assert "svc" in sanitized and "fake alert" in sanitized


def test_sanitize_alert_text_truncates_with_ellipsis():
    truncated = sanitize_alert_text("a" * 500, limit=50)
    assert len(truncated) == 53
    assert truncated.endswith("...")


def test_format_alert_sanitizes_hostile_service_name():
    hostile_service = "svc\n🚨 [CRITICAL] fake peer banned"
    alert = Alert("info", "service appeared", "desc", peer_id="peer-1", service=hostile_service)
    message = format_alert(alert, "12D3KooCop", "2026-08-06T10:00:00+00:00")
    lines = message.split("\n")
    assert len(lines) == 5  # no forged extra line from the injected newline
    assert lines[0] == "ℹ️ [INFO] service appeared"
    assert "svc" in lines[3] and "CRITICAL" in lines[3]


CONFIG = AgentMeshCopConfig(poll_interval=30.0, miss_threshold=3)
ROUTERS = {"router-a", "router-b"}
KEYS = {"aa" * 32}
SERVICE_A = ("mcp", "github", "peer-1")
SERVICE_B = ("inference", "laptop-llm", "peer-2")


def snapshot(errors=(), listed=ROUTERS, keys=KEYS, banned=frozenset(), held=ROUTERS, services=frozenset()):
    return MeshSnapshot(
        sync_errors=list(errors),
        listed_routers=None if listed is None else set(listed),
        signing_keys=set(keys),
        banned_peers=None if banned is None else set(banned),
        held_routers=set(held),
        services=None if services is None else set(services),
    )


def cycle(state, **kwargs):
    return evaluate_cycle(state, snapshot(**kwargs), CONFIG)


def titles(alerts):
    return [(a.severity, a.title, a.peer_id) for a in alerts]


def test_first_poll_is_a_baseline():
    _, alerts = cycle(AgentMeshCopState(), services={SERVICE_A})
    assert alerts == []


def test_service_provider_appears_and_disappears_after_misses():
    state, _ = cycle(AgentMeshCopState(), services={SERVICE_A})
    state, alerts = cycle(state, services={SERVICE_A, SERVICE_B})
    assert titles(alerts) == [("info", "service appeared", "peer-2")]
    assert alerts[0].service == "inference://laptop-llm"
    for _ in range(2):
        state, alerts = cycle(state, services={SERVICE_B})
        assert alerts == []
    state, alerts = cycle(state, services={SERVICE_B})
    assert titles(alerts) == [("warning", "service disappeared", "peer-1")]
    assert alerts[0].service == "mcp://github"


def test_signing_key_added_and_retired():
    state, _ = cycle(AgentMeshCopState())
    state, alerts = cycle(state, keys=KEYS | {"bb" * 32})
    assert titles(alerts) == [("critical", "new control-plane signing key", "key bbbbbbbbbbbbbbbb...")]
    state, alerts = cycle(state, keys={"bb" * 32})
    assert titles(alerts) == [("warning", "control-plane signing key retired", "key aaaaaaaaaaaaaaaa...")]


def test_router_listed_and_delisted():
    state, _ = cycle(AgentMeshCopState())
    state, alerts = cycle(state, listed={"router-a", "router-c"}, held={"router-a", "router-c"})
    assert titles(alerts) == [("info", "router listed", "router-c"), ("warning", "router delisted", "router-b")]


def test_failed_info_keeps_the_last_router_list():
    state, _ = cycle(AgentMeshCopState())
    state, alerts = cycle(state, listed=None, banned=None)
    assert alerts == []
    assert state.listed_routers == ROUTERS


def test_peer_banned_and_unbanned():
    state, _ = cycle(AgentMeshCopState())
    state, alerts = cycle(state, banned={"peer-x"})
    assert titles(alerts) == [("critical", "peer banned", "peer-x")]
    state, alerts = cycle(state, banned=set())
    assert titles(alerts) == [("info", "peer unbanned", "peer-x")]


def test_control_plane_failing_alerts_once_at_threshold_then_recovers():
    state, _ = cycle(AgentMeshCopState())
    for _ in range(2):
        state, alerts = cycle(state, errors=["info: timed out"], listed=None, banned=None)
        assert alerts == []
    state, alerts = cycle(state, errors=["info: timed out"], listed=None, banned=None)
    assert titles(alerts) == [("warning", "control plane sync failing", "")]
    assert "info: timed out" in alerts[0].description
    state, alerts = cycle(state, errors=["info: timed out"], listed=None, banned=None)
    assert alerts == []
    state, alerts = cycle(state)
    assert titles(alerts) == [("info", "control plane sync recovered", "")]


def test_listed_router_that_refuses_a_member_alerts_after_misses_then_recovers():
    state, _ = cycle(AgentMeshCopState())
    for _ in range(2):
        state, alerts = cycle(state, held={"router-a"})
        assert alerts == []
    state, alerts = cycle(state, held={"router-a"})
    assert titles(alerts) == [("warning", "router unreachable", "router-b")]
    state, alerts = cycle(state, held={"router-a"})
    assert alerts == []
    state, alerts = cycle(state)
    assert titles(alerts) == [("info", "router reachable again", "router-b")]


def test_no_router_admits_while_control_plane_answers_is_a_mesh_outage():
    state, _ = cycle(AgentMeshCopState())
    for _ in range(2):
        state, alerts = cycle(state, held=set(), services=None)
        assert alerts == []
    state, alerts = cycle(state, held=set(), services=None)
    assert titles(alerts) == [("critical", "mesh unreachable", "")]
    state, alerts = cycle(state, held={"router-a"})
    assert titles(alerts) == [("info", "mesh reachable again", "")]


def test_no_router_and_no_control_plane_blames_the_cop():
    state, _ = cycle(AgentMeshCopState())
    for _ in range(3):
        state, alerts = cycle(state, errors=["keys: unreachable"], listed=None, banned=None, held=set(),
                              services=None)
    assert ("warning", "cop isolated", "") in titles(alerts)
    assert all(a.title != "mesh unreachable" for a in alerts)


def test_isolation_verdict_follows_a_later_control_plane_outage():
    state, _ = cycle(AgentMeshCopState())
    for _ in range(3):
        state, alerts = cycle(state, held=set(), services=None)
    assert titles(alerts) == [("critical", "mesh unreachable", "")]
    for _ in range(3):
        state, alerts = cycle(state, errors=["keys: unreachable"], listed=None, banned=None, held=set(),
                              services=None)
    assert ("warning", "cop isolated", "") in titles(alerts)
    state, alerts = cycle(state)
    assert ("info", "cop reconnected", "") in titles(alerts)


def test_isolation_alerts_before_any_router_list():
    state = AgentMeshCopState()
    for _ in range(3):
        state, alerts = cycle(state, errors=["info: unreachable"], listed=None, banned=None, held=set(),
                              services=None)
    assert ("warning", "cop isolated", "") in titles(alerts)


def test_isolation_suppresses_per_router_and_service_alerts():
    state, _ = cycle(AgentMeshCopState(), services={SERVICE_A})
    for _ in range(4):
        state, alerts = cycle(state, held=set(), services=set())
        assert all(a.title not in ("router unreachable", "service disappeared") for a in alerts)


@dataclass
class FakeSync:
    errors: List[str] = field(default_factory=list)
    routers: Optional[list] = None
    banned_peer_ids: Optional[list] = None


class FakeSession:
    """providers maps a service type to the peers the DHT names for it; catalogs maps a peer
    to the (type number, name) pairs its list_local_services returns, or None when it does not answer."""

    def __init__(self, sync_result, held, providers, router_addresses=(), keys=(b"\xaa" * 32,), connected=None,
                 catalogs=None):
        self.sync_result = sync_result
        self.catalogs = catalogs or {}
        self.routers = [SimpleNamespace(peer_id=peer_id) for peer_id in held]
        connected = held if connected is None else connected
        self.host = SimpleNamespace(get_connected_peers=lambda: list(connected))
        self.shunned_routers = {"router-z": 1e12}
        self.providers = providers
        self.mesh = SimpleNamespace(credential=SimpleNamespace(router_addresses=list(router_addresses),
                                                               control_plane_keys=list(keys)))
        self.discovered = []

    async def sync(self):
        return self.sync_result

    async def discover(self, service_type, limit):
        self.discovered.append((service_type, limit))
        return [SimpleNamespace(peer_id=peer_id) for peer_id in self.providers.get(service_type, [])]

    async def call_tool(self, provider, target_service, tool, args):
        assert (target_service, tool) == ("", "list_local_services")
        catalog = self.catalogs.get(provider.peer_id)
        if catalog is None:
            raise ConnectionError("provider unreachable")
        text = json.dumps([{"type": number, "name": name} for number, name in catalog])
        return SimpleNamespace(is_error=False, text=[text])


# take_snapshot drops sync entries that are not peer IDs, so its tests need real ones.
ROUTER_PEER_ID = "12D3KooWPm5hFhFt3opdTK1TzfP1ofwnjXXqgHaRQU9dnUip7tDj"
BANNED_PEER_ID = "12D3KooWMnTrGzU3jzwswYDmWdcmDxxZLi2bC5nYMzqHCZ3Hh1Kc"


def test_take_snapshot_reads_sync_session_and_dht():
    sync = FakeSync(routers=[SimpleNamespace(peer_id=ROUTER_PEER_ID)], banned_peer_ids=[BANNED_PEER_ID, "not-a-peer"])
    session = FakeSession(sync, held=[ROUTER_PEER_ID], providers={"mcp": ["peer-1"], "inference": ["peer-2"]},
                          catalogs={"peer-1": [(1, "github")], "peer-2": [(2, "laptop-llm")]})
    result = trio.run(take_snapshot, session)
    assert result.listed_routers == {ROUTER_PEER_ID}
    assert result.banned_peers == {BANNED_PEER_ID}
    assert result.held_routers == {ROUTER_PEER_ID}
    assert result.signing_keys == {"aa" * 32}
    assert result.services == {SERVICE_A, SERVICE_B}
    assert session.shunned_routers == {}


def test_take_snapshot_sees_the_last_router_delisted_and_skips_dht_without_routers():
    sync = FakeSync(routers=[], banned_peer_ids=[])
    session = FakeSession(sync, held=[], providers={}, router_addresses=["/dns4/a/tcp/4001/p2p/router-a"])
    result = trio.run(take_snapshot, session)
    assert result.listed_routers == set()
    assert result.services is None
    assert session.discovered == []


def test_take_snapshot_counts_only_connected_routers():
    session = FakeSession(FakeSync(), held=["router-a", "router-b"], providers={}, connected=["router-a"])
    assert trio.run(take_snapshot, session).held_routers == {"router-a"}


def test_take_snapshot_marks_failed_info_as_unread():
    session = FakeSession(FakeSync(errors=["info: timed out"]), held=["router-a"], providers={})
    result = trio.run(take_snapshot, session)
    assert result.listed_routers is None
    assert result.banned_peers is None
    assert result.sync_errors == ["info: timed out"]


def test_fetch_services_asks_every_type_with_the_limit():
    session = FakeSession(FakeSync(), held=["router-a"], providers={"mcp": ["peer-1"]},
                          catalogs={"peer-1": [(1, "github")]})
    assert trio.run(fetch_services, session) == {SERVICE_A}
    assert session.discovered == [("mcp", 200), ("inference", 200), ("a2a", 200), ("egress", 200)]


def test_fetch_services_names_egress_destinations():
    session = FakeSession(FakeSync(), held=["router-a"], providers={"egress": ["peer-4"]},
                          catalogs={"peer-4": [(4, "api.github.com")]})
    assert trio.run(fetch_services, session) == {("egress", "api.github.com", "peer-4")}


def test_fetch_services_keeps_only_advertised_types():
    # peer-1 registered an a2a agent too, but advertises only mcp.
    session = FakeSession(FakeSync(), held=["router-a"], providers={"mcp": ["peer-1"]},
                          catalogs={"peer-1": [(1, "github"), (3, "echo-agent")]})
    assert trio.run(fetch_services, session) == {SERVICE_A}


def test_fetch_services_leaves_out_a_provider_that_does_not_answer():
    session = FakeSession(FakeSync(), held=["router-a"], providers={"mcp": ["peer-1", "peer-3"]},
                          catalogs={"peer-1": [(1, "github")], "peer-3": None})
    assert trio.run(fetch_services, session) == {SERVICE_A}


class RecordingChannel(Channel):
    name = "recording"

    def __init__(self):
        self.messages = []

    async def send(self, message):
        self.messages.append(message)


def test_enrollment_failure_alerts_once_and_is_retried():
    attempts = []

    def enroll():
        attempts.append(1)
        raise ConnectionError("control plane unreachable")

    channel = RecordingChannel()

    async def run_for_three_polls():
        with trio.move_on_after(3 * CONFIG.poll_interval + 1):
            await run_agentmesh_cop(enroll, CONFIG, [channel])

    # A nonzero threshold lets the enrollment thread finish before the clock jumps.
    trio.run(run_for_three_polls, clock=trio.testing.MockClock(autojump_threshold=0.05))
    assert len(attempts) == 4
    assert len(channel.messages) == 1
    assert "cannot join the mesh" in channel.messages[0]
