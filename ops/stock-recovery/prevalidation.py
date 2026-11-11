#!/usr/bin/env python3
"""Prevalidate frozen identities before any stop or recovery write.

Standard-library-only, offline, no execution. This is wrapper-adaptation
item 1 ("prevalidate identities without secrets"): it compares an
observed identity bundle against the source packet's frozen candidate
and fails closed on mismatch, malformed or missing identities. It
never invents host-only values, never falls back to a tag or a mutable
default, and rejects secret-shaped keys.

The result is always qualification=HOLD, service_recovery=NOT_TESTED
and execution_authorized=false, mirroring packet.py. A match binds
identity only; unknown host-only values stay named gates, not invented.
"""

import argparse
import json
import re
import sys
from pathlib import Path


MAX_OBSERVED_BYTES = 262144
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")

# Mirrors packet.REQUIRED_BINDINGS; keep in sync (test asserts equality).
REQUIRED_BINDINGS = (
    "binary_source_attestation",
    "host_platform",
    "compose_config",
    "provider_artifacts",
    "authoritative_store",
    "quiescence_mechanism",
    "watchdog_armed",
    "terminal_persistence",
    "journal_fault_matrix",
    "functional_recovery",
    "security_review",
    "qa_review",
    "release_acceptance",
    "operator_execution_authorization",
)

REQUIRED_OBSERVED_KEYS = (
    "repository",
    "platform",
    "index_digest",
    "manifest_digest",
    "config_digest",
    "docker_image_id",
    "recovery_manifest_digest",
)

SECRET_SUBSTRINGS = ("secret", "token", "password", "credential", "auth", "apikey", "api_key", "private")

# Mirrors the supported channels in config.example.yaml; a provider
# account outside them cannot be a CLIProxyAPI artifact identity.
SUPPORTED_PROVIDER_CHANNELS = (
    "vertex",
    "aistudio",
    "antigravity",
    "claude",
    "codex",
    "kimi",
    "xai",
    "meta",
)

# Mirrors AuthSourceFile/Git/ObjectStore/Postgres in
# sdk/cliproxy/auth/classification.go; "config" is an auth source, not a
# credential-store backend, so it cannot name the authoritative store.
SUPPORTED_STORE_BACKENDS = (
    "file",
    "git",
    "objectstore",
    "postgres",
)

# Mirrors the cloak booleans in config.example.yaml
# (disable-codex-cloaking, disable-claude-cloak-mode,
# disable-cloaking-model-list); the qualification matrix requires the
# disabled-provider/cloak/quota policy to be unchanged.
POLICY_ROLES = (
    "disable_codex_cloaking",
    "disable_claude_cloak_mode",
    "disable_cloaking_model_list",
)

# Mirrors the per-provider quota-cooling booleans in config.example.yaml:
# routing codex model-level-cooling and claude model-level-cooling.
# The key spells the same under both providers, so the role names carry
# the provider prefix the config sections provide.
QUOTA_COOLING_ROLES = (
    "codex_model_level_cooling",
    "claude_model_level_cooling",
)

# Mirrors the global cooldown booleans under routing.cooldown in
# config.example.yaml (disable-cooling, save-cooldown-status). Per-auth
# and per-provider disable-cooling overrides are provider/credential-keyed
# open names like disabled_providers, so this bundle covers only the
# global section, whose boolean keys form a closed list. The section's
# transient-error-cooldown-seconds is a duration, not a boolean policy
# identity, and is not named here.
COOLDOWN_ROLES = (
    "disable_cooling",
    "save_cooldown_status",
)

# Mirrors the routing booleans in config.example.yaml under the top-level
# routing section (session-affinity, session-affinity-subagents,
# force-model-prefix). The section's strategy, session-affinity-ttl and
# session-affinity-rebind-on are strings, not boolean policy identities,
# and are not named here.
ROUTING_ROLES = (
    "session_affinity",
    "session_affinity_subagents",
    "force_model_prefix",
)

# Mirrors the management booleans in config.example.yaml under the
# top-level management section (allow-remote,
# disable-control-panel, disable-auto-update-panel). The section's
# secret-key is a secret string, not a boolean policy identity, and
# base-url / panel-github-repository are strings; none are named here.
MANAGEMENT_ROLES = (
    "allow_remote",
    "disable_control_panel",
    "disable_auto_update_panel",
)

# Mirrors the server booleans in config.example.yaml under the top-level
# server section (commercial-mode, tls.enable,
# response-compression.enabled, discovery.enabled and
# discovery.auth-required). The section's host, port, trusted-proxies,
# github-token, tls cert/key, compression min-bytes and discovery
# service-name/type/subtypes/interfaces are strings, lists, paths or
# ints, none named here; discovery.advertise-management is deprecated
# and ignored, so it is not a live policy identity either.
SERVER_ROLES = (
    "commercial_mode",
    "tls_enable",
    "response_compression_enabled",
    "discovery_enabled",
    "discovery_auth_required",
)

# Mirrors the client booleans in config.example.yaml under the top-level
# client section (codex enable-apply-patch, codex
# optimize-multi-agent-v2, codex web-search-result-cache.enabled and
# claude show-codex-commentary, confirmed in internal/config/sdk_config.go).
# The web-search-result-cache ttl and limit are a duration string and an
# int, not boolean policy identities, and are not named here.
CLIENT_ROLES = (
    "codex_enable_apply_patch",
    "codex_optimize_multi_agent_v2",
    "codex_web_search_result_cache_enabled",
    "claude_show_codex_commentary",
)

# Mirrors the observability booleans in config.example.yaml under the
# top-level observability section (logs.debug, logs.logging-to-file,
# logs.request-log, usage.usage-statistics-enabled and pprof.enable,
# confirmed in internal/config/config.go and sdk_config.go). The
# logs-max-total-size-mb and error-logs-max-files are ints, the
# redis-usage-queue-retention-seconds is an int, and pprof.addr is a
# host:port string; none are named here.
OBSERVABILITY_ROLES = (
    "logs_debug",
    "logs_logging_to_file",
    "logs_request_log",
    "usage_usage_statistics_enabled",
    "pprof_enable",
)

# Mirrors the upstream codex booleans in config.example.yaml under the
# top-level upstream.codex section (response-steering,
# upstream-request-compression, websocket-compression,
# stream-bootstrap-buffering and orphan-delegation-compatibility,
# confirmed in internal/config/config_types.go). The section's
# upstream-request-compression-min-bytes is an int and
# stream-bootstrap-timeout is a duration string; disable-codex-cloaking
# and model-level-cooling are already bound by the policy and
# quota_cooling bundles, so none are named here.
UPSTREAM_CODEX_ROLES = (
    "response_steering",
    "upstream_request_compression",
    "websocket_compression",
    "stream_bootstrap_buffering",
    "orphan_delegation_compatibility",
)

# Mirrors the upstream claude booleans in config.example.yaml under the
# top-level upstream.claude section (tool-search, confirmed in
# internal/config/config_types.go). The section's model-level-cooling,
# disable-claude-cloak-mode and disable-cloaking-model-list are already
# bound by the quota_cooling and policy bundles, and
# session-date-pin-days is an int; the header-defaults block is
# commented out. None are named here.
UPSTREAM_CLAUDE_ROLES = (
    "tool_search",
)

# Mirrors the plugins boolean in config.example.yaml under the
# top-level plugins section (enabled, confirmed in
# internal/config/config_types.go). The section's dir is a string,
# store-sources / store-auth are lists, auth-revision is an int and
# configs is an open per-plugin map; none are named here.
PLUGINS_ROLES = (
    "enabled",
)


class PrevalidationError(ValueError):
    """An observed identity cannot be prevalidated against the packet."""


def _require_digest(value, label):
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise PrevalidationError(label + " must be a sha256 digest")


# Roles of the host Compose/config identity; a Compose file and the config
# rendered from it are different artifacts and must not be conflated.
COMPOSE_CONFIG_ROLES = ("compose_digest", "config_digest")


def _checked_compose_config(bundle):
    """Check host Compose/config identities, where supplied, by role.

    Compose/config identities are host-only and have no frozen packet
    value, so they are bound by shape: a non-empty object naming exactly
    the Compose-file and rendered-config roles, each with a digest value.
    A partial or role-swapped bundle conflates identities and fails
    closed; absence leaves the named gate unresolved rather than
    defaulting.
    """
    if "compose_config" not in bundle:
        return
    supplied = bundle["compose_config"]
    if not isinstance(supplied, dict) or not supplied:
        raise PrevalidationError("observed compose/config must be a non-empty object")
    if tuple(sorted(supplied)) != tuple(sorted(COMPOSE_CONFIG_ROLES)):
        raise PrevalidationError("observed compose/config must name exactly the compose and config roles")
    for role, expected in supplied.items():
        _require_digest(expected, "observed compose/config digest for " + role)


def _checked_authoritative_store(bundle):
    """Check which storage backend is claimed authoritative, where supplied.

    The authoritative store is host-only and has no frozen packet value,
    so it is bound by shape: a non-empty object naming exactly one
    supported store backend with a digest value identifying its canonical
    scope. Naming two backends (e.g. a file-store mirror beside Postgres)
    conflates which store wins and fails closed; absence leaves the named
    gate unresolved rather than defaulting.
    """
    if "authoritative_store" not in bundle:
        return
    supplied = bundle["authoritative_store"]
    if not isinstance(supplied, dict) or not supplied:
        raise PrevalidationError("observed authoritative store must be a non-empty object")
    if len(supplied) != 1:
        raise PrevalidationError("observed authoritative store must name exactly one backend")
    for name, expected in supplied.items():
        if not isinstance(name, str) or not name:
            raise PrevalidationError("observed authoritative store key is malformed")
        if name not in SUPPORTED_STORE_BACKENDS:
            raise PrevalidationError("observed authoritative store is not a supported backend: " + name)
        _require_digest(expected, "observed authoritative store digest for " + name)


def _checked_policy(bundle):
    """Check the claimed cloak policy, where supplied, against the roles.

    The cloak policy is host-only and has no frozen packet value, so it
    is bound by shape: a non-empty object naming exactly the three cloak
    booleans mirrored from config.example.yaml, each with a boolean
    value. A partial or role-swapped bundle conflates which provider's
    cloaking is claimed and fails closed; absence leaves the named gate
    unresolved rather than defaulting. The values are bound, not judged:
    whether they satisfy the unchanged-cloak matrix row is a
    qualification decision, not an identity gate.
    """
    if "policy" not in bundle:
        return
    supplied = bundle["policy"]
    if not isinstance(supplied, dict) or not supplied:
        raise PrevalidationError("observed policy must be a non-empty object")
    if tuple(sorted(supplied)) != tuple(sorted(POLICY_ROLES)):
        raise PrevalidationError("observed policy must name exactly the cloak policy roles")
    for role, value in supplied.items():
        if not isinstance(value, bool):
            raise PrevalidationError("observed policy value must be a boolean for " + role)


def _checked_quota_cooling(bundle):
    """Check the claimed quota-cooling policy, where supplied, by role.

    The quota-cooling policy is host-only and has no frozen packet value,
    so it is bound by shape: a non-empty object naming exactly the two
    quota-cooling roles mirrored from config.example.yaml (codex
    model-level-cooling and claude model-level-cooling), each with a
    boolean value. A partial or role-swapped bundle conflates which
    provider's cooling is claimed and fails closed; absence leaves the
    named gate unresolved rather than defaulting. The values are bound,
    not judged: whether they satisfy the unchanged-quota matrix row is
    a qualification decision, not an identity gate.
    """
    if "quota_cooling" not in bundle:
        return
    supplied = bundle["quota_cooling"]
    if not isinstance(supplied, dict) or not supplied:
        raise PrevalidationError("observed quota cooling must be a non-empty object")
    if tuple(sorted(supplied)) != tuple(sorted(QUOTA_COOLING_ROLES)):
        raise PrevalidationError("observed quota cooling must name exactly the quota cooling roles")
    for role, value in supplied.items():
        if not isinstance(value, bool):
            raise PrevalidationError("observed quota cooling value must be a boolean for " + role)


def _checked_cooldown(bundle):
    """Check the claimed global cooldown policy, where supplied, by role.

    The global cooldown policy is host-only and has no frozen packet
    value, so it is bound by shape: a non-empty object naming exactly the
    two cooldown booleans mirrored from routing.cooldown in
    config.example.yaml (disable-cooling, which controls cooldown
    scheduling globally, and save-cooldown-status, which persists
    per-auth cooldown status), each with a boolean value. A partial or
    role-swapped bundle conflates which cooldown behavior is claimed and
    fails closed; absence leaves the named gate unresolved rather than
    defaulting. The values are bound, not judged: whether they satisfy
    the unchanged-cooldown matrix row is a qualification decision, not
    an identity gate.
    """
    if "cooldown" not in bundle:
        return
    supplied = bundle["cooldown"]
    if not isinstance(supplied, dict) or not supplied:
        raise PrevalidationError("observed cooldown must be a non-empty object")
    if tuple(sorted(supplied)) != tuple(sorted(COOLDOWN_ROLES)):
        raise PrevalidationError("observed cooldown must name exactly the cooldown roles")
    for role, value in supplied.items():
        if not isinstance(value, bool):
            raise PrevalidationError("observed cooldown value must be a boolean for " + role)


def _checked_routing(bundle):
    """Check the claimed routing policy, where supplied, by role.

    The routing policy is host-only and has no frozen packet value, so it
    is bound by shape: a non-empty object naming exactly the three routing
    booleans mirrored from the top-level routing section in
    config.example.yaml (session-affinity, which binds sessions to
    credentials, session-affinity-subagents, which lets child sessions
    inherit the parent's credential, and force-model-prefix, which
    restricts unprefixed model requests), each with a boolean value. A
    partial or role-swapped bundle conflates which routing behavior is
    claimed and fails closed; absence leaves the named gate unresolved
    rather than defaulting. The values are bound, not judged: whether
    they satisfy the unchanged-routing matrix row is a qualification
    decision, not an identity gate.
    """
    if "routing" not in bundle:
        return
    supplied = bundle["routing"]
    if not isinstance(supplied, dict) or not supplied:
        raise PrevalidationError("observed routing must be a non-empty object")
    if tuple(sorted(supplied)) != tuple(sorted(ROUTING_ROLES)):
        raise PrevalidationError("observed routing must name exactly the routing roles")
    for role, value in supplied.items():
        if not isinstance(value, bool):
            raise PrevalidationError("observed routing value must be a boolean for " + role)


def _checked_management(bundle):
    """Check the claimed management policy, where supplied, by role.

    The management policy is host-only and has no frozen packet value,
    so it is bound by shape: a non-empty object naming exactly the three
    management booleans mirrored from the top-level management section
    in config.example.yaml (allow-remote, which admits non-localhost
    management access, disable-control-panel, which skips serving and
    syncing the bundled panel, and disable-auto-update-panel, which
    disables periodic background panel updates), each with a boolean
    value. The secret-key is a secret string, not a boolean policy
    identity, and base-url / panel-github-repository are strings; none
    are named here. A partial or role-swapped bundle conflates which
    management behavior is claimed and fails closed; absence leaves the
    named gate unresolved rather than defaulting. The values are bound,
    not judged: whether they satisfy the unchanged-management matrix
    row is a qualification decision, not an identity gate.
    """
    if "management" not in bundle:
        return
    supplied = bundle["management"]
    if not isinstance(supplied, dict) or not supplied:
        raise PrevalidationError("observed management must be a non-empty object")
    if tuple(sorted(supplied)) != tuple(sorted(MANAGEMENT_ROLES)):
        raise PrevalidationError("observed management must name exactly the management roles")
    for role, value in supplied.items():
        if not isinstance(value, bool):
            raise PrevalidationError("observed management value must be a boolean for " + role)


def _checked_server(bundle):
    """Check the claimed server policy, where supplied, by role.

    The server policy is host-only and has no frozen packet value, so it
    is bound by shape: a non-empty object naming exactly the five server
    booleans mirrored from config.example.yaml under the top-level
    server section (commercial-mode, which trims request-logging
    overhead, tls.enable, which serves HTTPS, response-compression.
    enabled, which compresses downstream responses, discovery.enabled,
    which advertises the gateway over mDNS/DNS-SD, and discovery.
    auth-required, which requires credentials for advertised client
    calls), each with a boolean value. The section's host, port,
    trusted-proxies, github-token, tls cert/key, compression min-bytes
    and discovery service-name/type/subtypes/interfaces are strings,
    lists, paths or ints; discovery.advertise-management is deprecated
    and ignored. None are named here. A partial or role-swapped bundle
    conflates which server behavior is claimed and fails closed;
    absence leaves the named gate unresolved rather than defaulting.
    The values are bound, not judged: whether they satisfy the
    unchanged-server matrix row is a qualification decision, not an
    identity gate.
    """
    if "server" not in bundle:
        return
    supplied = bundle["server"]
    if not isinstance(supplied, dict) or not supplied:
        raise PrevalidationError("observed server must be a non-empty object")
    if tuple(sorted(supplied)) != tuple(sorted(SERVER_ROLES)):
        raise PrevalidationError("observed server must name exactly the server roles")
    for role, value in supplied.items():
        if not isinstance(value, bool):
            raise PrevalidationError("observed server value must be a boolean for " + role)


def _checked_client(bundle):
    """Check the claimed client policy, where supplied, by role.

    The client policy is host-only and has no frozen packet value, so it
    is bound by shape: a non-empty object naming exactly the four client
    booleans mirrored from config.example.yaml under the top-level client
    section (codex enable-apply-patch, which advertises freeform
    apply_patch for supported models, codex optimize-multi-agent-v2,
    which optimizes Codex multi-agent requests, codex
    web-search-result-cache.enabled, which caches upstream web search
    results per session, and claude show-codex-commentary, which mirrors
    public Codex progress into visible Claude text), each with a boolean
    value. The web-search-result-cache ttl and limit are a duration
    string and an int; none are named here. A partial or role-swapped
    bundle conflates which client behavior is claimed and fails closed;
    absence leaves the named gate unresolved rather than defaulting.
    The values are bound, not judged: whether they satisfy the
    unchanged-client matrix row is a qualification decision, not an
    identity gate.
    """
    if "client" not in bundle:
        return
    supplied = bundle["client"]
    if not isinstance(supplied, dict) or not supplied:
        raise PrevalidationError("observed client must be a non-empty object")
    if tuple(sorted(supplied)) != tuple(sorted(CLIENT_ROLES)):
        raise PrevalidationError("observed client must name exactly the client roles")
    for role, value in supplied.items():
        if not isinstance(value, bool):
            raise PrevalidationError("observed client value must be a boolean for " + role)


def _checked_observability(bundle):
    """Check the claimed observability policy, where supplied, by role.

    The observability policy is host-only and has no frozen packet value,
    so it is bound by shape: a non-empty object naming exactly the five
    observability booleans mirrored from config.example.yaml under the
    top-level observability section (logs.debug, which enables debug
    logging, logs.logging-to-file, which writes application logs to
    rotating files instead of stdout, logs.request-log, which records
    proxy request/response logs, usage.usage-statistics-enabled, which
    enables in-memory usage statistics aggregation, and pprof.enable,
    which enables the pprof HTTP debug server), each with a boolean
    value. The logs-max-total-size-mb and error-logs-max-files are ints,
    the redis-usage-queue-retention-seconds is an int, and pprof.addr
    is a host:port string; none are named here. A partial or
    role-swapped bundle conflates which observability behavior is
    claimed and fails closed; absence leaves the named gate unresolved
    rather than defaulting. The values are bound, not judged: whether
    they satisfy the unchanged-observability matrix row is a
    qualification decision, not an identity gate.
    """
    if "observability" not in bundle:
        return
    supplied = bundle["observability"]
    if not isinstance(supplied, dict) or not supplied:
        raise PrevalidationError("observed observability must be a non-empty object")
    if tuple(sorted(supplied)) != tuple(sorted(OBSERVABILITY_ROLES)):
        raise PrevalidationError("observed observability must name exactly the observability roles")
    for role, value in supplied.items():
        if not isinstance(value, bool):
            raise PrevalidationError("observed observability value must be a boolean for " + role)


def _checked_upstream_codex(bundle):
    """Check the claimed upstream codex policy, where supplied, by role.

    The upstream codex policy is host-only and has no frozen packet
    value, so it is bound by shape: a non-empty object naming exactly
    the five upstream codex booleans mirrored from config.example.yaml
    under the top-level upstream.codex section (response-steering,
    which enables full-duplex Codex Responses WebSocket steering,
    upstream-request-compression, which compresses Codex request
    bodies with zstd, websocket-compression, which enables
    permessage-deflate on Codex WebSocket connections,
    stream-bootstrap-buffering, which holds back pre-generation frames
    until the first generated event, and orphan-delegation-
    compatibility, which converts orphan Codex delegation outputs into
    standard user messages), each with a boolean value. The section's
    upstream-request-compression-min-bytes is an int and
    stream-bootstrap-timeout is a duration string; disable-codex-
    cloaking and model-level-cooling are already bound by the policy
    and quota_cooling bundles. None are named here. A partial or
    role-swapped bundle conflates which upstream codex behavior is
    claimed and fails closed; absence leaves the named gate unresolved
    rather than defaulting. The values are bound, not judged: whether
    they satisfy the unchanged-upstream-codex matrix row is a
    qualification decision, not an identity gate.
    """
    if "upstream_codex" not in bundle:
        return
    supplied = bundle["upstream_codex"]
    if not isinstance(supplied, dict) or not supplied:
        raise PrevalidationError("observed upstream codex must be a non-empty object")
    if tuple(sorted(supplied)) != tuple(sorted(UPSTREAM_CODEX_ROLES)):
        raise PrevalidationError("observed upstream codex must name exactly the upstream codex roles")
    for role, value in supplied.items():
        if not isinstance(value, bool):
            raise PrevalidationError("observed upstream codex value must be a boolean for " + role)


def _checked_upstream_claude(bundle):
    """Check the claimed upstream claude policy, where supplied, by role.

    The upstream claude policy is host-only and has no frozen packet
    value, so it is bound by shape: a non-empty object naming exactly
    the upstream claude boolean mirrored from config.example.yaml
    under the top-level upstream.claude section (tool-search, which
    enables Codex client tool_search on Claude Responses routes with
    native tool search on api.anthropic.com and plain translation
    elsewhere), with a boolean value. The section's model-level-
    cooling, disable-claude-cloak-mode and disable-cloaking-model-
    list are already bound by the quota_cooling and policy bundles,
    and session-date-pin-days is an int; none are named here. A
    partial or role-swapped bundle conflates which upstream claude
    behavior is claimed and fails closed; absence leaves the named
    gate unresolved rather than defaulting. The values are bound, not
    judged: whether they satisfy the unchanged-upstream-claude
    matrix row is a qualification decision, not an identity gate.
    """
    if "upstream_claude" not in bundle:
        return
    supplied = bundle["upstream_claude"]
    if not isinstance(supplied, dict) or not supplied:
        raise PrevalidationError("observed upstream claude must be a non-empty object")
    if tuple(sorted(supplied)) != tuple(sorted(UPSTREAM_CLAUDE_ROLES)):
        raise PrevalidationError("observed upstream claude must name exactly the upstream claude roles")
    for role, value in supplied.items():
        if not isinstance(value, bool):
            raise PrevalidationError("observed upstream claude value must be a boolean for " + role)


def _checked_plugins(bundle):
    """Check the claimed plugins policy, where supplied, by role.

    The plugins policy is host-only and has no frozen packet value, so
    it is bound by shape: a non-empty object naming exactly the
    plugins boolean mirrored from config.example.yaml under the
    top-level plugins section (enabled, which toggles dynamic plugin
    loading), with a boolean value. The section's dir is a string,
    store-sources / store-auth are lists, auth-revision is an int and
    configs is an open per-plugin map; none are named here. A partial
    or role-swapped bundle conflates which plugins behavior is
    claimed and fails closed; absence leaves the named gate
    unresolved rather than defaulting. The values are bound, not
    judged: whether they satisfy the unchanged-plugins matrix row is
    a qualification decision, not an identity gate.
    """
    if "plugins" not in bundle:
        return
    supplied = bundle["plugins"]
    if not isinstance(supplied, dict) or not supplied:
        raise PrevalidationError("observed plugins must be a non-empty object")
    if tuple(sorted(supplied)) != tuple(sorted(PLUGINS_ROLES)):
        raise PrevalidationError("observed plugins must name exactly the plugins roles")
    for role, value in supplied.items():
        if not isinstance(value, bool):
            raise PrevalidationError("observed plugins value must be a boolean for " + role)


def _checked_disabled_providers(bundle):
    """Check the claimed disabled-provider set, where supplied, by shape.

    The openai-compatibility `disabled` flag (config.example.yaml,
    config_types.go Disabled) is per-provider and provider names are
    config-defined, so unlike the channel set there is no closed key
    list to mirror. The set is bound by shape only: a non-empty object
    naming secret-screened provider names, each with a boolean value
    (true claims that provider is disabled). Absence leaves the named
    gate unresolved rather than defaulting. The values are bound, not
    judged: whether the disabled set satisfies the unchanged-disabled
    matrix row is a qualification decision, not an identity gate.
    """
    if "disabled_providers" not in bundle:
        return
    supplied = bundle["disabled_providers"]
    if not isinstance(supplied, dict) or not supplied or len(supplied) > 64:
        raise PrevalidationError("observed disabled providers must be a non-empty object")
    for name, value in supplied.items():
        _check_secret_key(name, "observed disabled provider")
        if not isinstance(value, bool):
            raise PrevalidationError("observed disabled provider must be a boolean for " + name)


def _checked_manifest_candidate(manifest):
    if not isinstance(manifest, dict) or manifest.get("schema") != "stock-recovery-source/v1":
        raise PrevalidationError("unsupported source packet schema")
    candidate = manifest.get("candidate")
    if not isinstance(candidate, dict):
        raise PrevalidationError("missing packet candidate")
    for kind in ("index", "manifest", "config"):
        _require_digest(candidate.get(kind + "_digest"), "packet " + kind + " digest")
    _require_digest(candidate.get("docker_image_id"), "packet image ID")
    _require_digest(candidate.get("recovery_manifest_digest"), "packet recovery digest")
    platform = candidate.get("platform")
    if not isinstance(platform, dict) or not platform:
        raise PrevalidationError("packet platform is missing")
    for key, value in platform.items():
        if not isinstance(key, str) or not isinstance(value, str) or not value:
            raise PrevalidationError("packet platform is malformed")
    repository = candidate.get("repository")
    if not isinstance(repository, str) or not repository:
        raise PrevalidationError("packet repository is missing")
    bindings = manifest.get("unresolved_bindings")
    if bindings != list(REQUIRED_BINDINGS):
        raise PrevalidationError("source-only packet must retain every unresolved acceptance gate")
    return candidate


# Closed-schema protocol keys; each is validated by its own checker, so
# the open-ended secret-substring screen does not apply to the key itself.
NAMED_BUNDLE_KEYS = ("source_digests", "provider_artifacts", "compose_config", "authoritative_store", "policy", "quota_cooling", "cooldown", "routing", "management", "server", "client", "observability", "upstream_codex", "upstream_claude", "plugins", "disabled_providers")


def _check_secret_key(key, label, named_bundle=False):
    if not isinstance(key, str) or not key or len(key) > 128:
        raise PrevalidationError(label + " key is malformed")
    if named_bundle:
        return
    lowered = key.lower()
    if any(part in lowered for part in SECRET_SUBSTRINGS):
        raise PrevalidationError(label + " must not carry secrets")


def _checked_manifest_files(manifest):
    files = manifest.get("files")
    if not isinstance(files, dict) or not files or len(files) > 64:
        raise PrevalidationError("packet source inputs are missing")
    for name, expected in files.items():
        # File names are fixed packet identities (e.g. retained/authcount
        # legitimately contains a secret-shaped substring); only the
        # digest shape is enforced here.
        if not isinstance(name, str) or not name:
            raise PrevalidationError("packet source input key is malformed")
        _require_digest(expected, "packet source digest for " + name)
    return files


def _checked_source_digests(files, bundle):
    """Compare an optional observed source bundle against the packet by name.

    Source/helper/runbook identities are frozen in the packet, so any
    observed digest supplied under source_digests must match exactly.
    Absence leaves the named gate unresolved rather than defaulting.
    """
    if "source_digests" not in bundle:
        return
    supplied = bundle["source_digests"]
    if not isinstance(supplied, dict) or not supplied or len(supplied) > 64:
        raise PrevalidationError("observed source digests must be a non-empty object")
    for name, expected in supplied.items():
        # Unknown names fail closed — including secret-shaped names,
        # which cannot be frozen packet files.
        if not isinstance(name, str) or not name:
            raise PrevalidationError("observed source digest key is malformed")
        if name not in files:
            raise PrevalidationError("observed source digest is not in the frozen packet: " + name)
        _require_digest(expected, "observed source digest for " + name)
        if expected != files[name]:
            raise PrevalidationError("observed source digest does not match the frozen packet: " + name)


def _checked_provider_artifacts(bundle):
    """Check provider artifact identities, where supplied, against the channels.

    Provider artifact identities are host-only and have no frozen packet
    value, so they are bound by shape: a non-empty object naming only
    supported configuration channels, each with a digest value. Unknown
    or secret-shaped channels fail closed; absence leaves the named gate
    unresolved rather than defaulting.
    """
    if "provider_artifacts" not in bundle:
        return
    supplied = bundle["provider_artifacts"]
    if not isinstance(supplied, dict) or not supplied or len(supplied) > len(SUPPORTED_PROVIDER_CHANNELS):
        raise PrevalidationError("observed provider artifacts must be a non-empty object")
    for name, expected in supplied.items():
        if not isinstance(name, str) or not name:
            raise PrevalidationError("observed provider artifact key is malformed")
        if name not in SUPPORTED_PROVIDER_CHANNELS:
            raise PrevalidationError("observed provider artifact is not a supported channel: " + name)
        _require_digest(expected, "observed provider artifact digest for " + name)


def _checked_observed(observed):
    if not isinstance(observed, dict):
        raise PrevalidationError("observed identities must be an object")
    if len(observed) > 32:
        raise PrevalidationError("observed identities exceed key limit")
    for key, value in observed.items():
        _check_secret_key(key, "observed identity", named_bundle=key in NAMED_BUNDLE_KEYS)
        if value is None or isinstance(value, (bool, int, float)):
            raise PrevalidationError("observed identity value is malformed")
    for required in REQUIRED_OBSERVED_KEYS:
        if required not in observed:
            raise PrevalidationError("observed identity is missing: " + required)
    return observed


def prevalidate(manifest, observed):
    candidate = _checked_manifest_candidate(manifest)
    files = _checked_manifest_files(manifest)
    bundle = _checked_observed(observed)

    if bundle["repository"] != candidate["repository"]:
        raise PrevalidationError("repository does not match the frozen candidate")
    platform = bundle["platform"]
    if not isinstance(platform, dict) or platform != candidate["platform"]:
        raise PrevalidationError("platform does not match the frozen candidate")

    # OCI identities must be compared by role, never by tag or by swap.
    for kind, label in (
        ("index_digest", "index digest"),
        ("manifest_digest", "manifest digest"),
        ("config_digest", "config digest"),
    ):
        _require_digest(bundle.get(kind), "observed " + label)
        if bundle[kind] != candidate[kind]:
            raise PrevalidationError("observed " + label + " does not match the frozen candidate")
    _require_digest(bundle.get("docker_image_id"), "observed image ID")
    if bundle["docker_image_id"] != candidate["config_digest"]:
        raise PrevalidationError("image ID must be the config digest, not the registry index")
    _require_digest(bundle.get("recovery_manifest_digest"), "observed recovery digest")
    if bundle["recovery_manifest_digest"] != candidate["manifest_digest"]:
        raise PrevalidationError("an alternative recovery target needs separate qualification")

    # Frozen source/helper/runbook identities, where supplied, must match
    # the packet by name; absence leaves the named gate unresolved.
    _checked_source_digests(files, bundle)

    # Provider artifact identities, where supplied, must name supported
    # channels with digest values; absence leaves the gate unresolved.
    _checked_provider_artifacts(bundle)

    # Host Compose/config identities, where supplied, must name both
    # roles with digest values; absence leaves the gate unresolved.
    _checked_compose_config(bundle)

    # The claimed authoritative store, where supplied, must name exactly
    # one supported backend; absence leaves the gate unresolved.
    _checked_authoritative_store(bundle)

    # The claimed cloak policy, where supplied, must name exactly the
    # three cloak booleans; absence leaves the gate unresolved.
    _checked_policy(bundle)

    # The claimed quota-cooling policy, where supplied, must name
    # exactly the two quota-cooling booleans; absence leaves the
    # gate unresolved.
    _checked_quota_cooling(bundle)

    # The claimed global cooldown policy, where supplied, must name
    # exactly the two routing.cooldown booleans; absence leaves the
    # gate unresolved.
    _checked_cooldown(bundle)

    # The claimed routing policy, where supplied, must name exactly the
    # three top-level routing booleans; absence leaves the gate
    # unresolved.
    _checked_routing(bundle)

    # The claimed management policy, where supplied, must name exactly
    # the three top-level management booleans; absence leaves the gate
    # unresolved.
    _checked_management(bundle)

    # The claimed server policy, where supplied, must name exactly the
    # five top-level server booleans; absence leaves the gate
    # unresolved.
    _checked_server(bundle)

    # The claimed client policy, where supplied, must name exactly the
    # four top-level client booleans; absence leaves the gate
    # unresolved.
    _checked_client(bundle)

    # The claimed observability policy, where supplied, must name
    # exactly the five top-level observability booleans; absence
    # leaves the gate unresolved.
    _checked_observability(bundle)

    # The claimed upstream codex policy, where supplied, must name
    # exactly the five top-level upstream.codex booleans; absence
    # leaves the gate unresolved.
    _checked_upstream_codex(bundle)

    # The claimed upstream claude policy, where supplied, must name
    # exactly the top-level upstream.claude tool-search boolean;
    # absence leaves the gate unresolved.
    _checked_upstream_claude(bundle)

    # The claimed plugins policy, where supplied, must name exactly
    # the top-level plugins enabled boolean; absence leaves the gate
    # unresolved.
    _checked_plugins(bundle)

    # The claimed disabled-provider set, where supplied, must name
    # secret-screened providers with boolean values; absence leaves
    # the gate unresolved.
    _checked_disabled_providers(bundle)

    # Optional host-only identities are validated only where supplied;
    # absence leaves the named gate unresolved rather than defaulting.
    for key, value in bundle.items():
        if key in REQUIRED_OBSERVED_KEYS or key in NAMED_BUNDLE_KEYS:
            continue
        if isinstance(value, str):
            _require_digest(value, "host-only identity " + key)
        elif isinstance(value, list) and value:
            for item in value:
                _require_digest(item, "host-only identity " + key)
        elif isinstance(value, dict) and value:
            # Nested keys are screened too, so a secret-shaped host
            # identity cannot hide one level down under a clean name.
            for nested_key, item in value.items():
                _check_secret_key(nested_key, "host-only identity " + key)
                _require_digest(item, "host-only identity " + key)
        else:
            raise PrevalidationError("host-only identity is malformed: " + key)

    return {
        "identity_match": True,
        "source_binding": "BOUND",
        "qualification": "HOLD",
        "service_recovery": "NOT_TESTED",
        "execution_authorized": False,
        "unresolved_bindings": list(REQUIRED_BINDINGS),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, help="source packet manifest")
    parser.add_argument("--observed", required=True, help="observed identity bundle JSON")
    args = parser.parse_args(argv)
    try:
        manifest_raw = Path(args.manifest).read_bytes()
        observed_raw = Path(args.observed).read_bytes()
        if len(manifest_raw) > 1024 * 1024 or len(observed_raw) > MAX_OBSERVED_BYTES:
            raise PrevalidationError("identity input exceeds size limit")
        result = prevalidate(json.loads(manifest_raw), json.loads(observed_raw))
    except PrevalidationError:
        print(json.dumps({"identity_match": False, "qualification": "HOLD", "error_type": "PrevalidationError"}))
        return 1
    except (OSError, ValueError, TypeError):
        print(json.dumps({"identity_match": False, "qualification": "HOLD", "error_type": "InputError"}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
