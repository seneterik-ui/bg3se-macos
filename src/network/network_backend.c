/**
 * BG3SE-macOS - Network Backend Implementation
 *
 * Provides LocalBackend (in-process message bus) and RakNetBackend
 * (game transport via GameServer VMT dispatch).
 *
 * Issue #6: NetChannel API (Phase 4A / 4G)
 */

#include "network_backend.h"
#include "message_bus.h"
#include "net_hooks.h"
#include "extender_message.h"
#include "peer_manager.h"
#include "../core/logging.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// ============================================================================
// Static State
// ============================================================================

static bool s_initialized = false;

// ============================================================================
// JSON String Escape Helper
//
// Escapes characters that would break JSON string context: ", \, and
// control characters (0x00-0x1F). Returns bytes written (excluding NUL),
// or 0 if the buffer is too small.
// ============================================================================

static size_t json_escape_string(char *out, size_t out_cap, const char *in) {
    if (!in || !out || out_cap == 0) return 0;

    size_t w = 0;  // write position
    for (const char *p = in; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '"' || c == '\\') {
            if (w + 2 >= out_cap) return 0;
            out[w++] = '\\';
            out[w++] = (char)c;
        } else if (c < 0x20) {
            // Control character — encode as \uXXXX
            if (w + 6 >= out_cap) return 0;
            int n = snprintf(out + w, out_cap - w, "\\u%04x", c);
            if (n < 0) return 0;
            w += (size_t)n;
        } else {
            if (w + 1 >= out_cap) return 0;
            out[w++] = (char)c;
        }
    }
    if (w >= out_cap) return 0;
    out[w] = '\0';
    return w;
}

// ============================================================================
// LocalBackend Implementation
//
// Routes all messages through the in-process message_bus.
// Used for single-player / local testing.
// ============================================================================

static bool local_send_to_server(const char *channel, const char *module,
                                 const char *payload, uint64_t request_id,
                                 bool binary) {
    NetMessage msg = message_create_to_server(channel, module, payload, request_id);
    msg.binary = binary;
    bool ok = message_bus_queue(&msg);
    message_free(&msg);
    return ok;
}

static bool local_send_to_user(int32_t user_id, const char *channel,
                               const char *module, const char *payload,
                               uint64_t request_id, bool binary) {
    NetMessage msg = message_create_to_user(user_id, channel, module, payload,
                                            request_id);
    msg.binary = binary;
    bool ok = message_bus_queue(&msg);
    message_free(&msg);
    return ok;
}

static bool local_send_to_client(const char *guid, const char *channel,
                                 const char *module, const char *payload,
                                 uint64_t request_id, bool binary) {
    NetMessage msg = message_create_to_client(guid, channel, module, payload,
                                              request_id);
    msg.binary = binary;
    bool ok = message_bus_queue(&msg);
    message_free(&msg);
    return ok;
}

static bool local_broadcast(const char *channel, const char *module,
                            const char *payload, const char *exclude_char,
                            uint64_t request_id, bool binary) {
    NetMessage msg = message_create_broadcast(channel, module, payload,
                                              exclude_char, request_id);
    msg.binary = binary;
    bool ok = message_bus_queue(&msg);
    message_free(&msg);
    return ok;
}

static bool local_is_host(bool is_server) {
    return message_bus_is_host(is_server);
}

static int local_get_version(void) {
    return message_bus_version();
}

// ============================================================================
// RakNet Backend Implementation (Phase 4G)
//
// Routes messages through the game's RakNet transport via
// net_hooks_send_message() -> GameServer VMT SendToPeer.
//
// Wire format: JSON-encoded NetMessage fields as ExtenderMessage payload.
// Format: {"c":"channel","m":"module","p":"payload","r":request_id}
// ============================================================================

/**
 * Build a JSON wire payload from message fields and send via GameServer.
 * Returns true if the message was sent successfully.
 */
static bool raknet_send(int32_t peer_id, const char *channel, const char *module,
                        const char *payload, uint64_t request_id, bool binary) {
    // Phase 4I: Gate sends on handshake completion
    if (!peer_manager_can_send_extender(peer_id)) {
        LOG_NET_WARN("raknet_send: peer %d has not completed handshake, dropping", peer_id);
        return false;
    }

    // Build JSON wire payload with proper escaping for channel/module.
    // Payload is interpolated as a raw JSON value (caller must ensure valid JSON).
    const char *safe_channel = channel ? channel : "";
    const char *safe_module = module ? module : "";

    // Escape channel and module to prevent JSON injection
    size_t chan_len = strlen(safe_channel);
    size_t mod_len = strlen(safe_module);
    size_t esc_chan_cap = chan_len * 6 + 1;  // worst case: all \uXXXX
    size_t esc_mod_cap = mod_len * 6 + 1;
    char *esc_chan = malloc(esc_chan_cap);
    char *esc_mod = malloc(esc_mod_cap);
    if (!esc_chan || !esc_mod) {
        LOG_NET_ERROR("raknet_send: escape buffer malloc failed");
        free(esc_chan);
        free(esc_mod);
        return false;
    }

    json_escape_string(esc_chan, esc_chan_cap, safe_channel);
    json_escape_string(esc_mod, esc_mod_cap, safe_module);

    size_t json_cap = 256 + (payload ? strlen(payload) : 0)
                          + strlen(esc_chan) + strlen(esc_mod);
    char *json = malloc(json_cap);
    if (!json) {
        LOG_NET_ERROR("raknet_send: malloc(%zu) failed", json_cap);
        free(esc_chan);
        free(esc_mod);
        return false;
    }

    int written = snprintf(json, json_cap,
        "{\"c\":\"%s\",\"m\":\"%s\",\"p\":%s,\"r\":%llu,\"b\":%s}",
        esc_chan,
        esc_mod,
        (payload && payload[0]) ? payload : "\"\"",
        (unsigned long long)request_id,
        binary ? "true" : "false");

    free(esc_chan);
    free(esc_mod);

    if (written < 0 || (size_t)written >= json_cap) {
        LOG_NET_ERROR("raknet_send: JSON truncated (%d >= %zu)", written, json_cap);
        free(json);
        return false;
    }

    // Create ExtenderMessage and set payload
    ExtenderMessage *msg = extender_message_pool_get();
    if (!msg) {
        LOG_NET_ERROR("raknet_send: failed to get message from pool");
        free(json);
        return false;
    }

    if (!extender_message_set_payload(msg, json, (uint32_t)written)) {
        LOG_NET_ERROR("raknet_send: failed to set payload (%d bytes)", written);
        extender_message_pool_return(msg);
        free(json);
        return false;
    }

    free(json);

    // Send via GameServer VMT
    bool ok = net_hooks_send_message(peer_id, &msg->base);

    // Note: the game will call em_serialize on this message during transport,
    // which writes the payload to the bitstream. The message should NOT be
    // returned to pool here — the game still holds a reference.
    // Pool return happens after the game's send path completes.
    // For safety, we leak the pool slot for now. This is acceptable because:
    // 1. Extender messages are rare (<<1 per frame)
    // 2. Pool has 8 slots, malloc fallback exists
    // TODO: Hook the post-send path to reclaim pool slots.

    if (!ok) {
        // Send failed — safe to reclaim immediately
        extender_message_pool_return(msg);
    }

    return ok;
}

static bool raknet_send_to_server(const char *channel, const char *module,
                                   const char *payload, uint64_t request_id,
                                   bool binary) {
    // Client sends to peer 0 (the server)
    return raknet_send(0, channel, module, payload, request_id, binary);
}

static bool raknet_send_to_user(int32_t user_id, const char *channel,
                                 const char *module, const char *payload,
                                 uint64_t request_id, bool binary) {
    return raknet_send(user_id, channel, module, payload, request_id, binary);
}

static bool raknet_send_to_client(const char *guid, const char *channel,
                                   const char *module, const char *payload,
                                   uint64_t request_id, bool binary) {
    int32_t user_id = peer_manager_find_by_guid(guid);
    if (user_id < 0) {
        LOG_NET_WARN("raknet_send_to_client: no peer found for GUID %.32s",
                     guid ? guid : "(null)");
        return false;
    }
    return raknet_send(user_id, channel, module, payload, request_id, binary);
}

typedef struct {
    const char *channel;
    const char *module;
    const char *payload;
    const char *exclude_char;
    uint64_t request_id;
    bool binary;
    int sent;
} BroadcastCtx;

static bool broadcast_visitor(const PeerInfo *peer, void *user_data) {
    BroadcastCtx *ctx = (BroadcastCtx *)user_data;

    // Skip excluded character
    if (ctx->exclude_char && ctx->exclude_char[0] &&
        peer->character_guid[0] &&
        strcmp(peer->character_guid, ctx->exclude_char) == 0) {
        return true;
    }

    // Skip host (server sends to others, not itself)
    if (peer->is_host) return true;

    // Skip peers without handshake (Phase 4I)
    if (peer->proto_version == 0) return true;

    if (raknet_send(peer->user_id, ctx->channel, ctx->module,
                    ctx->payload, ctx->request_id, ctx->binary)) {
        ctx->sent++;
    }
    return true;
}

static bool raknet_broadcast(const char *channel, const char *module,
                              const char *payload, const char *exclude_char,
                              uint64_t request_id, bool binary) {
    // Sync PeerManager with GameServer's active peer list
    net_hooks_sync_active_peers();

    BroadcastCtx ctx = {
        .channel = channel,
        .module = module,
        .payload = payload,
        .exclude_char = exclude_char,
        .request_id = request_id,
        .binary = binary,
        .sent = 0
    };

    peer_manager_iterate(broadcast_visitor, &ctx);
    LOG_NET_DEBUG("raknet_broadcast: sent to %d peers", ctx.sent);
    return ctx.sent > 0;
}

static bool raknet_is_host(bool is_server) {
    // In RakNet mode, the server context IS the host
    return is_server;
}

static int raknet_get_version(void) {
    return PROTO_VERSION_CURRENT;
}

static NetworkBackend s_raknet_backend = {
    .type            = NETWORK_BACKEND_RAKNET,
    .send_to_server  = raknet_send_to_server,
    .send_to_user    = raknet_send_to_user,
    .send_to_client  = raknet_send_to_client,
    .broadcast       = raknet_broadcast,
    .is_host         = raknet_is_host,
    .get_version     = raknet_get_version,
};

// ============================================================================
// Backend Instances
// ============================================================================

static NetworkBackend s_local_backend = {
    .type            = NETWORK_BACKEND_LOCAL,
    .send_to_server  = local_send_to_server,
    .send_to_user    = local_send_to_user,
    .send_to_client  = local_send_to_client,
    .broadcast       = local_broadcast,
    .is_host         = local_is_host,
    .get_version     = local_get_version,
};

static NetworkBackend *s_active_backend = NULL;

// ============================================================================
// Public API
// ============================================================================

void network_backend_init(void) {
    if (s_initialized) return;

    s_active_backend = &s_local_backend;
    s_initialized = true;

    LOG_NET_DEBUG("Network backend initialized (LocalBackend)");
}

NetworkBackend *network_backend_get(void) {
    if (!s_initialized) {
        network_backend_init();
    }
    return s_active_backend;
}

NetworkBackendType network_backend_get_type(void) {
    if (!s_initialized) {
        network_backend_init();
    }
    return s_active_backend->type;
}

void network_backend_set_raknet(void) {
    if (!net_hooks_get_game_server()) {
        LOG_NET_WARN("network_backend_set_raknet: GameServer not captured, staying on LocalBackend");
        return;
    }
    s_active_backend = &s_raknet_backend;
    LOG_NET_INFO("Switched to RakNetBackend (GameServer=%p)", net_hooks_get_game_server());
}

void network_backend_set_local(void) {
    s_active_backend = &s_local_backend;
    LOG_NET_INFO("Switched to LocalBackend");
}
