/**
 * BG3SE-macOS - Extender Protocol Implementation
 *
 * Custom protocol inserted at index 0 of the game's ProtocolList.
 * Intercepts NETMSG_SCRIPT_EXTENDER (ID 400) messages and routes
 * them to the message bus for Lua event dispatch.
 *
 * Uses Itanium C++ ABI vtable layout for macOS ARM64 compatibility.
 * See protocol.h for the vtable structure.
 *
 * Issue #6: NetChannel API (Phase 4D)
 */

#include "extender_protocol.h"
#include "extender_message.h"
#include "message_bus.h"
#include "peer_manager.h"
#include "net_hooks.h"
#include "../core/logging.h"
#include "../core/safe_memory.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// ============================================================================
// Static State
// ============================================================================

static ExtenderProtocol *s_instance = NULL;

// ============================================================================
// VMT Function Implementations
//
// These match the game's net::Protocol virtual function signatures.
// The game will call these through our Itanium-compatible vtable.
// ============================================================================

static void extender_destructor(Protocol *self) {
    LOG_NET_DEBUG("ExtenderProtocol destructor called");

    ExtenderProtocol *ep = (ExtenderProtocol *)self;
    if (ep == s_instance) {
        s_instance = NULL;
    }
}

static void extender_deleting_destructor(Protocol *self) {
    LOG_NET_DEBUG("ExtenderProtocol deleting destructor called");

    ExtenderProtocol *ep = (ExtenderProtocol *)self;
    if (ep == s_instance) {
        s_instance = NULL;
    }
    free(ep);
}

// ============================================================================
// Hello Message Helpers (Phase 4I)
//
// The hello message is a JSON handshake: {"t":"hello","v":N}
// where N is the ProtoVersion value (currently 2).
//
// When received:
//   - Register/update the peer's proto_version
//   - If we're the server, send a hello reply
// ============================================================================

/**
 * Check if a payload is a hello message.
 * Copies payload into a NUL-terminated stack buffer to avoid overreads
 * (em->payload may not be NUL-terminated).
 */
static bool is_hello_message(const uint8_t *payload, uint32_t len) {
    if (!payload || len < 14 || len > 127) return false;  // minimum: {"t":"hello"}
    char buf[128];
    memcpy(buf, payload, len);
    buf[len] = '\0';
    return strstr(buf, "\"t\":\"hello\"") != NULL;
}

/**
 * Parse the version field from a hello JSON payload.
 * Copies payload into a NUL-terminated stack buffer first.
 * Looks for "v":N where N is an integer.
 * Returns 0 on parse failure.
 */
static uint32_t parse_hello_version(const uint8_t *payload, uint32_t len) {
    if (!payload || len == 0 || len > 127) return 0;
    char buf[128];
    memcpy(buf, payload, len);
    buf[len] = '\0';

    const char *vp = strstr(buf, "\"v\":");
    if (!vp) return 0;

    vp += 4;  // skip "v":
    while (*vp == ' ') vp++;

    int version = 0;
    if (sscanf(vp, "%d", &version) != 1 || version < 0) {
        return 0;
    }
    return (uint32_t)version;
}

/**
 * Send a hello reply to a specific peer.
 * Uses net_hooks_send_message() directly (bypasses raknet_send gating).
 */
static void send_hello_reply(int32_t peer_id) {
    char hello[64];
    snprintf(hello, sizeof(hello), "{\"t\":\"hello\",\"v\":%d}", PROTO_VERSION_CURRENT);

    ExtenderMessage *msg = extender_message_pool_get();
    if (!msg) {
        LOG_NET_WARN("send_hello_reply: pool exhausted");
        return;
    }

    if (!extender_message_set_payload(msg, hello, (uint32_t)strlen(hello))) {
        LOG_NET_WARN("send_hello_reply: failed to set payload");
        extender_message_pool_return(msg);
        return;
    }

    bool ok = net_hooks_send_message(peer_id, &msg->base);
    if (ok) {
        LOG_NET_INFO("Sent hello reply to peer %d (version %d)",
                     peer_id, PROTO_VERSION_CURRENT);
    } else {
        LOG_NET_WARN("send_hello_reply: send to peer %d failed", peer_id);
        extender_message_pool_return(msg);
    }
}

/**
 * Process an incoming network message.
 *
 * Checks if msg->MessageId == NETMSG_SCRIPT_EXTENDER (400).
 * If so, deserializes the payload and routes to message_bus.
 * Otherwise returns Unhandled to pass through the protocol chain.
 */
static ProtocolResult extender_process_msg(Protocol *self, void *unused,
                                           MessageContext *ctx, void *msg) {
    (void)self;
    (void)unused;

    if (!msg) {
        return PROTOCOL_RESULT_UNHANDLED;
    }

    // The game's net::Message has msg_id at offset 8 (after vptr)
    uint32_t msg_id = 0;
    if (!safe_memory_read_u32((mach_vm_address_t)msg + 8, &msg_id)) {
        return PROTOCOL_RESULT_UNHANDLED;
    }

    if (msg_id != NETMSG_SCRIPT_EXTENDER) {
        return PROTOCOL_RESULT_UNHANDLED;
    }

    int32_t sender = ctx ? ctx->user_id : -1;
    LOG_NET_INFO("ExtenderProtocol: received NETMSG_SCRIPT_EXTENDER from user %d", sender);

    // Auto-register unknown peers on first message (implicit handshake, Phase 4H)
    if (sender >= 0 && !peer_manager_get_peer(sender)) {
        peer_manager_add_peer(sender, NULL, false);
        peer_manager_set_proto_version(sender, PROTO_VERSION_CURRENT);
        LOG_NET_INFO("  Auto-registered peer user_id=%d (implicit handshake)", sender);
    }

    // Validate VMT before casting — ensures msg was allocated by our GetMessage hook
    if (!extender_message_is_ours(msg)) {
        LOG_NET_WARN("ExtenderProtocol: msg %p has unknown VMT, not our ExtenderMessage", msg);
        return PROTOCOL_RESULT_UNHANDLED;
    }

    // Cast to ExtenderMessage (VMT-validated)
    ExtenderMessage *em = (ExtenderMessage *)msg;

    // At this point, the game has already called em_serialize(deserializer).
    // Once BitstreamSerializer RE is complete (Phase 4G), em->payload will
    // contain the deserialized payload bytes.
    if (!em->payload || em->payload_size == 0) {
        LOG_NET_DEBUG("  ExtenderMessage has no payload (em_serialize is diagnostic-only)");
        extender_message_pool_return(em);
        return PROTOCOL_RESULT_HANDLED;
    }

    // Phase 4I: Intercept hello messages for handshake
    if (is_hello_message(em->payload, em->payload_size)) {
        uint32_t peer_version = parse_hello_version(em->payload, em->payload_size);
        if (sender >= 0 && peer_version > 0) {
            // Only reply if this is the peer's FIRST hello (proto_version was 0).
            // This prevents infinite ping-pong: client sends hello → server replies
            // → client receives reply (also a hello) but doesn't reply again.
            bool first_hello = false;
            PeerInfo *pi = peer_manager_get_peer(sender);
            if (pi && pi->proto_version == 0) {
                first_hello = true;
            }

            peer_manager_set_proto_version(sender, peer_version);
            LOG_NET_INFO("  Handshake: peer %d, version %u", sender, peer_version);

            if (first_hello) {
                send_hello_reply(sender);
            }
        } else if (peer_version == 0) {
            LOG_NET_WARN("  Hello from peer %d has invalid version", sender);
        }
        extender_message_pool_return(em);
        return PROTOCOL_RESULT_HANDLED;
    }

    // Parse the payload as a JSON-encoded NetMessage.
    // Expected format: {"Channel":"ch","Module":"mod","Payload":"data",...}
    // For now, treat the entire payload as the message payload on a default channel.
    LOG_NET_INFO("  Processing %u-byte payload from user %d", em->payload_size, sender);

    NetMessage net_msg = message_create_to_server("", "", "", 0);
    net_msg.user_id = sender;

    // Copy raw payload as the message content
    net_msg.payload = malloc(em->payload_size + 1);
    if (net_msg.payload) {
        memcpy(net_msg.payload, em->payload, em->payload_size);
        net_msg.payload[em->payload_size] = '\0';
        net_msg.payload_len = em->payload_size;

        if (!message_bus_queue_from_peer(sender, &net_msg)) {
            LOG_NET_WARN("  Failed to queue message from peer %d", sender);
        }
        free(net_msg.payload);
        net_msg.payload = NULL;
    }

    // Return message to pool
    extender_message_pool_return(em);

    return PROTOCOL_RESULT_HANDLED;
}

static ProtocolResult extender_pre_update(Protocol *self, void *game_time) {
    (void)self;
    (void)game_time;
    return PROTOCOL_RESULT_UNHANDLED;
}

static ProtocolResult extender_post_update(Protocol *self, void *game_time) {
    (void)self;
    (void)game_time;
    return PROTOCOL_RESULT_UNHANDLED;
}

static void extender_on_added_to_host(Protocol *self) {
    (void)self;
    LOG_NET_INFO("ExtenderProtocol added to host");

    ExtenderProtocol *ep = (ExtenderProtocol *)self;
    ep->active = true;
}

static void extender_on_removed_from_host(Protocol *self) {
    (void)self;
    LOG_NET_INFO("ExtenderProtocol removed from host");

    ExtenderProtocol *ep = (ExtenderProtocol *)self;
    ep->active = false;
}

static void extender_reset(Protocol *self) {
    (void)self;
    LOG_NET_DEBUG("ExtenderProtocol reset");
}

// ============================================================================
// Itanium C++ ABI Vtable Block
//
// Layout in memory:
//   [offset_to_top = 0]         <- preamble
//   [typeinfo = NULL]            <- preamble
//   [complete_destructor]        <- vmt[0]  (vptr points here)
//   [deleting_destructor]        <- vmt[1]
//   [process_msg]                <- vmt[2]
//   [pre_update]                 <- vmt[3]
//   [post_update]                <- vmt[4]
//   [on_added_to_host]           <- vmt[5]
//   [on_removed_from_host]       <- vmt[6]
//   [reset]                      <- vmt[7]
//
// Protocol.vmt points to &s_vtable_block.vmt (past the preamble).
// ============================================================================

static const ProtocolVtableBlock s_vtable_block = {
    .preamble = {
        .offset_to_top = 0,
        .typeinfo = NULL,
    },
    .vmt = {
        .complete_destructor = extender_destructor,
        .deleting_destructor = extender_deleting_destructor,
        .process_msg         = extender_process_msg,
        .pre_update          = extender_pre_update,
        .post_update         = extender_post_update,
        .on_added_to_host    = extender_on_added_to_host,
        .on_removed_from_host = extender_on_removed_from_host,
        .reset               = extender_reset,
    },
};

// ============================================================================
// Public API
// ============================================================================

ExtenderProtocol *extender_protocol_create(void) {
    ExtenderProtocol *proto = calloc(1, sizeof(ExtenderProtocol));
    if (!proto) {
        LOG_NET_ERROR("Failed to allocate ExtenderProtocol");
        return NULL;
    }

    // Point vmt past the preamble to the actual function table
    proto->base.vmt = &s_vtable_block.vmt;
    proto->base.peer = NULL;  // Set when added to ProtocolList
    proto->active = false;

    LOG_NET_DEBUG("Created ExtenderProtocol at %p (vmt=%p)", (void *)proto, (void *)&s_vtable_block.vmt);
    return proto;
}

void extender_protocol_destroy(ExtenderProtocol *proto) {
    if (!proto) return;

    LOG_NET_DEBUG("Destroying ExtenderProtocol at %p", (void *)proto);

    if (proto == s_instance) {
        s_instance = NULL;
    }

    free(proto);
}

ExtenderProtocol *extender_protocol_get(void) {
    if (!s_instance) {
        s_instance = extender_protocol_create();
    }
    return s_instance;
}

bool extender_protocol_is_active(void) {
    return s_instance && s_instance->active;
}
