#ifndef MTPROTO_ENGINE_H
#define MTPROTO_ENGINE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct MTEngine MTEngine;
typedef struct MTBuffer MTBuffer;
typedef uint64_t MTSessionHandle;
typedef uint64_t MTRequestId;

typedef struct {
    const uint8_t *data;
    size_t length;
} MTBytes;

typedef struct {
    const char *data;
    size_t length;
} MTString;

typedef struct {
    int64_t salt;
    double valid_since;
    double valid_until;
} MTSaltEntry;

typedef struct {
    MTString host;
    uint16_t port;
    MTBytes secret;
} MTAddress;

/* A temporary key the server has bound to the session's permanent key; expires_at in server time. */
typedef struct {
    MTBytes key;
    int32_t expires_at;
    /* The permanent key id it is bound to, 0 when unknown: an offer bound to another key is refused. */
    int64_t bound_to;
    const MTSaltEntry *salts;
    size_t salt_count;
    uint8_t has_init_hash;
    MTString init_hash;
} MTTemporaryKey;

enum {
    MTProxyKindNone = 0,
    MTProxyKindSocks5 = 1,
    MTProxyKindMTProxy = 2,
    /* TCP through a CONNECT tunnel; HTTP forwarded by the proxy. */
    MTProxyKindHttp = 3,
    /* A WEB proxy: the MTProxy transport obfuscated with secret, over the stream host's carrier
       (MTStreamTarget.carrier); host is the relay, for display only. Nothing connects without the
       stream host. */
    MTProxyKindWeb = 4,
};

typedef struct {
    uint8_t kind;
    MTString host;
    uint16_t port;
    MTString username;
    MTString password;
    MTBytes secret;
} MTProxy;

typedef struct {
    int32_t layer;
    int32_t api_id;
    MTString device_model;
    MTString system_version;
    MTString app_version;
    MTString system_lang_code;
    MTString lang_pack;
    MTString lang_code;
    uint8_t has_proxy;
    MTString proxy_address;
    int32_t proxy_port;
    uint8_t has_params;
    MTBytes params;
    MTString init_hash;
    uint8_t disable_updates;
} MTEnvironment;

enum {
    MTSessionRoleMain = 0,
    MTSessionRoleWorker = 1,
    MTSessionRoleWorkerRequiringAuthToken = 2,
    MTSessionRoleCdn = 3,
};

enum {
    MTFramingAbridged = 0,
    MTFramingIntermediate = 1,
    MTFramingPaddedIntermediate = 2,
};

typedef struct {
    int32_t datacenter_id;
    int16_t obfuscation_dc_id;
    uint8_t role;
    uint8_t framing;
    const MTAddress *addresses;
    size_t address_count;
    MTProxy proxy;
    MTBytes auth_key;
    const MTSaltEntry *salts;
    size_t salt_count;
    uint8_t has_init_hash;
    MTString init_hash;
    uint8_t generate_key;
    const MTString *public_keys_pem;
    size_t public_key_count;
    int32_t temp_key_expires_in;
    const MTEnvironment *environment;
    double time_difference;
    uint8_t online;
    uint8_t paused;
    uint8_t keep_connected;
    double idle_disconnect_after;
    double request_timeout;
    /* PFS run by the engine from the start, as mt_session_enable_pfs with public_keys_pem: 0 leaves it off. */
    int32_t pfs_lifetime;
    uint8_t pfs_make_permanent_key;
    const MTTemporaryKey *pfs_temporary_key;
} MTSessionSetup;

enum {
    MTRequestFlagAutomaticFloodWait = 1 << 0,
    MTRequestFlagReportFloodWait = 1 << 1,
    MTRequestFlagRetryServerErrors = 1 << 2,
    MTRequestFlagQuickAck = 1 << 3,
    MTRequestFlagProgress = 1 << 4,
    MTRequestFlagTimeoutTimer = 1 << 5,
    MTRequestFlagWithoutUpdates = 1 << 6,
    MTRequestFlagDelegateRetryDecisions = 1 << 7,
};

typedef struct {
    MTRequestId id;
    MTBytes body;
    uint32_t flags;
    uint32_t expected_response_size;
    MTRequestId invoke_after;
} MTRequest;

typedef enum {
    MTEventKindCompleted = 1,
    MTEventKindFailed = 2,
    MTEventKindAcknowledged = 3,
    MTEventKindProgress = 4,
    MTEventKindFloodWaitReported = 5,
    MTEventKindAuthorizationRequired = 6,
    MTEventKindSoftAuthReset = 7,
    MTEventKindAuthTokenRequired = 8,
    MTEventKindTemporaryKeyRejected = 9,
    MTEventKindInitHashStored = 10,
    MTEventKindInitHashCleared = 11,
    MTEventKindVerificationRequired = 12,
    MTEventKindUpdatesReset = 13,
    MTEventKindUpdate = 14,
    MTEventKindTimeDifferenceUpdated = 15,
    MTEventKindSaltsUpdated = 16,
    MTEventKindPong = 17,
    MTEventKindConnectionState = 18,
    MTEventKindAuthKeyRequired = 19,
    MTEventKindAuthKeyInvalid = 20,
    /* A key the session made and keeps, as a secret payload: integer1 its first salt, integer2 its expiry
       in server time (0 for a permanent key), value1 the time difference the handshake measured, code the
       dc its handshake carried (test offset included, negative for a media key), flags
       MTAuthKeyCreatedTemporary or MTAuthKeyCreatedPermanent. A key the session drops at once is not
       reported. */
    MTEventKindAuthKeyCreated = 21,
    MTEventKindAuthKeyCreationFailed = 22,
    MTEventKindTransportFlood = 23,
    MTEventKindNetworkUsage = 24,
    MTEventKindAddressResult = 25,
    MTEventKindClosed = 26,
    MTEventKindRetryDecisionRequired = 27,
    MTEventKindAuthKeyDestroyed = 28,
    MTEventKindConnectionDropped = 29,
    /* The engine bound the session's temporary key to the permanent one. */
    MTEventKindTemporaryKeyBound = 30,
    /* auth.bindTempAuthKey failed: code and text as the server sent them. */
    MTEventKindTemporaryKeyBindFailed = 31,
    /* PFS run by the engine: the server keeps refusing binds to the permanent key. */
    MTEventKindPermanentKeyInvalid = 32,
    /* PFS: the session talks under this bound temporary key from now on. integer1 key id, integer2
       expiry in server time, request_id the permanent key id it is bound to, code the datacenter id it
       was made for (negative for media addresses),
       flags 1 when the host gave the key (otherwise the session made it, and its AuthKeyCreated came
       first). */
    MTEventKindTemporaryKeyInUse = 33,
    /* PFS: the server no longer takes this temporary key (integer1 key id); a copy kept for other
       sessions should go. */
    MTEventKindTemporaryKeyDropped = 34,
    /* Engine-wide, for session 0: what was learned about named networks changed (payload); store it and
       give it back with mt_engine_set_route_memory on the next run. */
    MTEventKindRouteMemoryChanged = 35,
} MTEventKind;

enum {
    MTAuthKeyCreatedTemporary = 1 << 0,
    MTAuthKeyCreatedPermanent = 1 << 1,
};

enum {
    MTConnectionStateNetworkAvailable = 1 << 0,
    MTConnectionStateConnected = 1 << 1,
    MTConnectionStateUpdatingConnectionContext = 1 << 2,
    MTConnectionStatePerformingServiceTasks = 1 << 3,
    MTConnectionStateProxyHasConnectionIssues = 1 << 4,
    /* With UpdatingConnectionContext: the link answers and the session waits for its temporary key to
       be bound, which says nothing against the route. */
    MTConnectionStateAwaitingKeyBinding = 1 << 5,
};

enum {
    MTNetworkUsageCellular = 1 << 0,
};

enum {
    MTVerificationKindApns = 1,
    MTVerificationKindRecaptcha = 2,
};

typedef struct {
    MTEventKind kind;
    MTRequestId request_id;
    int32_t code;
    uint32_t flags;
    MTString text;
    MTString text2;
    MTBuffer *payload;
    double value1;
    double value2;
    int64_t integer1;
    int64_t integer2;
    const MTSaltEntry *salts;
    size_t salt_count;
} MTEvent;

typedef void (*MTEventCallback)(void *context, MTSessionHandle session, const MTEvent *event);
typedef void (*MTLogCallback)(void *context, int32_t level, MTString message);

MTEngine *mt_engine_create(uint32_t worker_threads, void *context, MTEventCallback on_event, MTLogCallback on_log);
void mt_engine_destroy(MTEngine *engine);
MTRequestId mt_engine_next_request_id(MTEngine *engine);
void mt_engine_set_network_available(MTEngine *engine, uint8_t available);
void mt_engine_reset_connections(MTEngine *engine);
/* The network the device is on now: an opaque key (a salted hash of what identifies it), empty when
   unknown. A network known to block TCP gets HTTP early from the first connection. */
void mt_engine_set_network(MTEngine *engine, MTBytes key);
void mt_engine_set_route_memory(MTEngine *engine, MTBytes memory);

/* Host streams: byte streams the host opens for the engine, as TLS to Telegram Web's fronts with the
   platform's own TLS. Strings in the target live for the duration of the call. */
typedef struct {
    MTString host;
    uint16_t port;
    /* 1: TLS with server_name, offering alpn (comma-separated), without checking the certificate:
       TLS only makes the connection look like a browser's, MTProto protects what it carries. */
    uint8_t tls;
    MTString server_name;
    MTString alpn;
    /* 1: the host's WEB proxy carrier rather than a network connection. host and port are the
       datacenter's, which the relay ignores (it reads the datacenter from the obfuscated stream). */
    uint8_t carrier;
} MTStreamTarget;

/* Callbacks get the context given to mt_engine_create and may call the mt_stream_* functions. The host
   reports each stream's end with mt_stream_closed unless the engine closed it first (close). Each
   stream stays with the host that opened it. Once mt_engine_destroy is called the host must not call
   mt_stream_* any more; the close callbacks it gets during mt_engine_destroy only let it free the
   streams. */
typedef struct {
    void (*open)(void *context, uint64_t stream, const MTStreamTarget *target);
    /* Bytes to send in order; confirm them with mt_stream_sent once the platform took them. */
    void (*write)(void *context, uint64_t stream, MTBytes bytes);
    /* The engine is done with the stream; it is not reported on any more. Also during mt_engine_destroy. */
    void (*close)(void *context, uint64_t stream);
    /* The host may receive again on a stream it stopped (mt_stream_received returned 0). */
    void (*resume)(void *context, uint64_t stream);
} MTStreamHost;

/* NULL removes the host; routes that need one are then not tried. */
void mt_engine_set_stream_host(MTEngine *engine, const MTStreamHost *host);
/* The stream is open (TLS done): bytes may go both ways. */
void mt_stream_opened(MTEngine *engine, uint64_t stream);
/* 1 while the host may go on receiving; 0: stop until the resume callback. */
uint8_t mt_stream_received(MTEngine *engine, uint64_t stream, MTBytes bytes);
void mt_stream_sent(MTEngine *engine, uint64_t stream, size_t count);
/* The stream ended, cleanly when error is empty; before mt_stream_opened, it could not be opened. */
void mt_stream_closed(MTEngine *engine, uint64_t stream, MTString error);

MTSessionHandle mt_session_create(MTEngine *engine, const MTSessionSetup *setup);
void mt_session_destroy(MTEngine *engine, MTSessionHandle session);
void mt_session_send(MTEngine *engine, MTSessionHandle session, const MTRequest *request);
void mt_session_cancel(MTEngine *engine, MTSessionHandle session, MTRequestId request);
void mt_session_set_paused(MTEngine *engine, MTSessionHandle session, uint8_t paused);
void mt_session_set_online(MTEngine *engine, MTSessionHandle session, uint8_t online);
void mt_session_set_auth_key(MTEngine *engine, MTSessionHandle session, MTBytes key, const MTSaltEntry *salts, size_t salt_count, uint8_t has_init_hash, MTString init_hash);
void mt_session_set_addresses(MTEngine *engine, MTSessionHandle session, const MTAddress *addresses, size_t count);
void mt_session_set_obfuscation_dc_id(MTEngine *engine, MTSessionHandle session, int16_t dc_id);
void mt_session_set_proxy(MTEngine *engine, MTSessionHandle session, const MTProxy *proxy);

enum {
    MTTransportTcp = 0,
    MTTransportHttp = 1,
    MTTransportAuto = 2,
};

/* Which transports the session may use; HTTP goes to `http_port`, or to each address's own port
   when it is 0. Auto stays on TCP while TCP answers and moves to HTTP while it does not. */
void mt_session_set_transport(MTEngine *engine, MTSessionHandle session, uint8_t transport, uint16_t http_port);

/* Telegram Web's endpoints on one front, through host streams; used only while a stream host is set
   and no proxy is. When TCP gets no answer, Auto tries the WebSocket endpoint (ws_path, carrying the
   stream transport) beside plain HTTP, and the HTTPS endpoint (path) once the WebSocket one fails or
   keeps silent. address, when not empty, is connected to instead of looking host up. */
typedef struct {
    MTString host;
    uint16_t port;
    MTString path;
    MTString address;
    MTString ws_path;
} MTWebEndpoint;

/* NULL: none. */
void mt_session_set_web_endpoint(MTEngine *engine, MTSessionHandle session, const MTWebEndpoint *endpoint);
/* Telegram Web's own endpoints for the session's datacenter: {pluto,venus,aurora,vesta,flora}.web.telegram.org
   (the -1 fronts for sessions other than the main one), /apiws and /apiw1, or /apiws_test and
   /apiw_test1 for the test servers. */
void mt_session_use_telegram_web(MTEngine *engine, MTSessionHandle session, uint8_t test);

/* The engine makes temporary keys that live `lifetime` seconds with these RSA keys and binds them to
   the session's key, which becomes the permanent key, before anything else goes out. 0 when none of
   the keys parses: PFS stays off. Without make_permanent_key, a session that has no key asks for the
   permanent key (AuthKeyRequired) instead of making one. temporary_key, when not NULL, is a key
   already bound to the permanent key: the session starts under it without a handshake. */
uint8_t mt_session_enable_pfs(MTEngine *engine, MTSessionHandle session, int32_t lifetime,
                           const MTString *public_keys_pem, size_t public_key_count,
                           uint8_t make_permanent_key, const MTTemporaryKey *temporary_key);
/* A temporary key bound to the session's permanent key elsewhere: the session takes it at once when
   it has no key in use, otherwise the next time it needs a new one. */
void mt_session_offer_temporary_key(MTEngine *engine, MTSessionHandle session, const MTTemporaryKey *key);
/* PFS with the permanent key from the host: whether this session may make one itself while it has none. */
void mt_session_allow_permanent_key(MTEngine *engine, MTSessionHandle session, uint8_t allowed);
void mt_session_update_environment(MTEngine *engine, MTSessionHandle session, const MTEnvironment *environment, const MTRequest *noop);
void mt_session_set_auth_token_ready(MTEngine *engine, MTSessionHandle session, uint8_t ready);
void mt_session_resolve_apns(MTEngine *engine, MTSessionHandle session, MTRequestId request, MTString nonce, MTString secret);
void mt_session_resolve_recaptcha(MTEngine *engine, MTSessionHandle session, MTRequestId request, MTString token);
void mt_session_fail_request(MTEngine *engine, MTSessionHandle session, MTRequestId request, int32_t code, MTString message);
void mt_session_decide_retry(MTEngine *engine, MTSessionHandle session, MTRequestId request, uint8_t retry);
void mt_session_invalidate_initialization(MTEngine *engine, MTSessionHandle session);
void mt_session_set_time_difference(MTEngine *engine, MTSessionHandle session, double difference);
void mt_session_destroy_auth_key(MTEngine *engine, MTSessionHandle session);

const uint8_t *mt_buffer_data(const MTBuffer *buffer);
size_t mt_buffer_length(const MTBuffer *buffer);
void mt_buffer_free(MTBuffer *buffer);

uint32_t mt_engine_abi_version(void);

#ifdef __cplusplus
}
#endif

#endif
