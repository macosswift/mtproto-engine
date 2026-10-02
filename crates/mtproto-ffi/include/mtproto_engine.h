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

enum {
    MTProxyKindNone = 0,
    MTProxyKindSocks5 = 1,
    MTProxyKindMTProxy = 2,
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
    MTEventKindAuthKeyCreated = 21,
    MTEventKindAuthKeyCreationFailed = 22,
    MTEventKindTransportFlood = 23,
    MTEventKindNetworkUsage = 24,
    MTEventKindAddressResult = 25,
    MTEventKindClosed = 26,
    MTEventKindRetryDecisionRequired = 27,
    MTEventKindAuthKeyDestroyed = 28,
} MTEventKind;

enum {
    MTConnectionStateNetworkAvailable = 1 << 0,
    MTConnectionStateConnected = 1 << 1,
    MTConnectionStateUpdatingConnectionContext = 1 << 2,
    MTConnectionStatePerformingServiceTasks = 1 << 3,
    MTConnectionStateProxyHasConnectionIssues = 1 << 4,
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
