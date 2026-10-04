// tdlib-bench: tdlib's own network layer behind mtproto-bench's raw client protocol.
//
// The sessions are tdlib's `Session` (and with it `SessionConnection`, `RawConnection`, the
// obfuscated transport and fake-TLS init). The connector that hands them connections follows
// `ConnectionCreator::client_loop`: the same flood controls, offline backoff, check mode (a new
// connection to an address not proven lately is pinged with req_pq before use, up to three at a
// time, except through a proxy) and the 10 s expiry of unused connections. It serves one address,
// as the bench does; a secret makes it an MTProto proxy, as in the Rust client.
// Workloads and the JSON report are those of mtproto-bench's raw client (`client.rs`).

#include "td/telegram/Global.h"
#include "td/telegram/net/NetType.h"
#include "td/telegram/StateManager.h"
#include "td/telegram/net/AuthDataShared.h"
#include "td/telegram/net/DcId.h"
#include "td/telegram/net/MtprotoHeader.h"
#include "td/telegram/net/NetQuery.h"
#include "td/telegram/net/NetQueryCreator.h"
#include "td/telegram/net/NetQueryStats.h"
#include "td/telegram/net/Session.h"
#include "td/telegram/telegram_api.h"

#include "td/mtproto/AuthKey.h"
#include "td/mtproto/Ping.h"
#include "td/mtproto/ProxySecret.h"
#include "td/mtproto/RawConnection.h"
#include "td/mtproto/TlsInit.h"
#include "td/mtproto/TransportType.h"

#include "td/actor/actor.h"
#include "td/actor/ConcurrentScheduler.h"

#include "td/tl/TlObject.h"

#include "td/utils/algorithm.h"
#include "td/utils/BufferedFd.h"
#include "td/utils/crypto.h"
#include "td/utils/FloodControlStrict.h"
#include "td/utils/logging.h"
#include "td/utils/misc.h"
#include "td/utils/port/IPAddress.h"
#include "td/utils/port/SocketFd.h"
#include "td/utils/Random.h"
#include "td/utils/Slice.h"
#include "td/utils/Time.h"
#include "td/utils/tl_helpers.h"
#include "td/utils/tl_parsers.h"
#include "td/utils/tl_storers.h"
#include "td/utils/TlStorerToString.h"
#include "td/utils/UInt.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace {

constexpr td::int32 CALL = 0x7e570001;
constexpr td::int32 CALL_RESULT = 0x7e570002;
constexpr td::uint32 TAG_SIZED = 1012;
constexpr td::uint32 TAG_UPLOAD = 1022;

struct Args {
  std::string engine_label = "tdlib";
  std::string address;
  int dc = 2;
  std::string key_hex;
  td::int64 salt = 0;
  std::string secret;
  std::string workload = "small";
  size_t requests = 1000;
  size_t concurrency = 8;
  td::uint32 part_size = 128 * 1024;
  td::uint64 total_bytes = 0;
  size_t sessions = 2;
  size_t session_concurrency = 4;
  double rate = 10.0;
  double duration = 10.0;
  double deadline = 60.0;
  bool online = false;
  std::string transport = "tcp";
};

Args parse_args(int argc, char **argv) {
  Args args;
  for (int i = 1; i + 1 < argc; i += 2) {
    std::string flag = argv[i];
    std::string value = argv[i + 1];
    if (flag == "--engine-label") {
      args.engine_label = value;
    } else if (flag == "--address") {
      args.address = value;
    } else if (flag == "--dc") {
      args.dc = std::atoi(value.c_str());
    } else if (flag == "--key-hex") {
      args.key_hex = value;
    } else if (flag == "--salt") {
      args.salt = std::strtoll(value.c_str(), nullptr, 10);
    } else if (flag == "--secret") {
      args.secret = value;
    } else if (flag == "--workload") {
      args.workload = value;
    } else if (flag == "--requests") {
      args.requests = std::strtoull(value.c_str(), nullptr, 10);
    } else if (flag == "--concurrency") {
      args.concurrency = std::strtoull(value.c_str(), nullptr, 10);
    } else if (flag == "--part-size") {
      args.part_size = static_cast<td::uint32>(std::strtoul(value.c_str(), nullptr, 10));
    } else if (flag == "--total-bytes") {
      args.total_bytes = std::strtoull(value.c_str(), nullptr, 10);
    } else if (flag == "--sessions") {
      args.sessions = std::strtoull(value.c_str(), nullptr, 10);
    } else if (flag == "--session-concurrency") {
      args.session_concurrency = std::strtoull(value.c_str(), nullptr, 10);
    } else if (flag == "--rate") {
      args.rate = std::atof(value.c_str());
    } else if (flag == "--duration") {
      args.duration = std::atof(value.c_str());
    } else if (flag == "--deadline") {
      args.deadline = std::atof(value.c_str());
    } else if (flag == "--online") {
      args.online = value == "1" || value == "true";
    } else if (flag == "--transport") {
      args.transport = value;
    } else if (flag == "--mode" && value != "fake") {
      std::fprintf(stderr, "tdlib-bench: only --mode fake is supported\n");
      std::exit(2);
    }
  }
  static const char *const workloads[] = {"latency", "small", "steady", "media", "mixed", "upload", "mixed-upload"};
  if (std::find(std::begin(workloads), std::end(workloads), args.workload) == std::end(workloads)) {
    std::fprintf(stderr, "tdlib-bench: unknown workload %s\n", args.workload.c_str());
    std::exit(2);
  }
  if (const char *online = std::getenv("TDLIB_BENCH_ONLINE")) {
    args.online = std::string(online) == "1";
  }
  return args;
}

std::string unhex(const std::string &hex) {
  std::string out;
  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    out.push_back(static_cast<char>(std::strtoul(hex.substr(i, 2).c_str(), nullptr, 16)));
  }
  return out;
}

class BenchCall final : public td::telegram_api::Function {
 public:
  BenchCall(td::uint32 tag, std::string payload) : tag_(tag), payload_(std::move(payload)) {
  }
  std::int32_t get_id() const final {
    return CALL;
  }
  void store(td::TlStorerCalcLength &s) const final {
    s.store_binary(CALL);
    s.store_binary(static_cast<td::int32>(tag_));
    s.store_string(payload_);
  }
  void store(td::TlStorerUnsafe &s) const final {
    s.store_binary(CALL);
    s.store_binary(static_cast<td::int32>(tag_));
    s.store_string(payload_);
  }
  void store(td::TlStorerToString &s, const char *field_name) const final {
    s.store_class_begin(field_name, "bench.call");
    s.store_field("tag", static_cast<td::int32>(tag_));
    s.store_class_end();
  }

 private:
  td::uint32 tag_;
  std::string payload_;
};

// The tag and payload of a bench.callResult, or nothing.
bool parse_result(td::Slice body, td::uint32 *tag, std::string *payload) {
  td::TlParser parser(body);
  if (parser.fetch_int() != CALL_RESULT) {
    return false;
  }
  *tag = static_cast<td::uint32>(parser.fetch_int());
  *payload = parser.fetch_string<std::string>();
  return parser.get_error() == nullptr;
}

class BenchAuthData final : public td::AuthDataShared {
 public:
  BenchAuthData(td::DcId dc_id, td::mtproto::AuthKey auth_key, std::vector<td::mtproto::ServerSalt> salts)
      : dc_id_(dc_id), auth_key_(std::move(auth_key)), salts_(std::move(salts)) {
  }
  td::DcId dc_id() const final {
    return dc_id_;
  }
  const std::shared_ptr<td::mtproto::PublicRsaKeyInterface> &public_rsa_key() final {
    return public_rsa_key_;
  }
  td::mtproto::AuthKey get_auth_key() final {
    std::lock_guard<std::mutex> guard(mutex_);
    return auth_key_;
  }
  void set_auth_key(const td::mtproto::AuthKey &auth_key) final {
    std::lock_guard<std::mutex> guard(mutex_);
    auth_key_ = auth_key;
  }
  void update_server_time_difference(double diff, bool force) final {
    std::lock_guard<std::mutex> guard(mutex_);
    if (force || !has_time_difference_ || diff > time_difference_) {
      time_difference_ = diff;
      has_time_difference_ = true;
    }
  }
  double get_server_time_difference() final {
    std::lock_guard<std::mutex> guard(mutex_);
    return time_difference_;
  }
  void add_auth_key_listener(td::unique_ptr<Listener> listener) final {
    if (listener->notify()) {
      std::lock_guard<std::mutex> guard(mutex_);
      listeners_.push_back(std::move(listener));
    }
  }
  void set_future_salts(const std::vector<td::mtproto::ServerSalt> &future_salts) final {
    std::lock_guard<std::mutex> guard(mutex_);
    salts_ = future_salts;
  }
  std::vector<td::mtproto::ServerSalt> get_future_salts() final {
    std::lock_guard<std::mutex> guard(mutex_);
    return salts_;
  }

 private:
  td::DcId dc_id_;
  td::mtproto::AuthKey auth_key_;
  std::vector<td::mtproto::ServerSalt> salts_;
  std::shared_ptr<td::mtproto::PublicRsaKeyInterface> public_rsa_key_;
  std::mutex mutex_;
  double time_difference_ = td::Clocks::system() - td::Time::now();
  bool has_time_difference_ = false;
  std::vector<td::unique_ptr<Listener>> listeners_;
};

// The health of the one address, as DcOptionsSet::Stat keeps it.
struct AddressStat {
  double ok_at = -1000;
  double error_at = -1001;
  double check_at = -1002;
  bool is_ok() const {
    return ok_at > error_at && ok_at > check_at;
  }
};

class Connector;

class ConnectionStats final : public td::mtproto::RawConnection::StatsCallback {
 public:
  ConnectionStats(td::ActorId<Connector> connector, AddressStat *stat) : connector_(connector), stat_(stat) {
  }
  void on_read(td::uint64 bytes) final {
  }
  void on_write(td::uint64 bytes) final {
  }
  void on_pong() final;
  void on_error() final;
  void on_mtproto_error() final;

 private:
  td::ActorId<Connector> connector_;
  AddressStat *stat_;
};

// ConnectionCreator::client_loop for one client (one Session), one address.
class Connector final : public td::Actor {
 public:
  Connector(td::IPAddress address, td::mtproto::TransportType transport_type, AddressStat *stat, bool online)
      : address_(address)
      , transport_type_(std::move(transport_type))
      , stat_(stat)
      , online_(online)
      , proxied_(!transport_type_.secret.get_raw_secret().empty())
      , http_(transport_type_.type == td::mtproto::TransportType::Http) {
    sanity_flood_control_.add_limit(5, 10);
    flood_control_.add_limit(1, 1);
    flood_control_.add_limit(4, 2);
    flood_control_.add_limit(8, 3);
    flood_control_online_.add_limit(1, 4);
    flood_control_online_.add_limit(5, 5);
    mtproto_error_flood_control_.add_limit(1, 1);
    mtproto_error_flood_control_.add_limit(4, 2);
    mtproto_error_flood_control_.add_limit(8, 3);
  }

  void request(td::Promise<td::unique_ptr<td::mtproto::RawConnection>> promise) {
    queries_.push_back(std::move(promise));
    loop();
  }

  void on_network(bool network_flag, td::uint32 generation) {
    network_flag_ = network_flag;
    network_generation_ = generation;
    if (network_flag_) {
      backoff_delay_ = 1;
      backoff_wakeup_at_ = 0;
      sanity_flood_control_.clear_events();
      flood_control_.clear_events();
      flood_control_online_.clear_events();
      loop();
    }
  }

  void on_online(bool online) {
    online_ = online;
    loop();
  }

  void on_pong() {
    stat_->ok_at = td::Time::now();
  }
  void on_error() {
    stat_->error_at = td::Time::now();
  }
  void on_mtproto_error() {
    mtproto_error_flood_control_.add_event(td::Time::now());
  }

  void on_connection(td::Result<td::unique_ptr<td::mtproto::RawConnection>> result, bool checked) {
    CHECK(pending_ > 0);
    pending_--;
    if (checked) {
      CHECK(checking_ > 0);
      checking_--;
    }
    if (result.is_ok()) {
      backoff_delay_ = 1;
      backoff_wakeup_at_ = 0;
      ready_.emplace_back(result.move_as_ok(), td::Time::now());
    }
    loop();
  }

 private:
  td::IPAddress address_;
  td::mtproto::TransportType transport_type_;
  AddressStat *stat_;
  bool online_;
  bool proxied_;
  // DcOptionsSet::find_connection: an HTTP option is always checked before use.
  bool http_;
  td::FloodControlStrict sanity_flood_control_;
  td::FloodControlStrict flood_control_;
  td::FloodControlStrict flood_control_online_;
  td::FloodControlStrict mtproto_error_flood_control_;
  td::int32 backoff_wakeup_at_ = 0;
  td::int32 backoff_delay_ = 1;
  size_t pending_ = 0;
  size_t checking_ = 0;
  std::vector<std::pair<td::unique_ptr<td::mtproto::RawConnection>, double>> ready_;
  std::vector<td::Promise<td::unique_ptr<td::mtproto::RawConnection>>> queries_;
  std::map<td::uint64, td::ActorOwn<>> children_;
  td::uint64 next_token_ = 1;

  bool network_flag_ = false;
  td::uint32 network_generation_ = 0;

  static constexpr double READY_CONNECTIONS_TIMEOUT = 10;
  static constexpr td::int32 MAX_BACKOFF = 16;

  void start_up() final {
    class StateCallback final : public td::StateManager::Callback {
     public:
      explicit StateCallback(td::ActorId<Connector> connector) : connector_(connector) {
      }
      bool on_network(td::NetType network_type, td::uint32 generation) final {
        td::send_closure(connector_, &Connector::on_network, network_type != td::NetType::None, generation);
        return connector_.is_alive();
      }
      bool on_online(bool is_online) final {
        td::send_closure(connector_, &Connector::on_online, is_online);
        return connector_.is_alive();
      }

     private:
      td::ActorId<Connector> connector_;
    };
    td::send_closure(td::G()->state_manager(), &td::StateManager::add_callback,
                     td::make_unique<StateCallback>(actor_id(this)));
  }

  void timeout_expired() final {
    loop();
  }

  void hangup_shared() final {
    children_.erase(get_link_token());
  }

  void loop() final {
    if (!network_flag_) {
      return;
    }
    auto expires_at = td::Time::now() - READY_CONNECTIONS_TIMEOUT;
    td::remove_if(ready_, [&](auto &v) { return v.second < expires_at; });
    auto it = queries_.begin();
    while (it != queries_.end() && !ready_.empty()) {
      if (!it->is_canceled()) {
        it->set_value(std::move(ready_.back().first));
        ready_.pop_back();
      }
      ++it;
    }
    queries_.erase(queries_.begin(), it);

    bool check_mode = checking_ != 0 && !proxied_;
    while (true) {
      if (queries_.empty()) {
        if (!ready_.empty()) {
          set_timeout_in(READY_CONNECTIONS_TIMEOUT);
        }
        return;
      }
      if (check_mode) {
        if (checking_ >= 3) {
          return;
        }
      } else if (pending_ >= queries_.size()) {
        return;
      }
      auto &flood_control = online_ ? flood_control_online_ : flood_control_;
      auto wakeup_at = std::max(flood_control.get_wakeup_at(), mtproto_error_flood_control_.get_wakeup_at());
      wakeup_at = std::max(sanity_flood_control_.get_wakeup_at(), wakeup_at);
      if (!online_) {
        wakeup_at = std::max(wakeup_at, static_cast<double>(backoff_wakeup_at_));
      }
      if (wakeup_at > td::Time::now()) {
        set_timeout_at(wakeup_at);
        return;
      }
      sanity_flood_control_.add_event(td::Time::now());
      if (!online_) {
        backoff_wakeup_at_ = static_cast<td::int32>(td::Time::now()) + backoff_delay_;
        backoff_delay_ = std::min(MAX_BACKOFF, backoff_delay_ * 2);
      }
      bool should_check = !stat_->is_ok() || http_ || stat_->error_at > td::Time::now() - 10;
      if (!proxied_) {
        check_mode |= should_check;
      }

      auto r_socket_fd = td::SocketFd::open(address_);
      if (r_socket_fd.is_error()) {
        stat_->error_at = td::Time::now();
        set_timeout_in(0.1);
        return;
      }
      flood_control.add_event(td::Time::now());
      pending_++;
      if (check_mode) {
        stat_->check_at = td::Time::now();
        checking_++;
      }
      connect(r_socket_fd.move_as_ok(), check_mode);
    }
  }

  void connect(td::SocketFd socket_fd, bool check_mode) {
    auto token = next_token_++;
    auto promise = td::PromiseCreator::lambda(
        [actor_id = actor_id(this), check_mode, token](td::Result<td::BufferedFd<td::SocketFd>> r_fd) mutable {
          td::send_closure(actor_id, &Connector::on_socket, std::move(r_fd), check_mode, token);
        });
    if (transport_type_.secret.emulate_tls()) {
      class Callback final : public td::TransparentProxy::Callback {
       public:
        Callback(td::Promise<td::BufferedFd<td::SocketFd>> promise, td::ActorId<Connector> connector)
            : promise_(std::move(promise)), connector_(connector) {
        }
        void set_result(td::Result<td::BufferedFd<td::SocketFd>> r_buffered_socket_fd) final {
          if (r_buffered_socket_fd.is_error() && was_connected_) {
            td::send_closure(connector_, &Connector::on_error);
          }
          promise_.set_result(std::move(r_buffered_socket_fd));
        }
        void on_connected() final {
          was_connected_ = true;
        }

       private:
        td::Promise<td::BufferedFd<td::SocketFd>> promise_;
        td::ActorId<Connector> connector_;
        bool was_connected_ = true;
      };
      children_[token] = td::create_actor<td::mtproto::TlsInit>(
          "TlsInit", std::move(socket_fd), transport_type_.secret.get_domain(),
          transport_type_.secret.get_proxy_secret().str(), td::make_unique<Callback>(std::move(promise), actor_id(this)),
          actor_shared(this, token), td::Clocks::system() - td::Time::now());
    } else {
      promise.set_value(td::BufferedFd<td::SocketFd>(std::move(socket_fd)));
    }
  }

  void on_socket(td::Result<td::BufferedFd<td::SocketFd>> r_fd, bool check_mode, td::uint64 token) {
    auto promise = td::PromiseCreator::lambda(
        [actor_id = actor_id(this), check_mode](td::Result<td::unique_ptr<td::mtproto::RawConnection>> result) mutable {
          td::send_closure(actor_id, &Connector::on_connection, std::move(result), check_mode);
        });
    if (r_fd.is_error()) {
      return promise.set_error(r_fd.move_as_error());
    }
    auto raw_connection = td::mtproto::RawConnection::create(
        address_, r_fd.move_as_ok(), transport_type_, td::make_unique<ConnectionStats>(actor_id(this), stat_));
    raw_connection->extra().extra = network_generation_;
    if (check_mode) {
      auto ping_token = next_token_++;
      children_[ping_token] = td::mtproto::create_ping_actor("Check", std::move(raw_connection), nullptr,
                                                             std::move(promise), actor_shared(this, ping_token));
    } else {
      promise.set_value(std::move(raw_connection));
    }
  }
};

void ConnectionStats::on_pong() {
  td::send_closure(connector_, &Connector::on_pong);
}
void ConnectionStats::on_error() {
  td::send_closure(connector_, &Connector::on_error);
}
void ConnectionStats::on_mtproto_error() {
  td::send_closure(connector_, &Connector::on_mtproto_error);
}

class Bench;

class SessionCallback final : public td::Session::Callback {
 public:
  SessionCallback(td::ActorId<Bench> bench, td::ActorId<Connector> connector, int index)
      : bench_(bench), connector_(connector), index_(index) {
  }
  void on_failed() final;
  void on_closed() final {
  }
  void request_raw_connection(td::unique_ptr<td::mtproto::AuthData> auth_data,
                              td::Promise<td::unique_ptr<td::mtproto::RawConnection>> promise) final {
    td::send_closure(connector_, &Connector::request, std::move(promise));
  }
  void on_tmp_auth_key_updated(td::mtproto::AuthKey auth_key) final {
  }
  void on_server_salt_updated(std::vector<td::mtproto::ServerSalt> server_salts) final {
  }
  void on_update(td::BufferSlice &&update, td::uint64 auth_key_id) final {
  }
  void on_result(td::NetQueryPtr query) final;

 private:
  td::ActorId<Bench> bench_;
  td::ActorId<Connector> connector_;
  int index_;
};

enum class Kind { Small, Sized, Upload };

std::string upload_payload(td::uint64 seed, td::uint32 size) {
  td::uint64 state = (seed * 0x9e3779b97f4a7c15ULL) | 1;
  std::string out(size, '\0');
  for (auto &byte : out) {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    byte = static_cast<char>(state);
  }
  return out;
}

struct Record {
  double sent;
  double done = -1;
  Kind kind;
  td::uint32 tag;
  int session;
};

class Bench final : public td::Actor {
 public:
  explicit Bench(Args args) : args_(std::move(args)) {
  }

  void on_result(td::NetQueryPtr query) {
    auto it = by_query_.find(query->id());
    if (it == by_query_.end()) {
      query->clear();
      return;
    }
    auto index = it->second;
    by_query_.erase(it);
    auto &record = records_[index];
    outstanding_[record.session]--;
    bool valid = false;
    if (query->is_ok()) {
      td::uint32 tag = 0;
      std::string payload;
      if (parse_result(query->ok().as_slice(), &tag, &payload)) {
        if (record.kind == Kind::Small) {
          valid = tag == record.tag;
        } else if (record.kind == Kind::Sized) {
          valid = tag == TAG_SIZED && payload.size() == static_cast<size_t>(args_.part_size);
        } else {
          td::uint32 received = 0;
          valid = tag == TAG_UPLOAD && payload.size() == 4 && (std::memcpy(&received, payload.data(), 4), true) &&
                  received == args_.part_size;
        }
      }
    }
    query->clear();
    if (valid) {
      completed_++;
      record.done = elapsed();
      if (record.kind != Kind::Small) {
        bytes_ += args_.part_size;
      }
    } else {
      failed_++;
    }
    loop();
  }

  void on_session_failed(int index) {
    LOG(WARNING) << "Session " << index << " failed; reopening";
    open_session(index);
  }

 private:
  Args args_;
  td::ActorOwn<td::StateManager> state_manager_;
  std::shared_ptr<td::AuthDataShared> auth_data_;
  AddressStat stat_;
  td::IPAddress address_;
  td::mtproto::TransportType transport_type_;
  std::vector<td::ActorOwn<Connector>> connectors_;
  std::vector<td::ActorOwn<td::Session>> sessions_;
  std::vector<size_t> outstanding_;
  std::vector<Record> records_;
  std::vector<size_t> probes_;
  std::map<td::uint64, size_t> by_query_;
  size_t completed_ = 0;
  size_t failed_ = 0;
  td::uint64 bytes_ = 0;
  double start_ = 0;
  size_t issued_ = 0;
  size_t parts_ = 0;
  double next_probe_ = 0;
  size_t probe_count_ = 0;
  double next_tick_ = 0;
  bool finished_ = false;

  double elapsed() const {
    return td::Time::now() - start_;
  }

  void start_up() final {
    set_context(std::make_shared<td::Global>());
    td::G()->set_net_query_stats(std::make_shared<td::NetQueryStats>());
    td::MtprotoHeader::Options options;
    options.api_id = 9;
    options.system_language_code = "en";
    options.device_model = "MTProto engine benchmark";
    options.system_version = "bench";
    options.application_version = "bench";
    options.language_pack = "";
    options.language_code = "en";
    td::G()->set_mtproto_header(td::make_unique<td::MtprotoHeader>(options));
    state_manager_ = td::create_actor<td::StateManager>("StateManager", actor_shared(this));
    td::G()->set_state_manager(state_manager_.get());
    td::send_closure(state_manager_, &td::StateManager::on_online, args_.online);

    auto colon = args_.address.rfind(':');
    address_.init_ipv4_port(args_.address.substr(0, colon), td::to_integer<int>(args_.address.substr(colon + 1)))
        .ensure();
    td::mtproto::ProxySecret secret;
    if (!args_.secret.empty()) {
      secret = td::mtproto::ProxySecret::from_link(args_.secret).move_as_ok();
    }
    if (args_.transport == "http") {
      transport_type_ = td::mtproto::TransportType{td::mtproto::TransportType::Http, 0, td::mtproto::ProxySecret()};
    } else {
      transport_type_ = td::mtproto::TransportType{td::mtproto::TransportType::ObfuscatedTcp,
                                                   static_cast<td::int16>(args_.dc), std::move(secret)};
    }

    auto key = unhex(args_.key_hex);
    unsigned char sha[20];
    td::sha1(key, sha);
    td::uint64 key_id;
    std::memcpy(&key_id, sha + 12, 8);
    auto now = td::Clocks::system();
    std::vector<td::mtproto::ServerSalt> salts{td::mtproto::ServerSalt{args_.salt, now - 86400, now + 86400}};
    auth_data_ = std::make_shared<BenchAuthData>(td::DcId::internal(args_.dc),
                                                 td::mtproto::AuthKey(key_id, std::move(key)), salts);

    bool media = args_.workload == "media" || args_.workload == "mixed" || args_.workload == "upload" ||
                 args_.workload == "mixed-upload";
    size_t count = 1 + (media ? args_.sessions : 0);
    connectors_.resize(count);
    sessions_.resize(count);
    outstanding_.assign(count, 0);
    for (size_t i = 0; i < count; i++) {
      connectors_[i] = td::create_actor<Connector>("Connector", address_, transport_type_, &stat_, args_.online);
      open_session(static_cast<int>(i));
    }
    parts_ = args_.part_size == 0 ? 0 : static_cast<size_t>((args_.total_bytes + args_.part_size - 1) / args_.part_size);
    start_ = td::Time::now();
    loop();
  }

  void open_session(int index) {
    bool is_main = index == 0;
    auto now = td::Clocks::system();
    std::vector<td::mtproto::ServerSalt> salts{td::mtproto::ServerSalt{args_.salt, now - 86400, now + 86400}};
    sessions_[index] = td::create_actor_on_scheduler<td::Session>(
        td::Slice(is_main ? "MainSession" : "MediaSession"),
        is_main ? td::Scheduler::instance()->sched_id() : td::G()->get_slow_net_scheduler_id(),
        td::make_unique<SessionCallback>(actor_id(this), connectors_[index].get(), index), auth_data_, args_.dc,
        args_.dc, is_main, is_main, false, false, false, false, td::mtproto::AuthKey(), salts);
  }

  void issue(int session, Kind kind, bool probe) {
    auto index = records_.size();
    Record record;
    record.sent = elapsed();
    record.kind = kind;
    record.tag = static_cast<td::uint32>(1 + (index % 900));
    record.session = session;
    std::string payload(8, '\0');
    td::uint64 value = index;
    if (kind == Kind::Sized) {
      record.tag = TAG_SIZED;
      payload.resize(4);
      td::uint32 size = args_.part_size;
      std::memcpy(&payload[0], &size, 4);
    } else if (kind == Kind::Upload) {
      record.tag = TAG_UPLOAD;
      payload = upload_payload(index, args_.part_size);
    } else {
      std::memcpy(&payload[0], &value, 8);
    }
    records_.push_back(record);
    if (probe) {
      probes_.push_back(index);
    }
    auto id = td::UniqueId::next();
    auto type = kind == Kind::Sized    ? td::NetQuery::Type::Download
                : kind == Kind::Upload ? td::NetQuery::Type::Upload
                                       : td::NetQuery::Type::Common;
    auto query = td::G()->net_query_creator().create(id, nullptr, BenchCall(record.tag, payload), {},
                                                     td::DcId::internal(args_.dc), type, td::NetQuery::AuthFlag::On);
    by_query_[id] = index;
    outstanding_[session]++;
    td::send_closure(sessions_[session], &td::Session::send, std::move(query));
  }

  void timeout_expired() final {
    loop();
  }

  void loop() final {
    if (finished_) {
      return;
    }
    auto now = elapsed();
    if (now >= args_.deadline) {
      return finish();
    }
    auto &workload = args_.workload;
    if (workload == "latency") {
      if (outstanding_[0] == 0) {
        if (issued_ >= args_.requests) {
          return finish();
        }
        issued_++;
        issue(0, Kind::Small, false);
      }
    } else if (workload == "small") {
      while (issued_ < args_.requests && outstanding_[0] < args_.concurrency) {
        issued_++;
        issue(0, Kind::Small, false);
      }
      if (issued_ >= args_.requests && outstanding_[0] == 0) {
        return finish();
      }
    } else if (workload == "media" || workload == "mixed" || workload == "upload" || workload == "mixed-upload") {
      auto part_kind = workload.find("upload") != std::string::npos ? Kind::Upload : Kind::Sized;
      for (size_t worker = 1; worker < sessions_.size(); worker++) {
        while (issued_ < parts_ && outstanding_[worker] < args_.session_concurrency) {
          issued_++;
          issue(static_cast<int>(worker), part_kind, false);
        }
      }
      bool media_done = issued_ >= parts_;
      for (size_t worker = 1; worker < sessions_.size(); worker++) {
        media_done &= outstanding_[worker] == 0;
      }
      bool mixed = workload.rfind("mixed", 0) == 0;
      if (mixed && !media_done && args_.rate > 0) {
        while (now >= next_probe_) {
          issue(0, Kind::Small, true);
          probe_count_++;
          next_probe_ += 1.0 / args_.rate;
        }
      }
      if (media_done && outstanding_[0] == 0) {
        return finish();
      }
      if (mixed && !media_done && args_.rate > 0) {
        set_timeout_in(std::max(0.001, next_probe_ - now));
        return;
      }
    } else if (workload == "steady") {
      auto interval = 1.0 / std::max(args_.rate, 0.1);
      while (now < args_.duration && now >= next_tick_) {
        issue(0, Kind::Small, false);
        next_tick_ += interval;
      }
      if (now >= args_.duration && outstanding_[0] == 0) {
        return finish();
      }
      if (now < args_.duration) {
        set_timeout_in(std::max(0.001, next_tick_ - now));
        return;
      }
    } else {
      LOG(FATAL) << "Unknown workload " << workload;
    }
    set_timeout_in(std::max(0.001, args_.deadline - now));
  }

  void finish() {
    finished_ = true;
    auto total = elapsed();
    std::vector<size_t> indices;
    if (args_.workload.rfind("mixed", 0) == 0) {
      indices = probes_;
    } else {
      for (size_t i = 0; i < records_.size(); i++) {
        indices.push_back(i);
      }
    }
    std::vector<double> samples;
    for (auto index : indices) {
      if (records_[index].done >= 0) {
        samples.push_back((records_[index].done - records_[index].sent) * 1000.0);
      }
    }
    std::sort(samples.begin(), samples.end());
    auto at = [&](double q) {
      return samples.empty() ? 0.0 : samples[static_cast<size_t>(std::llround((samples.size() - 1.0) * q))];
    };
    size_t pending = by_query_.size();
    std::string out = "{\"engine\":\"" + args_.engine_label + "\",\"workload\":\"" + args_.workload + "\"";
    out += ",\"completed\":" + std::to_string(completed_) + ",\"failed\":" + std::to_string(failed_ + pending);
    char buffer[256];
    std::snprintf(buffer, sizeof(buffer),
                  ",\"elapsed\":%.6f,\"latency_ms\":{\"p50\":%.6f,\"p95\":%.6f,\"p99\":%.6f,\"max\":%.6f}", total,
                  at(0.5), at(0.95), at(0.99), samples.empty() ? 0.0 : samples.back());
    out += buffer;
    std::snprintf(buffer, sizeof(buffer), ",\"bytes\":%llu,\"throughput_mbps\":%.6f",
                  static_cast<unsigned long long>(bytes_), total > 0 ? bytes_ / 1e6 / total : 0.0);
    out += buffer;
    out += ",\"requests\":[";
    for (size_t i = 0; i < records_.size(); i++) {
      if (i > 0) {
        out += ",";
      }
      if (records_[i].done >= 0) {
        std::snprintf(buffer, sizeof(buffer), "[%.6f,%.6f]", records_[i].sent, records_[i].done);
      } else {
        std::snprintf(buffer, sizeof(buffer), "[%.6f,null]", records_[i].sent);
      }
      out += buffer;
    }
    out += "]}";
    std::printf("%s\n", out.c_str());
    std::fflush(stdout);
    std::_Exit(0);
  }
};

void SessionCallback::on_failed() {
  td::send_closure(bench_, &Bench::on_session_failed, index_);
}

void SessionCallback::on_result(td::NetQueryPtr query) {
  td::send_closure(bench_, &Bench::on_result, std::move(query));
}

}  // namespace

int main(int argc, char **argv) {
  auto args = parse_args(argc, argv);
  td::init_openssl_threads();
  SET_VERBOSITY_LEVEL(std::getenv("TDLIB_BENCH_LOG") ? VERBOSITY_NAME(INFO) : VERBOSITY_NAME(FATAL));
  td::ConcurrentScheduler scheduler(4, 0);
  scheduler.create_actor_unsafe<Bench>(0, "Bench", std::move(args)).release();
  scheduler.start();
  while (scheduler.run_main(10)) {
  }
  scheduler.finish();
  return 0;
}
