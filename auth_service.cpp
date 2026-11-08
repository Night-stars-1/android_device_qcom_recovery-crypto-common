// SPDX-License-Identifier: Apache-2.0
// Recovery-only protocol bridge. No key enrollment, deletion or software auth.
#include <aidl/android/hardware/gatekeeper/BnGatekeeper.h>
#include <aidl/android/hardware/security/sharedsecret/BnSharedSecret.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <android/hardware/gatekeeper/1.0/IGatekeeper.h>
#include <android/hardware/keymaster/4.1/IKeymasterDevice.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <algorithm>
#include <chrono>
#include <climits>
#include <cstdint>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

namespace keymaster::V4_1 {
android::hardware::keymaster::V4_1::IKeymasterDevice* CreateKeymasterDevice();
}
namespace gk = aidl::android::hardware::gatekeeper;
namespace km = aidl::android::hardware::security::keymint;
namespace ss = aidl::android::hardware::security::sharedsecret;
namespace oldgk = android::hardware::gatekeeper::V1_0;
namespace oldkm = android::hardware::keymaster::V4_0;
using ndk::ScopedAStatus;

static ScopedAStatus Unavailable() {
  return ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
}
static uint64_t Little64(const uint8_t* p) {
  uint64_t n = 0;
  for (int i = 7; i >= 0; --i) n = (n << 8) | p[i];
  return n;
}
static uint64_t Big64(const uint8_t* p) {
  uint64_t n = 0;
  for (int i = 0; i < 8; ++i) n = (n << 8) | p[i];
  return n;
}

class Gatekeeper final : public gk::BnGatekeeper {
 public:
  explicit Gatekeeper(android::sp<oldgk::IGatekeeper> impl) : impl_(std::move(impl)) {}
  ScopedAStatus deleteAllUsers() override {
    return Deny();
  }
  ScopedAStatus deleteUser(int32_t) override {
    return Deny();
  }
  ScopedAStatus enroll(int32_t, const std::vector<uint8_t>&, const std::vector<uint8_t>&,
                       const std::vector<uint8_t>&, gk::GatekeeperEnrollResponse*) override {
    return Deny();
  }
  ScopedAStatus verify(int32_t uid, int64_t challenge, const std::vector<uint8_t>& handle,
                       const std::vector<uint8_t>& password,
                       gk::GatekeeperVerifyResponse* out) override {
    if (uid < 0 || handle.empty() || handle.size() > 4096 || password.size() > 4096)
      return ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
    std::lock_guard<std::mutex> lock(mutex_);
    android::hardware::hidl_vec<uint8_t> h, p;
    h.setToExternal(const_cast<uint8_t*>(handle.data()), handle.size());
    p.setToExternal(const_cast<uint8_t*>(password.data()), password.size());
    bool ok = false;
    auto status = impl_->verify(uid, challenge, h, p, [&](const oldgk::GatekeeperResponse& r) {
      out->statusCode = gk::IGatekeeper::ERROR_GENERAL_FAILURE;
      switch (r.code) {
        case oldgk::GatekeeperStatusCode::ERROR_RETRY_TIMEOUT:
          if (!r.timeout) return;
          out->statusCode = gk::IGatekeeper::ERROR_RETRY_TIMEOUT;
          out->timeoutMs = std::min<uint64_t>(r.timeout, INT32_MAX);
          ok = true;
          return;
        case oldgk::GatekeeperStatusCode::ERROR_GENERAL_FAILURE:
          ok = true;
          return;
        case oldgk::GatekeeperStatusCode::ERROR_NOT_IMPLEMENTED:
          out->statusCode = gk::IGatekeeper::ERROR_NOT_IMPLEMENTED;
          ok = true;
          return;
        case oldgk::GatekeeperStatusCode::STATUS_OK:
        case oldgk::GatekeeperStatusCode::STATUS_REENROLL:
          break;
        default:
          return;
      }
      // Preserve the authentic HAT; never manufacture a MAC or change its
      // SID.
      if (r.data.size() != 69 || r.data[0] != 0) return;
      const uint8_t* token = r.data.data();
      auto& t = out->hardwareAuthToken;
      t.challenge = Little64(token + 1);
      t.userId = Little64(token + 9);
      t.authenticatorId = Little64(token + 17);
      uint32_t type = (uint32_t(token[25]) << 24) | (uint32_t(token[26]) << 16) |
                      (uint32_t(token[27]) << 8) | token[28];
      t.authenticatorType = static_cast<km::HardwareAuthenticatorType>(type);
      t.timestamp.milliSeconds = Big64(token + 29);
      t.mac.assign(token + 37, token + 69);
      out->statusCode = r.code == oldgk::GatekeeperStatusCode::STATUS_REENROLL
                            ? gk::IGatekeeper::STATUS_REENROLL
                            : gk::IGatekeeper::STATUS_OK;
      ok = true;
    });
    return status.isOk() && ok ? ScopedAStatus::ok() : Unavailable();
  }

 private:
  static ScopedAStatus Deny() {
    return ScopedAStatus::fromServiceSpecificError(gk::IGatekeeper::ERROR_NOT_IMPLEMENTED);
  }
  android::sp<oldgk::IGatekeeper> impl_;
  std::mutex mutex_;
};

class SharedSecret final : public ss::BnSharedSecret {
 public:
  explicit SharedSecret(android::sp<oldkm::IKeymasterDevice> impl) : impl_(std::move(impl)) {}
  ScopedAStatus getSharedSecretParameters(ss::SharedSecretParameters* out) override {
    std::lock_guard<std::mutex> lock(mutex_);
    bool ok = false;
    auto status = impl_->getHmacSharingParameters(
        [&](oldkm::ErrorCode error, const oldkm::HmacSharingParameters& p) {
          if (error != oldkm::ErrorCode::OK || (p.seed.size() != 0 && p.seed.size() != 32)) return;
          out->seed.assign(p.seed.begin(), p.seed.end());
          out->nonce.assign(p.nonce.data(), p.nonce.data() + p.nonce.size());
          ok = out->nonce.size() == 32;
        });
    return status.isOk() && ok ? ScopedAStatus::ok() : Unavailable();
  }
  ScopedAStatus computeSharedSecret(const std::vector<ss::SharedSecretParameters>& params,
                                    std::vector<uint8_t>* out) override {
    if (params.empty() || params.size() > 4)
      return ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
    android::hardware::hidl_vec<oldkm::HmacSharingParameters> converted;
    converted.resize(params.size());
    for (size_t i = 0; i < params.size(); ++i) {
      if (params[i].nonce.size() != 32 || (!params[i].seed.empty() && params[i].seed.size() != 32))
        return ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
      if (i && (params[i].seed < params[i - 1].seed ||
                (params[i].seed == params[i - 1].seed && params[i].nonce < params[i - 1].nonce)))
        return ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
      converted[i].seed.resize(params[i].seed.size());
      std::copy(params[i].seed.begin(), params[i].seed.end(), converted[i].seed.begin());
      std::copy(params[i].nonce.begin(), params[i].nonce.end(), converted[i].nonce.data());
    }
    std::lock_guard<std::mutex> lock(mutex_);
    bool ok = false;
    auto status = impl_->computeSharedHmac(
        converted, [&](oldkm::ErrorCode error, const android::hardware::hidl_vec<uint8_t>& check) {
          if (error != oldkm::ErrorCode::OK || check.size() != 32) return;
          out->assign(check.begin(), check.end());
          ok = true;
        });
    return status.isOk() && ok ? ScopedAStatus::ok() : Unavailable();
  }

 private:
  android::sp<oldkm::IKeymasterDevice> impl_;
  std::mutex mutex_;
};

int main(int argc, char** argv) {
  (void)argc;
  android::base::InitLogging(argv);
  rlimit no_core{ 0, 0 };
  if (setrlimit(RLIMIT_CORE, &no_core) != 0 || prctl(PR_SET_DUMPABLE, 0) != 0) return 1;
  bool listeners = false;
  for (int i = 0; i < 100; ++i) {
    auto ready = android::base::GetProperty("vendor.sys.listeners.registered", "");
    if (ready == "1" || ready == "true") {
      listeners = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  if (!listeners) {
    LOG(ERROR) << "Recovery auth: QSEE listeners did not become ready";
    return 1;
  }
  auto gatekeeper = oldgk::IGatekeeper::tryGetService("default");
  // Pinned QTI factory returns a raw RefBase pointer, not an sp<> ABI.
  auto* raw = ::keymaster::V4_1::CreateKeymasterDevice();
  android::sp<oldkm::IKeymasterDevice> keymaster;
  if (raw) {
    // Acquire the factory's first strong reference explicitly; fromExisting()
    // otherwise refuses a newly constructed RefBase with strong count zero.
    const char owner = 0;
    raw->incStrong(&owner);
    keymaster = android::sp<oldkm::IKeymasterDevice>::fromExisting(raw);
    raw->decStrong(&owner);
  }
  if (!gatekeeper || !keymaster) {
    LOG(ERROR) << "Recovery auth: pinned QTI implementation unavailable";
    return 1;
  }
  bool tee = false;
  auto info = keymaster->getHardwareInfo([&](oldkm::SecurityLevel level,
                                             const android::hardware::hidl_string&,
                                             const android::hardware::hidl_string&) {
    tee = level == oldkm::SecurityLevel::TRUSTED_ENVIRONMENT;
  });
  if (!info.isOk() || !tee) {
    LOG(ERROR) << "Recovery auth: Keymaster TEE check failed";
    return 1;
  }
  auto g = ndk::SharedRefBase::make<Gatekeeper>(gatekeeper);
  auto s = ndk::SharedRefBase::make<SharedSecret>(keymaster);
  ABinderProcess_setThreadPoolMaxThreadCount(1);
  if (AServiceManager_addService(g->asBinder().get(),
                                 "android.hardware.gatekeeper.IGatekeeper/default") != STATUS_OK ||
      AServiceManager_addService(s->asBinder().get(),
                                 "android.hardware.security.sharedsecret.ISharedSecret/legacy") !=
          STATUS_OK)
    return 1;
  ABinderProcess_joinThreadPool();
  return 1;
}
