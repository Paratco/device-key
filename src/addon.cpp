#include <algorithm>
#include <functional>
#include <string>
#include <vector>

#include <napi.h>

#include "backend.hpp"

namespace {

    // Runs one backend call on a worker thread and settles a promise: hardware calls can take hundreds of ms.
    class BackendWorker : public Napi::AsyncWorker {
    public:
        using Job = std::function<std::vector<uint8_t>()>;
        enum class Result { Undefined, Boolean, Bytes };

        BackendWorker(const Napi::Env &env, Job job, Result result)
            : Napi::AsyncWorker(env), job_(std::move(job)), result_(result), deferred_(Napi::Promise::Deferred::New(env)) {}

        Napi::Promise Promise() const { return deferred_.Promise(); }

    protected:
        void Execute() override {
            try {
                bytes_ = job_();
            } catch (const device_key::KeyError &e) {
                code_ = e.Code();
                SetError(e.what());
            } catch (const std::exception &e) {
                SetError(e.what());
            }
        }

        void OnOK() override {
            const auto env = Env();
            switch (result_) {
                case Result::Undefined: deferred_.Resolve(env.Undefined()); break;
                case Result::Boolean: deferred_.Resolve(Napi::Boolean::New(env, !bytes_.empty() && bytes_[0] != 0)); break;
                case Result::Bytes: deferred_.Resolve(Napi::Buffer<uint8_t>::Copy(env, bytes_.data(), bytes_.size())); break;
            }
        }

        void OnError(const Napi::Error &error) override {
            auto value = error.Value();
            if (code_ != nullptr) value.Set("code", code_);
            deferred_.Reject(value);
        }

    private:
        const char *code_ = nullptr;
        Job job_;
        Result result_;
        Napi::Promise::Deferred deferred_;
        std::vector<uint8_t> bytes_;
    };

    Napi::Promise Run(const Napi::Env &env, BackendWorker::Job job, const BackendWorker::Result result) {
        auto *worker = new BackendWorker(env, std::move(job), result);
        const auto promise = worker->Promise();
        worker->Queue();
        return promise;
    }

    // Key names become key container / keychain labels: keep them short and plain on every OS.
    std::string KeyName(const Napi::CallbackInfo &info) {
        if (info.Length() < 1 || !info[0].IsString()) {
            throw Napi::TypeError::New(info.Env(), "name must be a string");
        }
        auto name = info[0].As<Napi::String>().Utf8Value();
        const bool plain = std::all_of(name.begin(), name.end(), [](const char c) {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        });
        if (name.empty() || name.size() > 64 || !plain) {
            throw Napi::TypeError::New(info.Env(), "name must be 1-64 characters of A-Z a-z 0-9 . _ -");
        }
        return name;
    }

    Napi::Value IsAvailable(const Napi::CallbackInfo &info) {
        return Run(info.Env(), [] { return std::vector<uint8_t>{device_key::Available() ? uint8_t{1} : uint8_t{0}}; },
                   BackendWorker::Result::Boolean);
    }

    Napi::Value CreateKey(const Napi::CallbackInfo &info) {
        return Run(info.Env(), [name = KeyName(info)] {
            device_key::CreateKey(name);
            return std::vector<uint8_t>{};
        }, BackendWorker::Result::Undefined);
    }

    Napi::Value PublicPoint(const Napi::CallbackInfo &info) {
        return Run(info.Env(), [name = KeyName(info)] { return device_key::PublicPoint(name); }, BackendWorker::Result::Bytes);
    }

    Napi::Value SignDigest(const Napi::CallbackInfo &info) {
        const auto name = KeyName(info);
        if (info.Length() < 2 || !info[1].IsBuffer() || info[1].As<Napi::Buffer<uint8_t>>().Length() != 32) {
            throw Napi::TypeError::New(info.Env(), "digest must be a 32-byte Buffer (SHA-256)");
        }
        device_key::Digest digest{};
        const auto buffer = info[1].As<Napi::Buffer<uint8_t>>();
        std::copy_n(buffer.Data(), digest.size(), digest.begin());

        return Run(info.Env(), [name, digest] { return device_key::SignDigest(name, digest); }, BackendWorker::Result::Bytes);
    }

    Napi::Value DeleteKey(const Napi::CallbackInfo &info) {
        return Run(info.Env(), [name = KeyName(info)] {
            device_key::DeleteKey(name);
            return std::vector<uint8_t>{};
        }, BackendWorker::Result::Undefined);
    }

    Napi::Object Init(const Napi::Env env, Napi::Object exports) {
        exports.Set("isAvailable", Napi::Function::New(env, IsAvailable));
        exports.Set("createKey", Napi::Function::New(env, CreateKey));
        exports.Set("publicPoint", Napi::Function::New(env, PublicPoint));
        exports.Set("signDigest", Napi::Function::New(env, SignDigest));
        exports.Set("deleteKey", Napi::Function::New(env, DeleteKey));
        return exports;
    }

}

NODE_API_MODULE(device_key, Init)
