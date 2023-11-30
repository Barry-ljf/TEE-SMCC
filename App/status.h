#ifndef __STATUS_H_
#define __STATUS_H_

#include <string>

namespace smcc {
class Status {
 private:
  enum class Code {
    kOK = 0,
    kNetworkError,
    kMismatchError,
    kInternalError,
    kEcallError,
    kInvalidError,
    kUnavailableError,
    kRPCError,
    kTimeoutError,
    kDuplicateError,
    kNotFoundError,
  };

 public:
  virtual ~Status() = default;

  Status(const Status &rhs) {
    this->status_code_ = rhs.status_code_;
    this->err_msg_ = rhs.err_msg_;
  };

  Status(Status &&rhs) {
    this->status_code_ = rhs.status_code_;
    this->err_msg_ = std::move(rhs.err_msg_);
  }

  Status &operator=(const Status &rhs) {
    this->status_code_ = rhs.status_code_;
    this->err_msg_ = std::move(rhs.err_msg_);
    return *this;
  }

  Status &operator=(const Status &&rhs) {
    this->status_code_ = rhs.status_code_;
    this->err_msg_ = std::move(rhs.err_msg_);
    return *this;
  }

  std::string getMessage(void) { return err_msg_; }

  static Status OK(void) { return Status(Code::kOK, "No error."); }

  static Status DuplicateError(const std::string &msg) {
    return Status(Code::kDuplicateError, msg);
  }

  static Status NetworkError(const std::string &msg) {
    return Status(Code::kNetworkError, msg);
  }

  static Status EcallError(const std::string &msg) {
    return Status(Code::kEcallError, msg);
  }

  static Status InternalError(const std::string &msg) {
    return Status(Code::kInternalError, msg);
  }

  static Status UnavailableError(const std::string &msg) {
    return Status(Code::kUnavailableError, msg);
  }

  static Status RPCError(const std::string &msg) {
    return Status(Code::kRPCError, msg);
  }

  static Status TimeoutError(const std::string &msg) {
    return Status(Code::kTimeoutError, msg);
  }

  static Status NotFoundError(const std::string &msg) {
    return Status(Code::kNotFoundError, msg);
  }

  bool IsOK() const { return status_code_ == Code::kOK; }

 private:
  explicit Status(const Code &status_code, const std::string &msg)
      : status_code_(status_code), err_msg_(msg) {}

  Code status_code_;
  std::string err_msg_;
};
}  // namespace smcc

#endif
