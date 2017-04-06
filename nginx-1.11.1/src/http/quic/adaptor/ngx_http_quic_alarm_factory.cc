// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ngx_http_quic_alarm_factory.h"
#include "net/tools/epoll_server/epoll_server.h"

namespace net {

namespace {

class QuicEpollAlarm : public QuicAlarm {
 public:
  QuicEpollAlarm(QuicArenaScopedPtr<Delegate> delegate)
      : QuicAlarm(std::move(delegate)){}

 protected:
  void SetImpl() override {
    DCHECK(deadline().IsInitialized());
  }

  void CancelImpl() override {
    DCHECK(!deadline().IsInitialized());
  }

 private:
	int64_t OnAlarm() {
      //EpollAlarm::OnAlarm();
      // Fire will take care of registering the alarm, if needed.
      return 0;
    }

};

}  // namespace

QuicEpollAlarmFactory::QuicEpollAlarmFactory() {}

QuicEpollAlarmFactory::~QuicEpollAlarmFactory() {}

QuicAlarm* QuicEpollAlarmFactory::CreateAlarm(QuicAlarm::Delegate* delegate) {
  return new QuicEpollAlarm(QuicArenaScopedPtr<QuicAlarm::Delegate>(delegate));
}

QuicArenaScopedPtr<QuicAlarm> QuicEpollAlarmFactory::CreateAlarm(
    QuicArenaScopedPtr<QuicAlarm::Delegate> delegate,
    QuicConnectionArena* arena) {
  if (arena != nullptr) {
    return arena->New<QuicEpollAlarm>(std::move(delegate));
  } else {
    return QuicArenaScopedPtr<QuicAlarm>(
        new QuicEpollAlarm(std::move(delegate)));
  }
}

}  // namespace net
