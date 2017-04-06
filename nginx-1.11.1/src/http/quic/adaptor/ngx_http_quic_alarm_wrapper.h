#ifndef __NGX_HTTP_QUIC_ALARM_GO_WRAPPER_H__
#define __NGX_HTTP_QUIC_ALARM_GO_WRAPPER_H__
//#include "go_functions.h"
#include "net/quic/platform/api/quic_clock.h"
#include "net/quic/core/quic_alarm.h"
#include "base/logging.h"
#include <iostream>

namespace net {

class NgxQuicAlarmNgxWrapper : public QuicAlarm {
public:
	NgxQuicAlarmNgxWrapper(QuicClock* clock,
                       QuicArenaScopedPtr<Delegate> delegate)
      : QuicAlarm(std::move(delegate)){}

	virtual ~NgxQuicAlarmNgxWrapper() {
    // Notify go object that we are destroyed
	}

  // Should be called by gowrapper only
	void Fire_() { Fire(); }

	void SetNgxQuicAlarm(int64_t ngx_quic_alarm) { ngx_quic_alarm_ = ngx_quic_alarm; }

protected:
	void SetImpl() override {
		NgxQuicAlarmSetImpl_C(ngx_quic_alarm_, quic_clock_to_int64(deadline()));
	}
	void CancelImpl() override { NgxQuicAlarmCancelImpl_C(ngx_quic_alarm_); }

private:
	int64_t ngx_quic_alarm_;

	int64_t quic_clock_to_int64(QuicTime time) {
		return (time - QuicTime::Zero()).ToMicroseconds();
	}
};
}
#endif
