source src/onirule.tcl
namespace import ::testcl::event

foreach event_type {
  HTTP_PROXY_CONNECT
  JSON_REQUEST_ERROR
  MQTT_CLIENT_DATA
  ASM_RESPONSE_LOGIN
  SERVERSSL_SERVERCERT
} {
  if {[catch {event $event_type} message]} {
    error "current event '$event_type' was rejected: $message"
  }
}

if {![catch {event NOT_A_REAL_EVENT}]} {
  error "invalid event was accepted"
}
