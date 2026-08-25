package provide testcl 1.0.14
package require log

namespace eval ::testcl {
  variable expectedEvent
  variable variables
  namespace export rule
  namespace export when
  namespace export event
  namespace export run
}

# testcl::rule --
#
# Override of the iRule rule command
#
# Arguments:
# ruleName The name of the rule
# body the body of the rule
#
# Side Effects:
# None.
#
# Results:
# None.
proc ::testcl::rule {ruleName body} {
  log::log debug "rule $ruleName invoked"
  set rc [catch $body result]
  log::log info "rule $ruleName finished, return code: $rc  result: $result"

  if {$rc != 2000} {
    log::log error "Expected return code 200 from calling when, got $rc"
    log::log error "Error info: $::errorInfo"
    log::log error "++++++++++++++++++++++++++++++++++++++++++"	  	  
    error "Expected return code 2000 from calling when, got $rc"
  } else {
    return "rule $ruleName"
  }
  
}

# testcl::when --
#
# Override of the iRule when command
#
# https://devcentral.f5.com/wiki/iRules.when.ashx
#
# Arguments:
# event Type of event, for instance HTTP_REQUEST
# [timing on|off] currently ignored
# [priority N] currently ignored
# body the body of the when command
#
# Side Effects:
# None.
#
# Results:
# None.
proc ::testcl::when args {
	
  # TODO add support for priority 
  if { [llength $args] != 2 && [llength $args] != 4 && [llength $args] != 6 } {
    error "wrong # args for when, expected 2, 4 or 6 args"
  } else {
    set event [lindex $args 0]
    set body [lindex $args end]
  }

  variable variables
  if [ info exists variables ] {
    foreach { key value } [ array get variables ] {
      uplevel 0 {set $key $value}
    }
  }

  variable expectedEvent

  if {[info exists expectedEvent] && $event eq $expectedEvent} {
    log::log debug "when invoked with expected event '$event'"
    set rc [catch $body result]
    log::log info "when invoked with expected event $event finished, return code: $rc  result: $result"

    variable expectedEvent
    variable expectedEndState
    if { ![info exist expectedEndState] } {
      log::log debug "endstate verification skipped - undefined in current \"it\" context"
      if {$rc >= 1000} {
        error "Expected return code < 1000, got $rc"
      }
      return -code 2000 "when $event"
    }

    if {$rc != 1000} {
      log::log error "Expected end state with return code 3, got $rc"
      log::log error "Error info: $::errorInfo"
      log::log error "++++++++++++++++++++++++++++++++++++++++++"	  	  
      error "Expected end state with return code 3, got $rc"
    }

    if {$result ne $expectedEndState} {
      error "Expected end state $expectedEndState, got $result"
    }

    return -code 2000 "when $event"

  } elseif {[info exists expectedEvent] && $event ne $expectedEvent} {
    log::log debug "when not invoked due to non-matching event type"
  } else {
    log::log error "when not invoked due to missing expected event"
    error "when not invoked due to missing expected event"
  }

}

# testcl::event --
#
# Proc to setup the kind of event to expect
#
# Arguments:
# event_type The type of event, e.g. HTTP_REQUEST, HTTP_RESPONSE, CLIENT_ACCEPTED
#
# Side Effects:
# None.
#
# Results:
# None.

proc ::testcl::event {event_type} {
  variable expectedEvent
  set validEvents [::testcl::supported_events]
  if { [lsearch $validEvents "$event_type"] != -1 } {
    set expectedEvent $event_type
  } else {
    log::log error "Unsupported event: $event_type. Supported events are $validEvents"
    error "Unsupported event: $event_type. Supported events are $validEvents"
  }
}

# The catalog is based on F5's current Master List of iRule Events. It is
# intentionally a validation catalog, not a claim that every event has a
# complete mock implementation in TesTcl.
proc ::testcl::supported_events {} {
  return {
    ACCESS2_POLICY_EXPRESSION_EVAL ACCESS_ACL_ALLOWED ACCESS_ACL_DENIED
    ACCESS_PER_REQUEST_AGENT_EVENT ACCESS_POLICY_AGENT_EVENT ACCESS_POLICY_COMPLETED
    ACCESS_SAML_ASSERTION ACCESS_SAML_AUTHN ACCESS_SAML_SLO_REQ ACCESS_SAML_SLO_RESP
    ACCESS_SESSION_CLOSED ACCESS_SESSION_STARTED ADAPT_REQUEST_HEADERS
    ADAPT_REQUEST_RESULT ADAPT_RESPONSE_HEADERS ADAPT_RESPONSE_RESULT ANTIFRAUD_ALERT
    ANTIFRAUD_LOGIN ASM_REQUEST_BLOCKING ASM_REQUEST_DONE
    ASM_REQUEST_VIOLATION ASM_RESPONSE_LOGIN ASM_RESPONSE_VIOLATION AUTH_ERROR AUTH_FAILURE
    AUTH_RESULT AUTH_SUCCESS AUTH_WANTCREDENTIAL AVR_CSPM_INJECTION BOTDEFENSE_ACTION
    BOTDEFENSE_REQUEST CACHE_REQUEST CACHE_RESPONSE CACHE_UPDATE CATEGORY_MATCHED
    CLASSIFICATION_DETECTED CLIENT_ACCEPTED
    CLIENT_CLOSED CLIENT_DATA CLIENTSSL_CLIENTCERT CLIENTSSL_CLIENTHELLO CLIENTSSL_DATA
    CLIENTSSL_HANDSHAKE CLIENTSSL_PASSTHROUGH CLIENTSSL_SERVERHELLO_SEND CONNECTOR_OPEN
    DIAMETER_EGRESS DIAMETER_INGRESS DIAMETER_RETRANSMISSION DNS_REQUEST DNS_RESPONSE
    ECA_REQUEST_ALLOWED ECA_REQUEST_DENIED EPI_NA_CHECK_HTTP_REQUEST FIX_HEADER FIX_MESSAGE
    FLOW_INIT GENERICMESSAGE_EGRESS GENERICMESSAGE_INGRESS GTP_GPDU_EGRESS GTP_GPDU_INGRESS
    GTP_PRIME_EGRESS GTP_PRIME_INGRESS GTP_SIGNALLING_EGRESS GTP_SIGNALLING_INGRESS
    HTML_COMMENT_MATCHED HTML_TAG_MATCHED HTTP_CLASS_FAILED HTTP_CLASS_SELECTED
    HTTP_DISABLED HTTP_PROXY_CONNECT HTTP_PROXY_REQUEST HTTP_PROXY_RESPONSE HTTP_REJECT
    HTTP_REQUEST HTTP_REQUEST_DATA HTTP_REQUEST_RELEASE HTTP_REQUEST_SEND HTTP_RESPONSE
    HTTP_RESPONSE_CONTINUE HTTP_RESPONSE_DATA HTTP_RESPONSE_RELEASE ICAP_REQUEST ICAP_RESPONSE
    IN_DOSL7_ATTACK IVS_ENTRY_REQUEST IVS_ENTRY_RESPONSE JSON_REQUEST
    JSON_REQUEST_ERROR JSON_REQUEST_MISSING JSON_RESPONSE JSON_RESPONSE_ERROR
    JSON_RESPONSE_MISSING L7CHECK_CLIENT_DATA L7CHECK_SERVER_DATA LB_FAILED LB_QUEUED
    LB_SELECTED MQTT_CLIENT_DATA MQTT_CLIENT_EGRESS MQTT_CLIENT_INGRESS
    MQTT_CLIENT_SHUTDOWN MQTT_SERVER_DATA MQTT_SERVER_EGRESS MQTT_SERVER_INGRESS MR_EGRESS
    MR_FAILED MR_INGRESS NAME_RESOLVED PCP_REQUEST PCP_RESPONSE PEM_POLICY PERSIST_DOWN
    PING_REQUEST_READY PING_RESPONSE_READY QOE_PARSE_DONE REWRITE_REQUEST_DONE
    REWRITE_RESPONSE_DONE RTSP_REQUEST RTSP_REQUEST_DATA
    RTSP_RESPONSE RTSP_RESPONSE_DATA RULE_INIT SA_PICKED SERVER_CLOSED SERVER_CONNECTED
    SERVER_DATA SERVER_INIT SERVERSSL_CLIENTHELLO_SEND SERVERSSL_DATA SERVERSSL_HANDSHAKE
    SERVERSSL_SERVERCERT SERVERSSL_SERVERHELLO SIP SIP_REQUEST SIP_REQUEST_DONE
    SIP_REQUEST_SEND SIP_RESPONSE SIP_RESPONSE_DONE SIP_RESPONSE_SEND SOCKS_REQUEST
    SSE_RESPONSE STREAM_MATCHED USER_REQUEST USER_RESPONSE
    WS_CLIENT_DATA WS_CLIENT_FRAME WS_CLIENT_FRAME_DONE WS_REQUEST WS_RESPONSE
    WS_SERVER_DATA WS_SERVER_FRAME WS_SERVER_FRAME_DONE XML XML_CONTENT_BASED_ROUTING
  }
}

# testcl::run --
#
# Run irule
#
# Arguments:
# irule the file containing the irule
# rulename the name of the rule
#
# Side Effects:
# none
#
# Results:
# none
proc ::testcl::run {irule rulename {vars {}}} {
  log::log info "Running irule $irule"
  variable variables
  if {[array exists variables]} {
    array unset variables
  }
  if {$vars ne ""} {
    upvar 1 $vars a
    if {![array exists a]} {
      error "run variable argument '$vars' is not an array"
    }
    array set variables [array get a]
  }
  set rc [catch {source $irule} result]
  if { 0 != $rc } {
    log::log error "Running irule $irule failed: $result"	  
    log::log error "Error info: $::errorInfo"
    log::log error "++++++++++++++++++++++++++++++++++++++++++"	  	  
    error "Running irule $irule failed: $result"	
  }
  testcl::assertStringEquals "rule $rulename" $result
}

proc ::testcl::call args {
  return [eval $args]
}
