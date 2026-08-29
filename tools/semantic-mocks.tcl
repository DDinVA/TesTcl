# semantic-mocks.tcl -- TesTcl's adapter-owned semantic iRule mocks
#
# The upstream tcl-lsp framework provides broad command recognition and
# generated placeholders. This small overlay implements high-value behavior
# that depends on the adapter's scenario state without modifying the external
# tcl-lsp checkout.

namespace eval ::itest::semantic {
    variable stats
    array set stats {}
    variable hsl_handles
    array set hsl_handles {}
    variable hsl_messages {}
    variable next_hsl_handle 0
    variable requested_lb_failure ""
    variable lb_failure_pending 0
    variable lb_failure_cause ""
    variable lb_failure_fired 0
    variable http_retry_requested 0
    variable http_retry_request ""
    variable http_retry_reset 0
    variable http_release_requested 0
    variable http_close_requested 0
    variable http_request_number 0
    variable ws_enabled 1
    variable ws_request_seen 0
    variable ws_upgrade_seen 0
    variable ws_collection_requested 0
    variable ws_collection_length 0
    variable ws_release_requested 0
    variable ws_frame_dropped 0
    variable ws_message_dropped 0
    variable ws_disconnect_requested 0
    variable ws_disconnect_code ""
    variable ws_disconnect_reason ""
    variable ws_masking "remask"

    variable mqtt_enabled 1
    variable mqtt_collection_requested 0
    variable mqtt_collection_length 0
    variable mqtt_release_requested 0
    variable mqtt_dropped 0
    variable mqtt_disconnect_requested 0

    variable dns_rr_counter 0
    variable dns_rr_objects [dict create]
    variable dns_message_counter 0
    variable dns_message_objects [dict create]
    variable resolver_records [dict create]
    variable ssl_cert_counter 0
    variable ssl_cert_objects [dict create]
    variable http2_pending [dict create]

    variable sip_discarded 0
    variable sip_response_requested 0
    variable sip_response_code ""
    variable sip_response_phrase ""
    variable sip_response_headers {}
    variable sip_persist_key ""
    variable sip_persist_mode "use"
    variable sip_persist_timeout 0
    variable sip_persist_bidirectional 0
    variable sip_persist_direction "detect"

    namespace eval ::state::websocket {
        variable request_headers {}
        variable response_headers {}
        variable method ""
        variable uri ""
        variable host ""
        variable status ""
        variable frame_type ""
        variable eom 1
        variable orig_masked 0
        variable mask ""
        variable payload ""
        variable payload_length 0
    }

    foreach tls_side {client server} {
        namespace eval ::state::tls::$tls_side {
            variable sni ""
            variable sni_required 0
            variable cipher_name ""
            variable cipher_bits 0
            variable cipher_version ""
            variable cipher_clientlist ""
            variable cert_subject ""
            variable cert_issuer ""
            variable cert_serial ""
            variable cert_hash ""
            variable cert_count 0
            variable cert_mode "ignore"
            variable verify_result 0
            variable disabled 0
            variable extensions ""
            variable alpn ""
            variable handshake_done 0
            variable session_id ""
        }
    }

    namespace eval ::state::http2 {
        variable active 0
        variable version 0
        variable stream_id 0
        variable stream_priority 0
        variable concurrency 0
        variable requests 0
        variable enabled 1
        variable clientside_enabled 1
        variable serverside_enabled 1
        variable disconnected 0
        variable discarded 0
        variable pseudo_headers {}
    }

    namespace eval ::state::mqtt {
        variable type ""
        variable protocol_name "MQTT"
        variable protocol_version 4
        variable client_id ""
        variable clean_session 1
        variable keep_alive 60
        variable username ""
        variable password ""
        variable will_topic ""
        variable will_message ""
        variable will_qos 0
        variable will_retain 0
        variable packet_id 0
        variable qos 0
        variable dup 0
        variable retain 0
        variable topic ""
        variable payload ""
        variable payload_length 0
        variable message ""
        variable message_length 0
        variable return_code 0
        variable return_code_list {}
        variable session_present 0
        variable topic_list {}
    }

    namespace eval ::state::sip {
        variable type "request"
        variable transport "tcp"
        variable method ""
        variable uri ""
        variable version "SIP/2.0"
        variable status ""
        variable phrase ""
        variable headers {}
        variable payload ""
        variable payload_length 0
        variable message ""
        variable message_length 0
        variable call_id ""
        variable from ""
        variable to ""
        variable route_status "unrouted"
        variable persist_key ""
        variable record_route {}
        variable route {}
        variable via {}
    }

    namespace eval ::state::diameter {
        variable type request
        variable version 1
        variable rflag 1
        variable pflag 0
        variable eflag 0
        variable tflag 0
        variable command_code 0
        variable application_id 0
        variable hop_by_hop_id 0
        variable end_to_end_id 0
        variable avps {}
        variable payload ""
        variable payload_length 0
        variable message ""
        variable message_length 20
        variable route_status unrouted
        variable persist_key ""
    }

    namespace eval ::state::radius {
        variable code 1
        variable id 0
        variable authenticator ""
        variable attributes {}
        variable payload ""
        variable payload_length 0
        variable message ""
        variable message_length 20
        variable message_hex ""
        variable payload_hex ""
        variable rtdom ""
        variable subscriber ""
    }

    namespace eval ::state::message {
        variable proto generic
        variable type request
        variable fields {}
    }

    namespace eval ::state::mr {
        variable payload ""
        variable payload_length 0
        variable collect_length 0
        variable peer ""
        variable route_status unrouted
        variable route ""
        variable route_target ""
        variable available_for_routing true
        variable always_match_port false
        variable ignore_peer_port false
        variable connect_back_port 0
        variable connection_instance "0 of 1"
        variable connection_mode per-peer
        variable equivalent_transport ""
        variable flow_id "flow-0"
        variable instance "/Common/mr_router"
        variable max_retries 3
        variable transport "config /Common/mr_router"
        variable retry_count 0
        variable stored {}
        variable streamed ""
        variable dropped false
        variable released false
        variable response ""
    }

    namespace eval ::state::gtp {
        variable version 2
        variable type 1
        variable teid 0
        variable sequence 0
        variable npdu 0
        variable length 0
        variable ies {}
        variable payload ""
        variable payload_length 0
        variable message ""
        variable message_length 0
        variable message_hex ""
        variable payload_hex ""
        variable discarded false
        variable responded false
    }

    proc _profile_enabled {name} {
        set wanted [string toupper $name]
        foreach profile $::orch::config(profiles) {
            if {[string toupper $profile] eq $wanted} {
                return 1
            }
        }
        return 0
    }

    proc _stat_key {args} {
        return [join $args |]
    }

    proc stats_snapshot {} {
        variable stats
        return [array get stats]
    }

    proc hsl_snapshot {} {
        variable hsl_messages
        return $hsl_messages
    }

    proc prepare_lb_failure {cause} {
        variable requested_lb_failure
        variable lb_failure_pending
        variable lb_failure_cause
        variable lb_failure_fired
        unset -nocomplain ::state::lb::failure_cause
        set requested_lb_failure $cause
        set lb_failure_pending [expr {$cause ne ""}]
        set lb_failure_cause $cause
        set lb_failure_fired 0
    }

    proc clear_lb_failure {} {
        variable requested_lb_failure
        variable lb_failure_pending
        variable lb_failure_cause
        variable lb_failure_fired
        unset -nocomplain ::state::lb::failure_cause
        set requested_lb_failure ""
        set lb_failure_pending 0
        set lb_failure_cause ""
        set lb_failure_fired 0
    }

    proc lb_failure_snapshot {} {
        variable lb_failure_cause
        variable lb_failure_fired
        set selected 0
        if {[info exists ::state::lb::selected]} {
            set selected $::state::lb::selected
        }
        return [list cause $lb_failure_cause fired $lb_failure_fired selected $selected]
    }

    proc prepare_http_retry {} {
        variable http_retry_requested
        variable http_retry_request
        variable http_retry_reset
        set http_retry_requested 0
        set http_retry_request ""
        set http_retry_reset 0
    }

    proc prepare_http_close {} {
        variable http_close_requested
        set http_close_requested 0
    }

    proc prepare_http_release {} {
        variable http_release_requested
        set http_release_requested 0
    }

    proc http_retry_snapshot {} {
        variable http_retry_requested
        variable http_retry_request
        variable http_retry_reset
        return [list requested $http_retry_requested request $http_retry_request reset $http_retry_reset]
    }

    proc http_release_snapshot {} {
        variable http_release_requested
        return [list requested $http_release_requested]
    }

    proc ws_reset_connection {} {
        variable ws_enabled
        variable ws_request_seen
        variable ws_upgrade_seen
        variable ws_collection_requested
        variable ws_collection_length
        variable ws_release_requested
        variable ws_frame_dropped
        variable ws_message_dropped
        variable ws_disconnect_requested
        variable ws_disconnect_code
        variable ws_disconnect_reason
        variable ws_masking
        set ws_enabled 1
        set ws_request_seen 0
        set ws_upgrade_seen 0
        set ws_collection_requested 0
        set ws_collection_length 0
        set ws_release_requested 0
        set ws_frame_dropped 0
        set ws_message_dropped 0
        set ws_disconnect_requested 0
        set ws_disconnect_code ""
        set ws_disconnect_reason ""
        set ws_masking remask
        namespace eval ::state::websocket {
            variable request_headers {}
            variable response_headers {}
            variable method ""
            variable uri ""
            variable host ""
            variable status ""
            variable frame_type ""
            variable eom 1
            variable orig_masked 0
            variable mask ""
            variable payload ""
            variable payload_length 0
        }
    }

    proc mqtt_reset_connection {} {
        variable mqtt_enabled
        variable mqtt_collection_requested
        variable mqtt_collection_length
        variable mqtt_release_requested
        variable mqtt_dropped
        variable mqtt_disconnect_requested
        set mqtt_enabled 1
        set mqtt_collection_requested 0
        set mqtt_collection_length 0
        set mqtt_release_requested 0
        set mqtt_dropped 0
        set mqtt_disconnect_requested 0
        namespace eval ::state::mqtt {
            variable type ""
            variable protocol_name "MQTT"
            variable protocol_version 4
            variable client_id ""
            variable clean_session 1
            variable keep_alive 60
            variable username ""
            variable password ""
            variable will_topic ""
            variable will_message ""
            variable will_qos 0
            variable will_retain 0
            variable packet_id 0
            variable qos 0
            variable dup 0
            variable retain 0
            variable topic ""
            variable payload ""
            variable payload_length 0
            variable message ""
            variable message_length 0
            variable return_code 0
            variable return_code_list {}
            variable session_present 0
            variable topic_list {}
        }
    }

    proc mqtt_prepare_message {} {
        variable mqtt_release_requested
        variable mqtt_dropped
        variable mqtt_disconnect_requested
        set mqtt_release_requested 0
        set mqtt_dropped 0
        set mqtt_disconnect_requested 0
    }

    proc _mqtt_require_event {allowed command_name} {
        if {$::itest::current_event ni $allowed} {
            error "$command_name is not valid during $::itest::current_event"
        }
    }

    proc mqtt_collection_snapshot {} {
        variable mqtt_collection_requested
        variable mqtt_collection_length
        variable mqtt_release_requested
        return [list requested $mqtt_collection_requested length $mqtt_collection_length released $mqtt_release_requested]
    }

    proc mqtt_flags_snapshot {} {
        variable mqtt_dropped
        variable mqtt_disconnect_requested
        return [list dropped $mqtt_dropped disconnect $mqtt_disconnect_requested]
    }

    proc ws_collection_snapshot {} {
        variable ws_collection_requested
        variable ws_collection_length
        variable ws_release_requested
        return [list requested $ws_collection_requested length $ws_collection_length released $ws_release_requested]
    }

    proc ws_disconnect_snapshot {} {
        variable ws_disconnect_requested
        variable ws_disconnect_code
        variable ws_disconnect_reason
        return [list requested $ws_disconnect_requested code $ws_disconnect_code reason $ws_disconnect_reason]
    }

    proc ws_take_disconnect_snapshot {} {
        variable ws_disconnect_requested
        variable ws_disconnect_code
        variable ws_disconnect_reason
        set snapshot [list requested $ws_disconnect_requested code $ws_disconnect_code reason $ws_disconnect_reason]
        set ws_disconnect_requested 0
        set ws_disconnect_code ""
        set ws_disconnect_reason ""
        return $snapshot
    }

    proc ws_prepare_frame {} {
        variable ws_frame_dropped
        variable ws_release_requested
        variable ws_disconnect_requested
        variable ws_disconnect_code
        variable ws_disconnect_reason
        set ws_frame_dropped 0
        set ws_release_requested 0
        set ws_disconnect_requested 0
        set ws_disconnect_code ""
        set ws_disconnect_reason ""
    }

    proc ws_finish_frame {eom} {
        variable ws_message_dropped
        if {$eom && $ws_message_dropped} {
            set ws_message_dropped 0
        }
    }

    proc _ws_require_event {allowed command_name} {
        if {$::itest::current_event ni $allowed} {
            error "$command_name is not valid during $::itest::current_event"
        }
    }

    proc _ws_header_get {headers_var name} {
        if {![info exists $headers_var]} {
            return ""
        }
        set wanted [string tolower $name]
        set raw [set $headers_var]
        # The adapter stores the already-quoted Tcl list as a single safe
        # scalar. Unwrap that one layer without evaluating caller-provided
        # content as a script.
        if {[llength $raw] == 1} {
            set candidate [lindex $raw 0]
            if {[llength $candidate] > 0 && [llength $candidate] % 2 == 0} {
                set raw $candidate
            }
        }
        foreach {header_name header_value} $raw {
            if {[string tolower $header_name] eq $wanted} {
                return $header_value
            }
        }
        return ""
    }

    proc ws_request_command {args} {
        _ws_require_event {WS_REQUEST} WS::request
        if {[llength $args] != 1} {
            error "WS::request requires one selector"
        }
        switch -exact -- [lindex $args 0] {
            protocol { return [_ws_header_get ::state::websocket::request_headers Sec-WebSocket-Protocol] }
            extension { return [_ws_header_get ::state::websocket::request_headers Sec-WebSocket-Extensions] }
            version { return [_ws_header_get ::state::websocket::request_headers Sec-WebSocket-Version] }
            key { return [_ws_header_get ::state::websocket::request_headers Sec-WebSocket-Key] }
            default { error "WS::request selector must be protocol, extension, version, or key" }
        }
    }

    proc ws_response_command {args} {
        _ws_require_event {WS_RESPONSE} WS::response
        if {[llength $args] != 1} {
            error "WS::response requires one selector"
        }
        switch -exact -- [lindex $args 0] {
            protocol { return [_ws_header_get ::state::websocket::response_headers Sec-WebSocket-Protocol] }
            extension { return [_ws_header_get ::state::websocket::response_headers Sec-WebSocket-Extensions] }
            version { return [_ws_header_get ::state::websocket::response_headers Sec-WebSocket-Version] }
            key { return [_ws_header_get ::state::websocket::response_headers Sec-WebSocket-Accept] }
            valid {
                set status [expr {[info exists ::state::websocket::status] ? $::state::websocket::status : 0}]
                set accept [_ws_header_get ::state::websocket::response_headers Sec-WebSocket-Accept]
                set upgrade [_ws_header_get ::state::websocket::response_headers Upgrade]
                set connection [_ws_header_get ::state::websocket::response_headers Connection]
                set request_seen [expr {[info exists ::itest::semantic::ws_request_seen] ? $::itest::semantic::ws_request_seen : 0}]
                set upgrade_ok 0
                foreach token [split $upgrade ,] {
                    if {[string tolower [string trim $token]] eq "websocket"} {
                        set upgrade_ok 1
                    }
                }
                set connection_ok 0
                foreach token [split $connection ,] {
                    if {[string tolower [string trim $token]] eq "upgrade"} {
                        set connection_ok 1
                    }
                }
                return [expr {$status == 101 && $request_seen && $accept ne "" && $upgrade_ok && $connection_ok}]
            }
            default { error "WS::response selector must be protocol, extension, version, key, or valid" }
        }
    }

    proc ws_enabled_command {args} {
        variable ws_enabled
        _ws_require_event {WS_REQUEST WS_RESPONSE HTTP_REQUEST HTTP_RESPONSE} WS::enabled
        if {[llength $args] == 0} {
            return $ws_enabled
        }
        if {[llength $args] != 1 || [string tolower [lindex $args 0]] ni {false 0}} {
            error "WS::enabled accepts only false"
        }
        set ws_enabled 0
        ::itest::log_decision ws enabled false
        return $ws_enabled
    }

    proc ws_masking_command {args} {
        variable ws_masking
        _ws_require_event {WS_REQUEST WS_RESPONSE} WS::masking
        if {[llength $args] != 1 || [lindex $args 0] ni {preserve remask}} {
            error "WS::masking accepts preserve or remask"
        }
        set ws_masking [lindex $args 0]
        ::itest::log_decision ws masking $ws_masking
        return ""
    }

    proc ws_collect_command {args} {
        variable ws_collection_requested
        variable ws_collection_length
        _ws_require_event {WS_CLIENT_FRAME WS_SERVER_FRAME WS_CLIENT_DATA WS_SERVER_DATA} WS::collect
        if {[llength $args] < 1 || [llength $args] > 2 || [lindex $args 0] ne "frame"} {
            error "WS::collect syntax is WS::collect frame ?length?"
        }
        set length 0
        if {[llength $args] == 2} {
            set length [lindex $args 1]
            if {![string is integer -strict $length] || $length < 1} {
                error "WS::collect length must be a positive integer"
            }
        }
        set ws_collection_requested 1
        set ws_collection_length $length
        ::itest::log_decision ws collect [list frame $length]
        return ""
    }

    proc ws_payload_command {args} {
        _ws_require_event {WS_CLIENT_DATA WS_SERVER_DATA} WS::payload
        set payload $::state::websocket::payload
        set payload_bytes [::itest::cmd::_payload_bytes $payload]
        if {[llength $args] == 0} {
            return $payload
        }
        if {[llength $args] == 1 && [lindex $args 0] eq "length"} {
            return [::itest::cmd::_payload_bytelength $payload]
        }
        if {[llength $args] == 1 || [llength $args] == 2} {
            foreach value $args {
                if {![string is integer -strict $value] || $value < 0} {
                    error "WS::payload offsets and lengths must be non-negative integers"
                }
            }
            set offset [lindex $args 0]
            set length [expr {[llength $args] == 1 ? $offset : [lindex $args 1]}]
            if {[llength $args] == 1} { set offset 0 }
            if {$length == 0} {
                return [::itest::cmd::_payload_bytes ""]
            }
            return [string range $payload_bytes $offset [expr {$offset + $length - 1}]]
        }
        if {[llength $args] == 4 && [lindex $args 0] eq "replace"} {
            set offset [lindex $args 1]
            set length [lindex $args 2]
            if {![string is integer -strict $offset] || $offset < 0 ||
                ![string is integer -strict $length] || $length < 0} {
                error "WS::payload replace offsets and lengths must be non-negative integers"
            }
            set replacement [lindex $args 3]
            set ::state::websocket::payload [::itest::cmd::_payload_splice $payload $offset $length $replacement]
            set ::state::websocket::payload_length [::itest::cmd::_payload_bytelength $::state::websocket::payload]
            return ""
        }
        error "unsupported WS::payload syntax"
    }

    proc ws_release_command {args} {
        variable ws_collection_requested
        variable ws_collection_length
        variable ws_release_requested
        _ws_require_event {WS_CLIENT_DATA WS_SERVER_DATA} WS::release
        if {[llength $args] != 0} {
            error "WS::release takes no arguments"
        }
        set ws_collection_requested 0
        set ws_collection_length 0
        set ws_release_requested 1
        ::itest::log_decision ws release
        return ""
    }

    proc ws_frame_command {args} {
        variable ws_frame_dropped
        _ws_require_event {WS_CLIENT_FRAME WS_SERVER_FRAME} WS::frame
        if {[llength $args] != 1} {
            error "WS::frame requires one selector in this emulator slice"
        }
        switch -exact -- [lindex $args 0] {
            eom { return $::state::websocket::eom }
            orig_masked { return $::state::websocket::orig_masked }
            type { return $::state::websocket::frame_type }
            mask { return $::state::websocket::mask }
            drop {
                set ws_frame_dropped 1
                ::itest::log_decision ws frame drop
                return ""
            }
            default { error "unsupported WS::frame selector" }
        }
    }

    proc ws_message_command {args} {
        variable ws_message_dropped
        _ws_require_event {WS_CLIENT_FRAME WS_SERVER_FRAME WS_CLIENT_DATA WS_SERVER_DATA} WS::message
        if {[llength $args] != 1 || [lindex $args 0] ne "drop"} {
            error "WS::message syntax is WS::message drop"
        }
        set ws_message_dropped 1
        ::itest::log_decision ws message drop
        return ""
    }

    proc ws_disconnect_command {args} {
        variable ws_disconnect_requested
        variable ws_disconnect_code
        variable ws_disconnect_reason
        _ws_require_event {WS_CLIENT_FRAME_DONE WS_SERVER_FRAME_DONE} WS::disconnect
        if {[llength $args] < 1 || [llength $args] > 2} {
            error "WS::disconnect requires a code and optional reason"
        }
        set code [lindex $args 0]
        if {![string is integer -strict $code] || $code < 1000 || $code > 4999} {
            error "WS::disconnect code must be between 1000 and 4999"
        }
        set ws_disconnect_requested 1
        set ws_disconnect_code $code
        set ws_disconnect_reason [expr {[llength $args] == 2 ? [lindex $args 1] : ""}]
        if {[string bytelength $ws_disconnect_reason] > 123} {
            error "WS::disconnect reason must be at most 123 bytes"
        }
        ::itest::log_decision ws disconnect [list $code $ws_disconnect_reason]
        return ""
    }

    proc mqtt_field_command {field allowed command_name args} {
        _mqtt_require_event $allowed $command_name
        if {[llength $args] > 1} {
            error "$command_name accepts zero or one argument"
        }
        set variable_name ::state::mqtt::$field
        if {[llength $args] == 0} {
            return [set $variable_name]
        }
        set value [lindex $args 0]
        set $variable_name $value
        ::itest::log_decision mqtt ${field}_set $value
        return $value
    }

    proc mqtt_integer_field_command {field allowed command_name minimum maximum args} {
        _mqtt_require_event $allowed $command_name
        if {[llength $args] > 1} {
            error "$command_name accepts zero or one argument"
        }
        set variable_name ::state::mqtt::$field
        if {[llength $args] == 0} {
            return [set $variable_name]
        }
        set value [lindex $args 0]
        if {![string is integer -strict $value] || $value < $minimum || $value > $maximum} {
            error "$command_name value is out of range"
        }
        set $variable_name $value
        ::itest::log_decision mqtt ${field}_set $value
        return $value
    }

    proc mqtt_boolean_field_command {field allowed command_name args} {
        _mqtt_require_event $allowed $command_name
        if {[llength $args] > 1} {
            error "$command_name accepts zero or one argument"
        }
        set variable_name ::state::mqtt::$field
        if {[llength $args] == 0} {
            return [set $variable_name]
        }
        set value [lindex $args 0]
        if {$value ni {0 1 true false}} {
            error "$command_name value must be 0 or 1"
        }
        set value [expr {$value in {1 true}}]
        set $variable_name $value
        ::itest::log_decision mqtt ${field}_set $value
        return $value
    }

    proc mqtt_clean_session_command {args} {
        return [mqtt_boolean_field_command clean_session {MQTT_CLIENT_INGRESS MQTT_SERVER_INGRESS MQTT_CLIENT_DATA MQTT_SERVER_DATA MQTT_CLIENT_EGRESS MQTT_SERVER_EGRESS} MQTT::clean_session {*}$args]
    }

    proc mqtt_client_id_command {args} {
        return [mqtt_field_command client_id {MQTT_CLIENT_INGRESS MQTT_SERVER_INGRESS MQTT_CLIENT_DATA MQTT_SERVER_DATA MQTT_CLIENT_EGRESS MQTT_SERVER_EGRESS} MQTT::client_id {*}$args]
    }

    proc mqtt_keep_alive_command {args} {
        return [mqtt_integer_field_command keep_alive {MQTT_CLIENT_INGRESS MQTT_SERVER_INGRESS MQTT_CLIENT_DATA MQTT_SERVER_DATA MQTT_CLIENT_EGRESS MQTT_SERVER_EGRESS} MQTT::keep_alive 0 65535 {*}$args]
    }

    proc mqtt_password_command {args} {
        return [mqtt_field_command password {MQTT_CLIENT_INGRESS MQTT_SERVER_INGRESS MQTT_CLIENT_DATA MQTT_SERVER_DATA MQTT_CLIENT_EGRESS MQTT_SERVER_EGRESS} MQTT::password {*}$args]
    }

    proc mqtt_protocol_name_command {args} {
        return [mqtt_field_command protocol_name {MQTT_CLIENT_INGRESS MQTT_SERVER_INGRESS MQTT_CLIENT_DATA MQTT_SERVER_DATA MQTT_CLIENT_EGRESS MQTT_SERVER_EGRESS} MQTT::protocol_name {*}$args]
    }

    proc mqtt_protocol_version_command {args} {
        return [mqtt_integer_field_command protocol_version {MQTT_CLIENT_INGRESS MQTT_SERVER_INGRESS MQTT_CLIENT_DATA MQTT_SERVER_DATA MQTT_CLIENT_EGRESS MQTT_SERVER_EGRESS} MQTT::protocol_version 0 255 {*}$args]
    }

    proc mqtt_packet_id_command {args} {
        return [mqtt_integer_field_command packet_id {MQTT_CLIENT_INGRESS MQTT_SERVER_INGRESS MQTT_CLIENT_DATA MQTT_SERVER_DATA MQTT_CLIENT_EGRESS MQTT_SERVER_EGRESS} MQTT::packet_id 0 65535 {*}$args]
    }

    proc mqtt_qos_command {args} {
        return [mqtt_integer_field_command qos {MQTT_CLIENT_INGRESS MQTT_SERVER_INGRESS MQTT_CLIENT_DATA MQTT_SERVER_DATA MQTT_CLIENT_EGRESS MQTT_SERVER_EGRESS} MQTT::qos 0 2 {*}$args]
    }

    proc mqtt_dup_command {args} {
        return [mqtt_boolean_field_command dup {MQTT_CLIENT_INGRESS MQTT_SERVER_INGRESS MQTT_CLIENT_DATA MQTT_SERVER_DATA MQTT_CLIENT_EGRESS MQTT_SERVER_EGRESS} MQTT::dup {*}$args]
    }

    proc mqtt_retain_command {args} {
        return [mqtt_boolean_field_command retain {MQTT_CLIENT_INGRESS MQTT_SERVER_INGRESS MQTT_CLIENT_DATA MQTT_SERVER_DATA MQTT_CLIENT_EGRESS MQTT_SERVER_EGRESS} MQTT::retain {*}$args]
    }

    proc mqtt_return_code_command {args} {
        return [mqtt_integer_field_command return_code {MQTT_CLIENT_INGRESS MQTT_SERVER_INGRESS MQTT_CLIENT_DATA MQTT_SERVER_DATA MQTT_CLIENT_EGRESS MQTT_SERVER_EGRESS} MQTT::return_code 0 255 {*}$args]
    }

    proc mqtt_session_present_command {args} {
        return [mqtt_boolean_field_command session_present {MQTT_CLIENT_INGRESS MQTT_SERVER_INGRESS MQTT_CLIENT_DATA MQTT_SERVER_DATA MQTT_CLIENT_EGRESS MQTT_SERVER_EGRESS} MQTT::session_present {*}$args]
    }

    proc mqtt_topic_command {args} {
        return [mqtt_field_command topic {MQTT_CLIENT_INGRESS MQTT_SERVER_INGRESS MQTT_CLIENT_DATA MQTT_SERVER_DATA MQTT_CLIENT_EGRESS MQTT_SERVER_EGRESS} MQTT::topic {*}$args]
    }

    proc mqtt_username_command {args} {
        return [mqtt_field_command username {MQTT_CLIENT_INGRESS MQTT_SERVER_INGRESS MQTT_CLIENT_DATA MQTT_SERVER_DATA MQTT_CLIENT_EGRESS MQTT_SERVER_EGRESS} MQTT::username {*}$args]
    }

    proc mqtt_return_code_list_command {args} {
        return [mqtt_field_command return_code_list {MQTT_CLIENT_INGRESS MQTT_SERVER_INGRESS MQTT_CLIENT_DATA MQTT_SERVER_DATA MQTT_CLIENT_EGRESS MQTT_SERVER_EGRESS} MQTT::return_code_list {*}$args]
    }

    proc mqtt_type_command {args} {
        _mqtt_require_event {MQTT_CLIENT_INGRESS MQTT_SERVER_INGRESS MQTT_CLIENT_DATA MQTT_SERVER_DATA MQTT_CLIENT_EGRESS MQTT_SERVER_EGRESS} MQTT::type
        if {[llength $args] != 0} {
            error "MQTT::type takes no arguments"
        }
        return $::state::mqtt::type
    }

    proc mqtt_length_command {args} {
        _mqtt_require_event {MQTT_CLIENT_INGRESS MQTT_SERVER_INGRESS MQTT_CLIENT_DATA MQTT_SERVER_DATA MQTT_CLIENT_EGRESS MQTT_SERVER_EGRESS} MQTT::length
        if {[llength $args] != 0} {
            error "MQTT::length takes no arguments"
        }
        return $::state::mqtt::message_length
    }

    proc mqtt_message_command {args} {
        _mqtt_require_event {MQTT_CLIENT_INGRESS MQTT_SERVER_INGRESS MQTT_CLIENT_DATA MQTT_SERVER_DATA MQTT_CLIENT_EGRESS MQTT_SERVER_EGRESS} MQTT::message
        if {[llength $args] != 0} {
            error "MQTT::message takes no arguments"
        }
        return $::state::mqtt::message
    }

    proc mqtt_collect_command {args} {
        variable mqtt_collection_requested
        variable mqtt_collection_length
        _mqtt_require_event {MQTT_CLIENT_INGRESS MQTT_SERVER_INGRESS MQTT_CLIENT_DATA MQTT_SERVER_DATA} MQTT::collect
        if {[llength $args] > 1} {
            error "MQTT::collect accepts zero or one length"
        }
        set length 0
        if {[llength $args] == 1} {
            set length [lindex $args 0]
            if {![string is integer -strict $length] || $length < 1} {
                error "MQTT::collect length must be a positive integer"
            }
        }
        set mqtt_collection_requested 1
        set mqtt_collection_length $length
        ::itest::log_decision mqtt collect $length
        return ""
    }

    proc mqtt_release_command {args} {
        variable mqtt_collection_requested
        variable mqtt_collection_length
        variable mqtt_release_requested
        _mqtt_require_event {MQTT_CLIENT_DATA MQTT_SERVER_DATA} MQTT::release
        if {[llength $args] != 0} {
            error "MQTT::release takes no arguments"
        }
        set mqtt_collection_requested 0
        set mqtt_collection_length 0
        set mqtt_release_requested 1
        ::itest::log_decision mqtt release
        return ""
    }

    proc mqtt_payload_command {args} {
        _mqtt_require_event {MQTT_CLIENT_DATA MQTT_SERVER_DATA MQTT_CLIENT_INGRESS MQTT_SERVER_INGRESS} MQTT::payload
        set payload $::state::mqtt::payload
        if {[llength $args] == 0} {
            if {$::itest::current_event ni {MQTT_CLIENT_DATA MQTT_SERVER_DATA}} {
                error "MQTT::payload requires a data event"
            }
            return $payload
        }
        if {[llength $args] == 1 && [lindex $args 0] eq "length"} {
            return [::itest::cmd::_payload_bytelength $payload]
        }
        if {[llength $args] != 2 || [lindex $args 0] ni {replace prepend append}} {
            error "unsupported MQTT::payload syntax"
        }
        if {$::itest::current_event ni {MQTT_CLIENT_DATA MQTT_SERVER_DATA}} {
            error "MQTT::payload mutation requires a data event"
        }
        set operation [lindex $args 0]
        set value [::itest::cmd::_payload_bytes [lindex $args 1]]
        switch -exact -- $operation {
            replace { set payload $value }
            prepend { set payload [::itest::cmd::_payload_bytes "${value}${payload}"] }
            append { set payload [::itest::cmd::_payload_bytes "${payload}${value}"] }
        }
        set ::state::mqtt::payload $payload
        set ::state::mqtt::payload_length [::itest::cmd::_payload_bytelength $payload]
        ::itest::log_decision mqtt payload_$operation [lindex $args 1]
        return ""
    }

    proc mqtt_drop_command {args} {
        variable mqtt_dropped
        _mqtt_require_event {MQTT_CLIENT_INGRESS MQTT_SERVER_INGRESS MQTT_CLIENT_DATA MQTT_SERVER_DATA} MQTT::drop
        if {[llength $args] != 0} { error "MQTT::drop takes no arguments" }
        set mqtt_dropped 1
        ::itest::log_decision mqtt drop
        return ""
    }

    proc mqtt_disconnect_command {args} {
        variable mqtt_disconnect_requested
        _mqtt_require_event {MQTT_CLIENT_INGRESS MQTT_SERVER_INGRESS MQTT_CLIENT_DATA MQTT_SERVER_DATA} MQTT::disconnect
        if {[llength $args] != 0} { error "MQTT::disconnect takes no arguments" }
        set mqtt_disconnect_requested 1
        ::itest::log_decision mqtt disconnect
        return ""
    }

    proc mqtt_disable_command {args} {
        variable mqtt_enabled
        _mqtt_require_event {MQTT_CLIENT_INGRESS MQTT_SERVER_INGRESS MQTT_CLIENT_DATA MQTT_SERVER_DATA} MQTT::disable
        if {[llength $args] != 0} { error "MQTT::disable takes no arguments" }
        set mqtt_enabled 0
        ::itest::log_decision mqtt disable
        return ""
    }

    proc mqtt_enable_command {args} {
        variable mqtt_enabled
        _mqtt_require_event {MQTT_CLIENT_INGRESS MQTT_SERVER_INGRESS MQTT_CLIENT_DATA MQTT_SERVER_DATA} MQTT::enable
        if {[llength $args] != 0} { error "MQTT::enable takes no arguments" }
        set mqtt_enabled 1
        ::itest::log_decision mqtt enable
        return ""
    }

    proc sip_reset_connection {} {
        variable sip_discarded
        variable sip_response_requested
        variable sip_response_code
        variable sip_response_phrase
        variable sip_response_headers
        variable sip_persist_key
        variable sip_persist_mode
        variable sip_persist_timeout
        variable sip_persist_bidirectional
        variable sip_persist_direction
        set sip_discarded 0
        set sip_response_requested 0
        set sip_response_code ""
        set sip_response_phrase ""
        set sip_response_headers {}
        set sip_persist_key ""
        set sip_persist_mode use
        set sip_persist_timeout 0
        set sip_persist_bidirectional 0
        set sip_persist_direction detect
        _sip_clear_message_state
    }

    proc _sip_clear_message_state {} {
        foreach {name value} {
            type request
            transport tcp
            method ""
            uri ""
            version SIP/2.0
            status ""
            phrase ""
            headers {}
            payload ""
            payload_length 0
            message ""
            message_length 0
            call_id ""
            from ""
            to ""
            route_status unrouted
            persist_key ""
            record_route {}
            route {}
            via {}
        } {
            set ::state::sip::$name $value
        }
    }

    proc sip_prepare_message {} {
        variable sip_discarded
        variable sip_response_requested
        variable sip_response_code
        variable sip_response_phrase
        variable sip_response_headers
        variable sip_persist_key
        variable sip_persist_mode
        variable sip_persist_timeout
        variable sip_persist_bidirectional
        variable sip_persist_direction
        set sip_discarded 0
        set sip_response_requested 0
        set sip_response_code ""
        set sip_response_phrase ""
        set sip_response_headers {}
        set sip_persist_key ""
        set sip_persist_mode use
        set sip_persist_timeout 0
        set sip_persist_bidirectional 0
        set sip_persist_direction detect
        _sip_clear_message_state
    }

    proc sip_flags_snapshot {} {
        variable sip_discarded
        variable sip_response_requested
        variable sip_response_code
        variable sip_response_phrase
        return [list discarded $sip_discarded responded $sip_response_requested code $sip_response_code phrase $sip_response_phrase]
    }

    proc sip_response_snapshot {} {
        variable sip_response_requested
        variable sip_response_code
        variable sip_response_phrase
        variable sip_response_headers
        return [list requested $sip_response_requested code $sip_response_code phrase $sip_response_phrase headers $sip_response_headers]
    }

    proc _sip_require_event {allowed command_name} {
        if {$::itest::current_event ni $allowed} {
            error "$command_name is not valid during $::itest::current_event"
        }
    }

    proc _sip_header_matches {name wanted} {
        set canonical_name [switch -nocase -exact -- $name {
            b - c { set result content-type }
            e { set result content-encoding }
            f { set result from }
            i { set result call-id }
            k { set result supported }
            l { set result content-length }
            m { set result contact }
            r { set result refer-to }
            s { set result subject }
            t { set result to }
            v { set result via }
            default { set result [string tolower $name] }
        }; set result]
        set canonical_wanted [switch -nocase -exact -- $wanted {
            b - c { set result Content-Type }
            e { set result Content-Encoding }
            f { set result From }
            i { set result Call-ID }
            k { set result Supported }
            l { set result Content-Length }
            m { set result Contact }
            r { set result Refer-To }
            s { set result Subject }
            t { set result To }
            v { set result Via }
            default { set result "" }
        }; set result]
        if {$canonical_wanted eq ""} { set canonical_wanted [string tolower $wanted] }
        return [string equal $canonical_name [string tolower $canonical_wanted]]
    }

    proc _sip_validate_header_name {name} {
        if {![regexp {^[!#$%&'*+.^_`|~0-9A-Za-z-]+$} $name]} {
            error "SIP header name is invalid"
        }
    }

    proc _sip_validate_header_value {value} {
        if {[string first "\r" $value] >= 0 || [string first "\n" $value] >= 0} {
            error "SIP header value must not contain newlines"
        }
    }

    proc _sip_header_indices {wanted} {
        set result {}
        set index 0
        foreach {name value} $::state::sip::headers {
            if {[_sip_header_matches $name $wanted]} { lappend result $index }
            incr index
        }
        return $result
    }

    proc _sip_header_at {wanted index} {
        set matches [_sip_header_indices $wanted]
        if {$index < 0 || $index >= [llength $matches]} { return "" }
        set absolute [lindex $matches $index]
        return [lindex $::state::sip::headers [expr {$absolute * 2 + 1}]]
    }

    proc _sip_header_first {wanted} {
        return [_sip_header_at $wanted 0]
    }

    proc _sip_recompute_derived {} {
        set ::state::sip::call_id [string range [_sip_header_first Call-ID] 0 255]
        set ::state::sip::from [_sip_header_first From]
        set ::state::sip::to [_sip_header_first To]
        set record_route {}
        foreach {name value} $::state::sip::headers {
            if {[_sip_header_matches $name Record-Route]} { lappend record_route $value }
        }
        set ::state::sip::record_route $record_route
        set route {}
        foreach {name value} $::state::sip::headers {
            if {[_sip_header_matches $name Route]} { lappend route $value }
        }
        set ::state::sip::route $route
        set via {}
        foreach {name value} $::state::sip::headers {
            if {[_sip_header_matches $name Via]} { lappend via $value }
        }
        set ::state::sip::via $via
    }

    proc sip_rebuild_message {} {
        _sip_recompute_derived
        set payload $::state::sip::payload
        set header_lines {}
        foreach {name value} $::state::sip::headers {
            if {![_sip_header_matches $name Content-Length]} {
                lappend header_lines "$name: $value"
            }
        }
        lappend header_lines "Content-Length: [string bytelength $payload]"
        if {$::state::sip::type eq "request"} {
            set start "$::state::sip::method $::state::sip::uri $::state::sip::version"
        } else {
            set start "$::state::sip::version $::state::sip::status $::state::sip::phrase"
        }
        set message "$start\r\n[join $header_lines \r\n]\r\n\r\n$payload"
        set ::state::sip::message $message
        set ::state::sip::message_length [string bytelength $message]
        set ::state::sip::payload_length [string bytelength $payload]
        return ""
    }

    proc sip_header_command {args} {
        _sip_require_event {SIP_REQUEST SIP_REQUEST_DONE SIP_REQUEST_SEND SIP_RESPONSE SIP_RESPONSE_DONE SIP_RESPONSE_SEND} SIP::header
        if {[llength $args] == 0} { error "SIP::header requires a name or subcommand" }
        set command [lindex $args 0]
        set rest [lrange $args 1 end]
        switch -exact -- $command {
            value {
                if {[llength $rest] < 1 || [llength $rest] > 2} { error "SIP::header value requires a name and optional index" }
                set index [expr {[llength $rest] == 2 ? [lindex $rest 1] : 0}]
                if {![string is integer -strict $index] || $index < 0} { error "SIP header index must be non-negative" }
                return [_sip_header_at [lindex $rest 0] $index]
            }
            names {
                if {[llength $rest] != 0} { error "SIP::header names takes no arguments" }
                set result {}
                foreach {name value} $::state::sip::headers { lappend result $name }
                return $result
            }
            at {
                if {[llength $rest] != 1 || ![string is integer -strict [lindex $rest 0]] || [lindex $rest 0] < 0} { error "SIP::header at requires a non-negative index" }
                set absolute [expr {[lindex $rest 0] * 2}]
                if {$absolute >= [llength $::state::sip::headers]} { return "" }
                return [lindex $::state::sip::headers $absolute]
            }
            exists {
                if {[llength $rest] != 1} { error "SIP::header exists requires a name" }
                return [expr {[llength [_sip_header_indices [lindex $rest 0]]] > 0}]
            }
            count {
                if {[llength $rest] > 1} { error "SIP::header count accepts zero or one name" }
                if {[llength $rest] == 0} { return [expr {[llength $::state::sip::headers] / 2}] }
                return [llength [_sip_header_indices [lindex $rest 0]]]
            }
            values {
                if {[llength $rest] > 1} { error "SIP::header values accepts zero or one name" }
                set result {}
                if {[llength $rest] == 0} {
                    foreach {name value} $::state::sip::headers { lappend result $value }
                } else {
                    foreach index [_sip_header_indices [lindex $rest 0]] {
                        lappend result [lindex $::state::sip::headers [expr {$index * 2 + 1}]]
                    }
                }
                return $result
            }
            insert - replace - remove {
                if {$command eq "remove"} {
                    if {[llength $rest] < 1 || [llength $rest] > 2} { error "SIP::header remove requires a name and optional index" }
                    set name [lindex $rest 0]
                    set value ""
                    set supplied_index [expr {[llength $rest] == 2 ? [lindex $rest 1] : 0}]
                } else {
                    if {[llength $rest] < 2 || [llength $rest] > 3} { error "SIP::header $command requires name, value, and optional index" }
                    set name [lindex $rest 0]
                    set value [lindex $rest 1]
                    set supplied_index [expr {[llength $rest] == 3 ? [lindex $rest 2] : -1}]
                }
                _sip_validate_header_name $name
                if {$command ne "remove"} { _sip_validate_header_value $value }
                if {$supplied_index < -1 || ![string is integer -strict $supplied_index]} { error "SIP header index must be an integer" }
                set matches [_sip_header_indices $name]
                if {$command eq "remove"} {
                    if {[llength $matches] > $supplied_index} {
                        set absolute [lindex $matches $supplied_index]
                        set ::state::sip::headers [lreplace $::state::sip::headers [expr {$absolute * 2}] [expr {$absolute * 2 + 1}]]
                    }
                } elseif {$command eq "replace"} {
                    set target [expr {$supplied_index >= 0 ? ($supplied_index < [llength $matches] ? [lindex $matches $supplied_index] : -1) : ([llength $matches] ? [lindex $matches 0] : -1)}]
                    if {$target < 0} {
                        lappend ::state::sip::headers $name $value
                    } else {
                        lset ::state::sip::headers [expr {$target * 2}] $name
                        lset ::state::sip::headers [expr {$target * 2 + 1}] $value
                    }
                } else {
                    if {$supplied_index < 0} {
                        if {[llength $matches] > 0} {
                            set absolute [lindex $matches 0]
                            set ::state::sip::headers [linsert $::state::sip::headers [expr {$absolute * 2}] $name $value]
                        } elseif {[_sip_header_matches $name Via]} {
                            set ::state::sip::headers [linsert $::state::sip::headers 0 $name $value]
                        } else {
                            lappend ::state::sip::headers $name $value
                        }
                    } else {
                        set absolute [expr {$supplied_index * 2}]
                        set ::state::sip::headers [linsert $::state::sip::headers $absolute $name $value]
                    }
                }
                sip_rebuild_message
                ::itest::log_decision sip header_$command [list $name $value]
                return ""
            }
            default {
                if {[llength $rest] > 1} { error "SIP::header shorthand accepts a name and optional index" }
                set index [expr {[llength $rest] == 1 ? [lindex $rest 0] : 0}]
                if {![string is integer -strict $index] || $index < 0} { error "SIP header index must be non-negative" }
                return [_sip_header_at $command $index]
            }
        }
    }

    proc sip_simple_header_command {field header args} {
        _sip_require_event {SIP_REQUEST SIP_REQUEST_DONE SIP_REQUEST_SEND SIP_RESPONSE SIP_RESPONSE_DONE SIP_RESPONSE_SEND} SIP::$field
        if {[llength $args] != 0} { error "SIP::$field takes no arguments" }
        return [_sip_header_first $header]
    }

    proc sip_call_id_command {args} { return [sip_simple_header_command call_id Call-ID {*}$args] }
    proc sip_from_command {args} { return [sip_simple_header_command from From {*}$args] }
    proc sip_to_command {args} { return [sip_simple_header_command to To {*}$args] }
    proc sip_method_command {args} {
        _sip_require_event {SIP_REQUEST SIP_REQUEST_DONE SIP_REQUEST_SEND SIP_RESPONSE SIP_RESPONSE_DONE SIP_RESPONSE_SEND} SIP::method
        if {[llength $args] != 0} { error "SIP::method takes no arguments" }
        return $::state::sip::method
    }
    proc sip_message_command {args} {
        _sip_require_event {SIP_REQUEST SIP_REQUEST_DONE SIP_REQUEST_SEND SIP_RESPONSE SIP_RESPONSE_DONE SIP_RESPONSE_SEND} SIP::message
        if {[llength $args] != 0} { error "SIP::message takes no arguments" }
        return $::state::sip::message
    }
    proc sip_uri_command {args} {
        _sip_require_event {SIP_REQUEST SIP_REQUEST_DONE SIP_REQUEST_SEND SIP_RESPONSE SIP_RESPONSE_DONE SIP_RESPONSE_SEND} SIP::uri
        if {[llength $args] > 1} { error "SIP::uri accepts zero or one argument" }
        if {[llength $args] == 0} { return $::state::sip::uri }
        set value [lindex $args 0]
        if {[string first "\r" $value] >= 0 || [string first "\n" $value] >= 0 || [string first " " $value] >= 0} { error "SIP::uri contains invalid whitespace" }
        set ::state::sip::uri $value
        sip_rebuild_message
        ::itest::log_decision sip uri_set $value
        return $value
    }

    proc sip_payload_command {args} {
        _sip_require_event {SIP_REQUEST SIP_REQUEST_DONE SIP_REQUEST_SEND SIP_RESPONSE SIP_RESPONSE_DONE SIP_RESPONSE_SEND} SIP::payload
        set payload $::state::sip::payload
        if {[llength $args] == 0} { return $payload }
        if {[llength $args] == 1 && [lindex $args 0] eq "length"} { return [::itest::cmd::_payload_bytelength $payload] }
        if {[llength $args] == 1 || [llength $args] == 2} {
            foreach value $args { if {![string is integer -strict $value] || $value < 0} { error "SIP::payload offsets and lengths must be non-negative integers" } }
            set offset [lindex $args 0]
            set length [expr {[llength $args] == 1 ? $offset : [lindex $args 1]}]
            if {[llength $args] == 1} { set offset 0 }
            if {$length == 0} { return [::itest::cmd::_payload_bytes ""] }
            return [string range [::itest::cmd::_payload_bytes $payload] $offset [expr {$offset + $length - 1}]]
        }
        set operation [lindex $args 0]
        if {$operation eq "replace" && [llength $args] == 4} {
            set offset [lindex $args 1]; set length [lindex $args 2]; set value [lindex $args 3]
            if {![string is integer -strict $offset] || $offset < 0 || ![string is integer -strict $length] || $length < 0} { error "SIP::payload replace offsets and lengths must be non-negative integers" }
            set payload [::itest::cmd::_payload_splice $payload $offset $length $value]
        } elseif {$operation eq "insert" && [llength $args] == 3} {
            set offset [lindex $args 1]
            if {![string is integer -strict $offset] || $offset < 0} { error "SIP::payload insert offset must be non-negative" }
            set payload [::itest::cmd::_payload_splice $payload $offset 0 [lindex $args 2]]
        } elseif {$operation eq "delete" && [llength $args] == 3} {
            set offset [lindex $args 1]; set length [lindex $args 2]
            if {![string is integer -strict $offset] || $offset < 0 || ![string is integer -strict $length] || $length < 0} { error "SIP::payload delete offsets and lengths must be non-negative integers" }
            set payload [::itest::cmd::_payload_splice $payload $offset $length ""]
        } else { error "unsupported SIP::payload syntax" }
        set ::state::sip::payload $payload
        sip_rebuild_message
        ::itest::log_decision sip payload_$operation
        return ""
    }

    proc sip_response_command {args} {
        variable sip_response_code
        variable sip_response_phrase
        _sip_require_event {SIP_RESPONSE SIP_RESPONSE_DONE SIP_RESPONSE_SEND} SIP::response
        if {[llength $args] == 1 && [lindex $args 0] in {code phrase}} {
            return [expr {[lindex $args 0] eq "code" ? $::state::sip::status : $::state::sip::phrase}]
        }
        if {[llength $args] < 2 || [lindex $args 0] ne "rewrite"} { error "SIP::response syntax is code, phrase, or rewrite code phrase" }
        set code [lindex $args 1]
        if {![string is integer -strict $code] || $code < 100 || $code > 699} { error "SIP response code must be between 100 and 699" }
        set phrase [expr {[llength $args] > 2 ? [lindex $args 2] : $::state::sip::phrase}]
        set ::state::sip::status $code
        set ::state::sip::phrase $phrase
        sip_rebuild_message
        ::itest::log_decision sip response_rewrite [list $code $phrase]
        return ""
    }

    proc sip_respond_command {args} {
        variable sip_response_requested
        variable sip_response_code
        variable sip_response_phrase
        variable sip_response_headers
        _sip_require_event {SIP_REQUEST SIP_REQUEST_SEND} SIP::respond
        if {[llength $args] < 2 || (([llength $args] - 2) % 2) != 0} { error "SIP::respond requires code, phrase, and optional header pairs" }
        set code [lindex $args 0]
        if {![string is integer -strict $code] || $code < 100 || $code > 699} { error "SIP response code must be between 100 and 699" }
        _sip_validate_header_value [lindex $args 1]
        foreach {header_name header_value} [lrange $args 2 end] {
            _sip_validate_header_name $header_name
            _sip_validate_header_value $header_value
        }
        set sip_response_code $code
        set sip_response_phrase [lindex $args 1]
        set sip_response_headers [lrange $args 2 end]
        set sip_response_requested 1
        ::itest::log_decision sip respond [list $code $sip_response_phrase $sip_response_headers]
        return ""
    }

    proc sip_discard_command {args} {
        variable sip_discarded
        _sip_require_event {SIP_REQUEST SIP_REQUEST_SEND SIP_RESPONSE SIP_RESPONSE_SEND} SIP::discard
        if {[llength $args] != 0} { error "SIP::discard takes no arguments" }
        set sip_discarded 1
        ::itest::log_decision sip discard
        return ""
    }

    proc sip_persist_command {args} {
        variable sip_persist_key
        variable sip_persist_mode
        variable sip_persist_timeout
        variable sip_persist_bidirectional
        variable sip_persist_direction
        _sip_require_event {SIP_REQUEST SIP_REQUEST_SEND SIP_RESPONSE SIP_RESPONSE_SEND} SIP::persist
        if {[llength $args] == 0} { return $sip_persist_key }
        set command [lindex $args 0]
        if {$command in {reset use ignore bypass replace}} {
            if {[llength $args] != 1} { error "SIP::persist $command takes no arguments" }
            set sip_persist_mode $command
            if {$command eq "reset"} { set sip_persist_key "" }
        } elseif {$command eq "timeout"} {
            if {[llength $args] > 2} { error "SIP::persist timeout accepts zero or one value" }
            if {[llength $args] == 1} { return $sip_persist_timeout }
            if {![string is integer -strict [lindex $args 1]] || [lindex $args 1] < 0} { error "SIP persistence timeout must be non-negative" }
            set sip_persist_timeout [lindex $args 1]
        } elseif {$command eq "bidirectional"} {
            if {[llength $args] == 1} { return $sip_persist_bidirectional }
            if {[llength $args] != 2 || [lindex $args 1] ni {0 1 true false}} { error "SIP::persist bidirectional accepts a boolean" }
            set sip_persist_bidirectional [expr {[lindex $args 1] in {1 true}}]
        } elseif {$command eq "direction"} {
            if {[llength $args] == 1} { return $sip_persist_direction }
            if {[llength $args] != 2 || [lindex $args 1] ni {detect forward reverse}} { error "SIP persistence direction must be detect, forward, or reverse" }
            set sip_persist_direction [lindex $args 1]
        } else {
            if {[llength $args] > 2} { error "SIP::persist accepts a key and optional timeout" }
            set sip_persist_key $command
            if {[llength $args] == 2} {
                if {![string is integer -strict [lindex $args 1]] || [lindex $args 1] < 0} { error "SIP persistence timeout must be non-negative" }
                set sip_persist_timeout [lindex $args 1]
            }
        }
        set ::state::sip::persist_key $sip_persist_key
        ::itest::log_decision sip persist $args
        return $sip_persist_key
    }

    proc sip_route_status_command {args} {
        _sip_require_event {SIP_REQUEST SIP_REQUEST_DONE SIP_REQUEST_SEND SIP_RESPONSE SIP_RESPONSE_DONE SIP_RESPONSE_SEND} SIP::route_status
        if {[llength $args] != 0} { error "SIP::route_status takes no arguments" }
        return $::state::sip::route_status
    }

    proc _sip_list_header_command {field header args} {
        _sip_require_event {SIP_REQUEST SIP_REQUEST_DONE SIP_REQUEST_SEND SIP_RESPONSE SIP_RESPONSE_DONE SIP_RESPONSE_SEND} SIP::$field
        if {[llength $args] > 1} { error "SIP::$field accepts zero or one index" }
        set index [expr {[llength $args] == 1 ? [lindex $args 0] : 0}]
        if {![string is integer -strict $index] || $index < 0} { error "SIP::$field index must be non-negative" }
        return [_sip_header_at $header $index]
    }
    proc sip_record_route_command {args} { return [_sip_list_header_command record-route Record-Route {*}$args] }
    proc sip_route_command {args} { return [_sip_list_header_command route Route {*}$args] }

    proc sip_via_command {args} {
        _sip_require_event {SIP_REQUEST SIP_REQUEST_DONE SIP_REQUEST_SEND SIP_RESPONSE SIP_RESPONSE_DONE SIP_RESPONSE_SEND} SIP::via
        if {[llength $args] > 2} { error "SIP::via accepts a field and optional index" }
        set field ""
        set index 0
        if {[llength $args] == 1} {
            if {[string is integer -strict [lindex $args 0]]} { set index [lindex $args 0] } else { set field [lindex $args 0] }
        } elseif {[llength $args] == 2} { set field [lindex $args 0]; set index [lindex $args 1] }
        if {![string is integer -strict $index] || $index < 0} { error "SIP::via index must be non-negative" }
        set value [_sip_header_at Via $index]
        if {$field eq ""} { return $value }
        if {$value eq ""} { return "" }
        set parts [split $value ";"]
        set sent_by [string trim [lindex [split [lindex $parts 0]] 1]]
        set protocol_parts [split [lindex [split [lindex $parts 0]] 0] /]
        set proto [lindex $protocol_parts end]
        if {$field eq "proto"} { return $proto }
        if {$field eq "sent_by"} { return $sent_by }
        if {$field ni {received branch maddr ttl}} { error "SIP::via field must be proto, sent_by, received, branch, maddr, or ttl" }
        foreach parameter [lrange $parts 1 end] {
            set separator [string first = $parameter]
            if {$separator < 0} {
                set parameter_name [string trim $parameter]
                set parameter_value ""
            } else {
                set parameter_name [string trim [string range $parameter 0 [expr {$separator - 1}]]]
                set parameter_value [string trim [string range $parameter [expr {$separator + 1}] end]]
            }
            if {[string equal -nocase $parameter_name $field]} { return $parameter_value }
        }
        return ""
    }

    proc diameter_reset_connection {} {
        variable diameter_dropped
        variable diameter_responded
        variable diameter_response_args
        variable diameter_retransmission_action
        variable diameter_retransmission_default
        variable diameter_raw_payload
        variable diameter_disconnected
        variable diameter_dynamic_lookup_connection
        variable diameter_dynamic_lookup_message
        variable diameter_dynamic_insertion
        set diameter_dropped 0
        set diameter_responded 0
        set diameter_response_args {}
        set diameter_retransmission_action retransmit
        set diameter_retransmission_default retransmit
        set diameter_raw_payload 0
        set diameter_disconnected 0
        set diameter_dynamic_lookup_connection 1
        set diameter_dynamic_lookup_message 1
        set diameter_dynamic_insertion 1
        diameter_clear_message
    }

    proc diameter_clear_message {} {
        foreach {name value} {
            type request
            version 1
            rflag 1
            pflag 0
            eflag 0
            tflag 0
            command_code 0
            application_id 0
            hop_by_hop_id 0
            end_to_end_id 0
            avps {}
            payload ""
            payload_length 0
            payload_hex ""
            message ""
            message_length 20
            message_hex ""
            route_status unrouted
            persist_key ""
        } {
            set ::state::diameter::$name $value
        }
        set ::itest::semantic::diameter_raw_payload 0
    }

    proc diameter_prepare_message {} {
        variable diameter_dropped
        variable diameter_responded
        variable diameter_response_args
        variable diameter_disconnected
        set diameter_dropped 0
        set diameter_responded 0
        set diameter_response_args {}
        set diameter_disconnected 0
        diameter_clear_message
    }

    proc diameter_flags_snapshot {} {
        variable diameter_dropped
        variable diameter_responded
        variable diameter_response_args
        variable diameter_disconnected
        return [list dropped $diameter_dropped responded $diameter_responded response $diameter_response_args disconnected $diameter_disconnected]
    }

    proc diameter_response_snapshot {} {
        variable diameter_responded
        variable diameter_response_args
        return [list requested $diameter_responded args $diameter_response_args]
    }

    proc _diameter_require_event {allowed command_name} {
        if {$::itest::current_event ni $allowed} {
            error "$command_name is not valid during $::itest::current_event"
        }
    }

    proc _diameter_int {value field maximum} {
        if {![string is integer -strict $value] || $value < 0 || $value > $maximum} {
            error "Diameter $field must be an integer from 0 to $maximum"
        }
        return $value
    }

    proc _diameter_hex_uint {value width field maximum} {
        return [format %0*X $width [_diameter_int $value $field $maximum]]
    }

    proc _diameter_record_data {record} {
        set raw [lindex $record 3]
        if {$raw eq ""} { return [::itest::cmd::_payload_bytes ""] }
        return [binary format H* $raw]
    }

    proc _diameter_record_wire {record} {
        set code [_diameter_hex_uint [lindex $record 0] 8 code 0xffffffff]
        set flags [_diameter_int [lindex $record 1] flags 255]
        set vendor [_diameter_int [lindex $record 2] vendor_id 0xffffffff]
        if {$vendor} { set flags [expr {$flags | 0x80}] }
        set data [_diameter_record_data $record]
        set header_length [expr {($flags & 0x80) ? 12 : 8}]
        set length [expr {$header_length + [string length $data]}]
        if {$length > 0xffffff} { error "Diameter AVP length exceeds wire limit" }
        set result "${code}[format %02X $flags][format %06X $length]"
        if {$flags & 0x80} { append result [_diameter_hex_uint $vendor 8 vendor_id 0xffffffff] }
        append result [binary encode hex $data]
        while {[string length $result] % 8} { append result 00 }
        return $result
    }

    proc diameter_rebuild_message {} {
        set version [_diameter_int $::state::diameter::version version 255]
        set flags 0
        if {$::state::diameter::rflag} { set flags [expr {$flags | 0x80}] }
        if {$::state::diameter::pflag} { set flags [expr {$flags | 0x40}] }
        if {$::state::diameter::eflag} { set flags [expr {$flags | 0x20}] }
        if {$::state::diameter::tflag} { set flags [expr {$flags | 0x10}] }
        if {$::itest::semantic::diameter_raw_payload} {
            set payload [::itest::cmd::_payload_bytes $::state::diameter::payload]
        } else {
            set payload ""
            foreach record $::state::diameter::avps {
                append payload [binary decode hex [_diameter_record_wire $record]]
            }
        }
        set length [expr {20 + [string length $payload]}]
        if {$length > 0xffffff} { error "Diameter message length exceeds wire limit" }
        set header [format %02X%06X%02X $version $length $flags]
        append header [_diameter_hex_uint $::state::diameter::command_code 6 command_code 0xffffff]
        append header [_diameter_hex_uint $::state::diameter::application_id 8 application_id 0xffffffff]
        append header [_diameter_hex_uint $::state::diameter::hop_by_hop_id 8 hop_by_hop_id 0xffffffff]
        append header [_diameter_hex_uint $::state::diameter::end_to_end_id 8 end_to_end_id 0xffffffff]
        set message [binary decode hex $header]
        append message $payload
        set ::state::diameter::message $message
        set ::state::diameter::payload $payload
        set ::state::diameter::payload_length [string length $payload]
        set ::state::diameter::payload_hex [binary encode hex $payload]
        set ::state::diameter::message_length [string length $message]
        set ::state::diameter::message_hex [binary encode hex $message]
        return ""
    }

    proc _diameter_indices {code {vendor 0}} {
        set result {}
        set index 0
        foreach record $::state::diameter::avps {
            if {[lindex $record 0] == $code && [lindex $record 2] == $vendor} {
                lappend result $index
            }
            incr index
        }
        return $result
    }

    proc _diameter_selector {args} {
        if {[llength $args] < 1 || [llength $args] > 3} {
            error "Diameter AVP selector requires code, optional vendor_id, and optional index"
        }
        set code [lindex $args 0]
        if {![string is integer -strict $code] || $code < 0 || $code > 0xffffffff} {
            error "Diameter AVP code must be an integer"
        }
        set vendor [expr {[llength $args] > 1 ? [lindex $args 1] : 0}]
        set index [expr {[llength $args] > 2 ? [lindex $args 2] : 0}]
        if {![string is integer -strict $vendor] || $vendor < 0 || $vendor > 0xffffffff} {
            error "Diameter AVP vendor_id must be an integer"
        }
        if {![string is integer -strict $index] || $index < 0} {
            error "Diameter AVP index must be non-negative"
        }
        set matches [_diameter_indices $code $vendor]
        if {$index >= [llength $matches]} { return -1 }
        return [lindex $matches $index]
    }

    proc _diameter_data_hex {value} {
        return [binary encode hex [::itest::cmd::_payload_bytes $value]]
    }

    proc _diameter_set_record {absolute record} {
        set ::state::diameter::avps [lreplace $::state::diameter::avps $absolute $absolute $record]
        set ::itest::semantic::diameter_raw_payload 0
        diameter_rebuild_message
    }

    proc diameter_header_command {args} {
        _diameter_require_event {DIAMETER_INGRESS DIAMETER_EGRESS DIAMETER_RETRANSMISSION} DIAMETER::header
        if {[llength $args] < 1 || [llength $args] > 2} { error "DIAMETER::header requires a field and optional value" }
        set field [string tolower [lindex $args 0]]
        array set aliases {
            command command_code cmd command_code appid application_id app_id application_id
            hopid hop_by_hop_id hop_by_hop_id hop_by_hop_id endid end_to_end_id end_to_end_id end_to_end_id
        }
        if {[info exists aliases($field)]} { set field $aliases($field) }
        if {$field ni {version length rflag pflag eflag tflag command_code application_id hop_by_hop_id end_to_end_id}} {
            error "unsupported DIAMETER::header field $field"
        }
        if {[llength $args] == 1} { return [set ::state::diameter::$field] }
        if {$field eq "length"} { error "DIAMETER::header length is read-only" }
        set value [lindex $args 1]
        if {$field in {rflag pflag eflag tflag}} {
            if {$value ni {0 1 true false}} { error "Diameter header flags accept a boolean" }
            set value [expr {$value in {1 true}}]
        } elseif {$field eq "version"} {
            set value [_diameter_int $value version 255]
        } elseif {$field eq "command_code"} {
            set value [_diameter_int $value command_code 0xffffff]
        } else {
            set value [_diameter_int $value $field 0xffffffff]
        }
        set ::state::diameter::$field $value
        diameter_rebuild_message
        ::itest::log_decision diameter header_set [list $field $value]
        return $value
    }

    proc diameter_avp_command {args} {
        _diameter_require_event {DIAMETER_INGRESS DIAMETER_EGRESS DIAMETER_RETRANSMISSION} DIAMETER::avp
        if {[llength $args] < 1} { error "DIAMETER::avp requires a subcommand" }
        set operation [lindex $args 0]
        set rest [lrange $args 1 end]
        switch -exact -- $operation {
            count {
                if {[llength $rest] < 1 || [llength $rest] > 2} { error "DIAMETER::avp count requires code and optional vendor_id" }
                return [llength [_diameter_indices [lindex $rest 0] [expr {[llength $rest] == 2 ? [lindex $rest 1] : 0}]]]
            }
            create - append {
                if {[llength $rest] < 2 || [llength $rest] > 3} { error "DIAMETER::avp $operation requires code, data, and optional vendor_id" }
                set code [lindex $rest 0]
                set data [lindex $rest 1]
                set vendor [expr {[llength $rest] == 3 ? [lindex $rest 2] : 0}]
                set record [list [_diameter_int $code code 0xffffffff] 0 [_diameter_int $vendor vendor_id 0xffffffff] [_diameter_data_hex $data]]
                lappend ::state::diameter::avps $record
                set ::itest::semantic::diameter_raw_payload 0
                diameter_rebuild_message
                ::itest::log_decision diameter avp_$operation $record
                return [llength $::state::diameter::avps]
            }
            insert {
                if {[llength $rest] < 3 || [llength $rest] > 4} { error "DIAMETER::avp insert requires position, code, data, and optional vendor_id" }
                set position [_diameter_int [lindex $rest 0] position [llength $::state::diameter::avps]]
                set vendor [expr {[llength $rest] == 4 ? [lindex $rest 3] : 0}]
                set record [list [_diameter_int [lindex $rest 1] code 0xffffffff] 0 [_diameter_int $vendor vendor_id 0xffffffff] [_diameter_data_hex [lindex $rest 2]]]
                set ::state::diameter::avps [linsert $::state::diameter::avps $position $record]
                set ::itest::semantic::diameter_raw_payload 0
                diameter_rebuild_message
                return [llength $::state::diameter::avps]
            }
            delete {
                set absolute [_diameter_selector $rest]
                if {$absolute >= 0} {
                    set ::state::diameter::avps [lreplace $::state::diameter::avps $absolute $absolute]
                    diameter_rebuild_message
                }
                return ""
            }
            replace {
                if {[llength $rest] < 2 || [llength $rest] > 4} { error "DIAMETER::avp replace requires code, data, and optional vendor_id/index" }
                set code [lindex $rest 0]
                set data [lindex $rest 1]
                set selector [linsert [lrange $rest 2 end] 0 $code]
                set absolute [_diameter_selector $selector]
                if {$absolute < 0} { error "Diameter AVP was not found" }
                set old [lindex $::state::diameter::avps $absolute]
                _diameter_set_record $absolute [list [lindex $old 0] [lindex $old 1] [lindex $old 2] [_diameter_data_hex $data]]
                return ""
            }
            flags {
                if {[llength $rest] < 2 || [lindex $rest 0] ni {get set}} { error "DIAMETER::avp flags syntax is get|set code ?value? ?vendor_id? ?index?" }
                set action [lindex $rest 0]
                set selector [lrange $rest 1 end]
                if {$action eq "set"} {
                    if {[llength $selector] < 2 || [llength $selector] > 4} { error "DIAMETER::avp flags set requires code and value" }
                    set value [_diameter_int [lindex $selector 1] flags 255]
                    set selector [linsert [lrange $selector 2 end] 0 [lindex $selector 0]]
                } elseif {[llength $selector] < 1 || [llength $selector] > 3} { error "DIAMETER::avp flags get requires code" }
                set absolute [_diameter_selector $selector]
                if {$absolute < 0} { return "" }
                set old [lindex $::state::diameter::avps $absolute]
                if {$action eq "get"} { return [lindex $old 1] }
                _diameter_set_record $absolute [list [lindex $old 0] $value [lindex $old 2] [lindex $old 3]]
                return $value
            }
            code - length - data {
                set absolute [_diameter_selector $rest]
                if {$absolute < 0} { return "" }
                set record [lindex $::state::diameter::avps $absolute]
                if {$operation eq "code"} { return [lindex $record 0] }
                if {$operation eq "data"} { return [_diameter_record_data $record] }
                return [expr {(([lindex $record 1] & 0x80) ? 12 : 8) + [string length [_diameter_record_data $record]]}]
            }
            default { error "unsupported DIAMETER::avp operation $operation" }
        }
    }

    proc _diameter_simple_command {name args} {
        _diameter_require_event {DIAMETER_INGRESS DIAMETER_EGRESS DIAMETER_RETRANSMISSION} $name
        if {[llength $args] != 0} { error "$name takes no arguments" }
        switch -exact -- $name {
            DIAMETER::length { return $::state::diameter::message_length }
            DIAMETER::message { return $::state::diameter::message }
            DIAMETER::is_request { return $::state::diameter::rflag }
            DIAMETER::is_retransmission { return $::state::diameter::tflag }
            DIAMETER::route_status { return $::state::diameter::route_status }
            DIAMETER::retransmission_reason { return [expr {$::state::diameter::tflag ? "timeout" : ""}] }
            default { error "unsupported Diameter simple command $name" }
        }
    }

    proc diameter_command_command {args} {
        _diameter_require_event {DIAMETER_INGRESS DIAMETER_EGRESS DIAMETER_RETRANSMISSION} DIAMETER::command
        if {[llength $args] > 1} { error "DIAMETER::command accepts zero or one value" }
        if {[llength $args] == 0} { return $::state::diameter::command_code }
        set ::state::diameter::command_code [_diameter_int [lindex $args 0] command_code 0xffffff]
        diameter_rebuild_message
        return $::state::diameter::command_code
    }

    proc diameter_length_command {args} { return [_diameter_simple_command DIAMETER::length {*}$args] }
    proc diameter_message_command {args} { return [_diameter_simple_command DIAMETER::message {*}$args] }
    proc diameter_is_request_command {args} { return [_diameter_simple_command DIAMETER::is_request {*}$args] }
    proc diameter_is_response_command {args} {
        _diameter_require_event {DIAMETER_INGRESS DIAMETER_EGRESS DIAMETER_RETRANSMISSION} DIAMETER::is_response
        if {[llength $args] != 0} { error "DIAMETER::is_response takes no arguments" }
        return [expr {!$::state::diameter::rflag}]
    }
    proc diameter_is_retransmission_command {args} { return [_diameter_simple_command DIAMETER::is_retransmission {*}$args] }

    proc diameter_payload_command {args} {
        _diameter_require_event {DIAMETER_INGRESS DIAMETER_EGRESS DIAMETER_RETRANSMISSION} DIAMETER::payload
        if {[llength $args] == 0} { return $::state::diameter::payload }
        if {[llength $args] != 2 || [lindex $args 0] ne "replace"} { error "DIAMETER::payload syntax is replace payload" }
        set ::state::diameter::payload [::itest::cmd::_payload_bytes [lindex $args 1]]
        set ::itest::semantic::diameter_raw_payload 1
        diameter_rebuild_message
        ::itest::log_decision diameter payload_replace
        return ""
    }

    proc _diameter_find_data {code} {
        set absolute [_diameter_selector [list $code]]
        if {$absolute < 0} { return "" }
        return [_diameter_record_data [lindex $::state::diameter::avps $absolute]]
    }

    proc _diameter_set_data {code value} {
        set absolute [_diameter_selector [list $code]]
        set data_hex [_diameter_data_hex $value]
        if {$absolute < 0} {
            lappend ::state::diameter::avps [list $code 0 0 $data_hex]
        } else {
            set old [lindex $::state::diameter::avps $absolute]
            set ::state::diameter::avps [lreplace $::state::diameter::avps $absolute $absolute [list [lindex $old 0] [lindex $old 1] [lindex $old 2] $data_hex]]
        }
        set ::itest::semantic::diameter_raw_payload 0
        diameter_rebuild_message
        return $value
    }

    proc diameter_result_command {args} {
        _diameter_require_event {DIAMETER_INGRESS DIAMETER_EGRESS DIAMETER_RETRANSMISSION} DIAMETER::result
        if {[llength $args] == 0} {
            set data [_diameter_find_data 268]
            if {[string length $data] != 4} { return "" }
            scan [binary encode hex $data] %x value
            return $value
        }
        if {[llength $args] != 1} { error "DIAMETER::result accepts zero or one value" }
        set value [_diameter_int [lindex $args 0] result 0xffffffff]
        return [_diameter_set_data 268 [binary decode hex [_diameter_hex_uint $value 8 result 0xffffffff]]]
    }

    proc diameter_session_command {args} {
        _diameter_require_event {DIAMETER_INGRESS DIAMETER_EGRESS DIAMETER_RETRANSMISSION} DIAMETER::session
        if {[llength $args] == 0} { return [_diameter_find_data 263] }
        if {[llength $args] != 1} { error "DIAMETER::session accepts zero or one value" }
        return [_diameter_set_data 263 [lindex $args 0]]
    }

    proc _diameter_host_realm_command {code args} {
        _diameter_require_event {DIAMETER_INGRESS DIAMETER_EGRESS DIAMETER_RETRANSMISSION} DIAMETER::host
        if {[llength $args] < 1 || [llength $args] > 2 || [lindex $args 0] ni {origin dest}} { error "DIAMETER::host/realm requires origin or dest and optional value" }
        set selector [lindex $args 0]
        set value_code [expr {$code == 264 ? ($selector eq "origin" ? 264 : 293) : ($selector eq "origin" ? 296 : 283)}]
        if {[llength $args] == 1} { return [_diameter_find_data $value_code] }
        return [_diameter_set_data $value_code [lindex $args 1]]
    }
    proc diameter_host_command {args} { return [_diameter_host_realm_command 264 {*}$args] }
    proc diameter_realm_command {args} { return [_diameter_host_realm_command 296 {*}$args] }

    proc diameter_route_status_command {args} { return [_diameter_simple_command DIAMETER::route_status {*}$args] }
    proc diameter_state_command {args} {
        _diameter_require_event {DIAMETER_INGRESS DIAMETER_EGRESS DIAMETER_RETRANSMISSION} DIAMETER::state
        if {[llength $args] != 0} { error "DIAMETER::state takes no arguments" }
        return up
    }

    proc diameter_persist_command {args} {
        variable diameter_persist_mode
        _diameter_require_event {DIAMETER_INGRESS DIAMETER_EGRESS DIAMETER_RETRANSMISSION} DIAMETER::persist
        if {[llength $args] == 0} { return $::state::diameter::persist_key }
        set command [lindex $args 0]
        if {$command in {reset use ignore bypass replace}} {
            if {[llength $args] != 1} { error "DIAMETER::persist $command takes no arguments" }
            set diameter_persist_mode $command
            if {$command eq "reset"} { set ::state::diameter::persist_key "" }
        } else {
            if {[llength $args] > 2} { error "DIAMETER::persist accepts a key and optional timeout" }
            set ::state::diameter::persist_key $command
        }
        ::itest::log_decision diameter persist $args
        return $::state::diameter::persist_key
    }

    proc diameter_drop_command {args} {
        variable diameter_dropped
        _diameter_require_event {DIAMETER_INGRESS DIAMETER_EGRESS DIAMETER_RETRANSMISSION} DIAMETER::drop
        if {[llength $args] != 0} { error "DIAMETER::drop takes no arguments" }
        set diameter_dropped 1
        ::itest::log_decision diameter drop
        return ""
    }

    proc diameter_respond_command {args} {
        variable diameter_responded
        variable diameter_response_args
        _diameter_require_event {DIAMETER_INGRESS DIAMETER_EGRESS} DIAMETER::respond
        if {[llength $args] != 5} { error "DIAMETER::respond requires version, rflag, pflag, eflag, and tflag" }
        set version [_diameter_int [lindex $args 0] version 255]
        set flags {}
        foreach {name value} {rflag 1 pflag 2 eflag 3 tflag 4} {
            set raw [lindex $args $value]
            if {$raw ni {0 1 true false}} { error "Diameter $name accepts a boolean" }
            lappend flags [expr {$raw in {1 true}}]
        }
        set ::state::diameter::version $version
        lassign $flags ::state::diameter::rflag ::state::diameter::pflag ::state::diameter::eflag ::state::diameter::tflag
        diameter_rebuild_message
        set diameter_response_args $args
        set diameter_responded 1
        ::itest::log_decision diameter respond $args
        return ""
    }

    proc diameter_retransmission_command {args} {
        variable diameter_retransmission_action
        _diameter_require_event {DIAMETER_INGRESS DIAMETER_EGRESS DIAMETER_RETRANSMISSION} DIAMETER::retransmission
        if {[llength $args] == 0} { return $diameter_retransmission_action }
        if {[llength $args] != 2 || [lindex $args 0] ne "action" || [lindex $args 1] ni {disabled busy unable retransmit}} { error "DIAMETER::retransmission syntax is action disabled|busy|unable|retransmit" }
        set diameter_retransmission_action [lindex $args 1]
        ::itest::log_decision diameter retransmission $diameter_retransmission_action
        return $diameter_retransmission_action
    }
    proc diameter_retransmission_default_command {args} {
        variable diameter_retransmission_default
        _diameter_require_event {CLIENT_ACCEPTED SERVER_CONNECTED} DIAMETER::retransmission_default
        if {[llength $args] == 0} { return $diameter_retransmission_default }
        if {[llength $args] != 2 || [lindex $args 0] ne "action" || [lindex $args 1] ni {disabled busy unable retransmit}} { error "DIAMETER::retransmission_default syntax is action disabled|busy|unable|retransmit" }
        set diameter_retransmission_default [lindex $args 1]
        return $diameter_retransmission_default
    }
    proc diameter_retransmission_reason_command {args} { return [_diameter_simple_command DIAMETER::retransmission_reason {*}$args] }
    proc diameter_retransmit_command {args} {
        _diameter_require_event {DIAMETER_INGRESS DIAMETER_EGRESS DIAMETER_RETRANSMISSION} DIAMETER::retransmit
        if {[llength $args] > 2 || ([llength $args] > 0 && [lindex $args 0] ni {disabled busy unable retransmit})} { error "DIAMETER::retransmit accepts an optional action and note" }
        ::itest::log_decision diameter retransmit $args
        return ""
    }
    proc diameter_retry_command {args} {
        _diameter_require_event {DIAMETER_INGRESS DIAMETER_EGRESS DIAMETER_RETRANSMISSION} DIAMETER::retry
        if {[llength $args] < 1 || [llength $args] > 2} { error "DIAMETER::retry requires a message and optional across flag" }
        ::itest::log_decision diameter retry $args
        return ""
    }
    proc diameter_skip_capabilities_exchange_command {args} {
        _diameter_require_event {CLIENT_ACCEPTED SERVER_CONNECTED} DIAMETER::skip_capabilities_exchange
        if {[llength $args] > 1} { error "DIAMETER::skip_capabilities_exchange accepts an optional hostname" }
        ::itest::log_decision diameter skip_capabilities_exchange $args
        return ""
    }
    proc diameter_dynamic_route_lookup_command {args} {
        variable diameter_dynamic_lookup_connection
        variable diameter_dynamic_lookup_message
        _diameter_require_event {DIAMETER_INGRESS DIAMETER_EGRESS DIAMETER_RETRANSMISSION} DIAMETER::dynamic_route_lookup
        if {[llength $args] == 0} { return $diameter_dynamic_lookup_message }
        if {[llength $args] != 2 || [lindex $args 0] ni {connection message} || [lindex $args 1] ni {0 1 true false enabled disabled}} { error "DIAMETER::dynamic_route_lookup requires connection|message and a boolean" }
        set value [expr {[lindex $args 1] in {1 true enabled}}]
        if {[lindex $args 0] eq "connection"} { set diameter_dynamic_lookup_connection $value } else { set diameter_dynamic_lookup_message $value }
        return $value
    }
    proc diameter_dynamic_route_insertion_command {args} {
        variable diameter_dynamic_insertion
        _diameter_require_event {DIAMETER_INGRESS DIAMETER_EGRESS DIAMETER_RETRANSMISSION} DIAMETER::dynamic_route_insertion
        if {[llength $args] == 0} { return $diameter_dynamic_insertion }
        if {[llength $args] != 1 || [lindex $args 0] ni {0 1 true false enabled disabled}} { error "DIAMETER::dynamic_route_insertion requires a boolean" }
        set diameter_dynamic_insertion [expr {[lindex $args 0] in {1 true enabled}}]
        return $diameter_dynamic_insertion
    }
    proc diameter_disconnect_command {args} {
        variable diameter_disconnected
        _diameter_require_event {DIAMETER_INGRESS DIAMETER_EGRESS} DIAMETER::disconnect
        if {[llength $args] != 3} { error "DIAMETER::disconnect requires origin host, origin realm, and cause" }
        set diameter_disconnected 1
        ::itest::log_decision diameter disconnect $args
        return ""
    }

    proc _radius_require_event {command_name} {
        if {$::itest::current_event ni {
            CLIENT_ACCEPTED CLIENT_CLOSED CLIENT_DATA SERVER_CLOSED SERVER_CONNECTED SERVER_DATA
            RADIUS_AAA_AUTH_REQUEST RADIUS_AAA_AUTH_RESPONSE RADIUS_AAA_ACCT_REQUEST RADIUS_AAA_ACCT_RESPONSE
        }} {
            error "$command_name is not valid during $::itest::current_event"
        }
    }

    proc radius_clear_message {} {
        foreach {name value} {
            code 1
            id 0
            authenticator ""
            attributes {}
            payload ""
            payload_length 0
            message ""
            message_length 20
            message_hex ""
            payload_hex ""
            rtdom ""
            subscriber ""
        } {
            set ::state::radius::$name $value
        }
    }

    proc radius_reset_connection {} { radius_clear_message }
    proc radius_prepare_message {} { radius_clear_message }

    proc _radius_int {value field maximum} {
        if {![string is integer -strict $value] || $value < 0 || $value > $maximum} {
            error "RADIUS $field must be an integer from 0 to $maximum"
        }
        return $value
    }

    proc _radius_hex_uint {value width field maximum} {
        return [format %0*X $width [_radius_int $value $field $maximum]]
    }

    proc _radius_record_data {record} {
        set raw [lindex $record 4]
        if {$raw eq ""} { return [::itest::cmd::_payload_bytes ""] }
        return [binary decode hex $raw]
    }

    proc _radius_record_wire {record} {
        set code [_radius_int [lindex $record 0] code 255]
        set vendor [_radius_int [lindex $record 1] vendor_id 0xffffffff]
        set vendor_type [_radius_int [lindex $record 2] vendor_type 255]
        set data [_radius_record_data $record]
        if {$code == 26} {
            if {!$vendor || !$vendor_type} { error "RADIUS Vendor-Specific attributes require vendor_id and vendor_type" }
            set inner_length [expr {2 + [string length $data]}]
            if {$inner_length > 255} { error "RADIUS Vendor-Specific attribute is too long" }
            set content [_radius_hex_uint $vendor 8 vendor_id 0xffffffff][format %02X%02X $vendor_type $inner_length]
            append content [binary encode hex $data]
        } else {
            if {$vendor || $vendor_type} { error "RADIUS vendor fields require attribute code 26" }
            set content [binary encode hex $data]
        }
        set length [expr {2 + [string length $content] / 2}]
        if {$length > 255} { error "RADIUS attribute length exceeds wire limit" }
        return [format %02X%02X $code $length]$content
    }

    proc radius_rebuild_message {} {
        set code [_radius_int $::state::radius::code code 255]
        set id [_radius_int $::state::radius::id id 255]
        set auth $::state::radius::authenticator
        if {$auth eq ""} { set auth [binary format H32 00000000000000000000000000000000] }
        if {[string length $auth] != 16} { error "RADIUS authenticator must contain exactly 16 bytes" }
        set payload ""
        foreach record $::state::radius::attributes {
            append payload [binary decode hex [_radius_record_wire $record]]
        }
        set length [expr {20 + [string length $payload]}]
        if {$length > 4096} { error "RADIUS message exceeds the 4096-byte wire limit" }
        set header [format %02X%02X%04X $code $id $length]
        append header [binary encode hex $auth]
        set message [binary decode hex $header]
        append message $payload
        set ::state::radius::payload $payload
        set ::state::radius::payload_length [string length $payload]
        set ::state::radius::payload_hex [binary encode hex $payload]
        set ::state::radius::message $message
        set ::state::radius::message_length [string length $message]
        set ::state::radius::message_hex [binary encode hex $message]
        return ""
    }

    proc _radius_attribute_code {value} {
        array set names {
            user-name 1 user-password 2 nas-ip-address 4 nas-port 5 service-type 6
            framed-ip-address 8 reply-message 18 state 24 class 25 vendor-specific 26
            session-timeout 27 called-station-id 30 calling-station-id 31 nas-identifier 32
            acct-status-type 40 acct-input-octets 42 acct-output-octets 43 acct-session-id 44
            event-timestamp 55 nas-port-type 61 connect-info 77
        }
        set key [string tolower [string map {_ -} $value]]
        if {[info exists names($key)]} { return $names($key) }
        return [_radius_int $value attribute 255]
    }

    proc _radius_type {value {default string}} {
        if {$value eq ""} { return $default }
        set value [string tolower $value]
        if {$value in {octet string integer integer64 ip4 ip6 ip4prefix ip6prefix}} { return $value }
        return octet
    }

    proc _radius_indices {code vendor vendor_type} {
        set result {}
        set index 0
        foreach record $::state::radius::attributes {
            if {[lindex $record 0] == $code && [lindex $record 1] == $vendor && [lindex $record 2] == $vendor_type} {
                lappend result $index
            }
            incr index
        }
        return $result
    }

    proc _radius_selector {args} {
        if {[llength $args] < 1} { error "RADIUS::avp requires an attribute" }
        set code [_radius_attribute_code [lindex $args 0]]
        set type string
        set index 0
        set vendor 0
        set vendor_type 0
        set cursor 1
        while {$cursor < [llength $args]} {
            set token [lindex $args $cursor]
            if {$token in {octet string integer integer64 ip4 ip6 ip4prefix ip6prefix}} {
                set type [_radius_type $token]
                incr cursor
            } elseif {$token eq "index"} {
                if {$cursor + 1 >= [llength $args]} { error "RADIUS::avp index requires a value" }
                set index [_radius_int [lindex $args [incr cursor]] index 0xffffffff]
                incr cursor
            } elseif {$token eq "vendor-id"} {
                if {$cursor + 1 >= [llength $args]} { error "RADIUS::avp vendor-id requires a value" }
                set vendor [_radius_int [lindex $args [incr cursor]] vendor_id 0xffffffff]
                incr cursor
            } elseif {$token eq "vendor-type"} {
                if {$cursor + 1 >= [llength $args]} { error "RADIUS::avp vendor-type requires a value" }
                set vendor_type [_radius_int [lindex $args [incr cursor]] vendor_type 255]
                incr cursor
            } else {
                error "unsupported RADIUS::avp option $token"
            }
        }
        set matches [_radius_indices $code $vendor $vendor_type]
        set absolute -1
        if {$index < [llength $matches]} { set absolute [lindex $matches $index] }
        return [dict create code $code type $type index $index vendor $vendor vendor_type $vendor_type absolute $absolute]
    }

    proc _radius_data_hex {value type} {
        switch -- $type {
            integer { return [_radius_hex_uint $value 8 integer 0xffffffff] }
            integer64 { return [_radius_hex_uint $value 16 integer64 0xffffffffffffffff] }
            ip4 {
                set octets [split $value .]
                if {[llength $octets] != 4} { error "RADIUS ip4 value is invalid" }
                set hex ""
                foreach octet $octets { append hex [_radius_hex_uint $octet 2 ip4 255] }
                return $hex
            }
            default { return [binary encode hex [::itest::cmd::_payload_bytes $value]] }
        }
    }

    proc _radius_value {record type} {
        set data [_radius_record_data $record]
        switch -- $type {
            integer - integer64 {
                if {[string length $data] ni {4 8}} { return "" }
                scan [binary encode hex $data] %x value
                return $value
            }
            ip4 {
                if {[string length $data] != 4} { return "" }
                set hex [binary encode hex $data]
                return [join [list [scan [string range $hex 0 1] %x] [scan [string range $hex 2 3] %x] [scan [string range $hex 4 5] %x] [scan [string range $hex 6 7] %x]] .]
            }
            octet { return [binary encode hex $data] }
            default {
                if {[catch {encoding convertfrom utf-8 $data} value]} { return $data }
                return $value
            }
        }
    }

    proc _radius_set_record {absolute record} {
        set ::state::radius::attributes [lreplace $::state::radius::attributes $absolute $absolute $record]
        radius_rebuild_message
    }

    proc radius_avp_command {args} {
        _radius_require_event RADIUS::avp
        if {[llength $args] < 1} { error "RADIUS::avp requires an attribute or subcommand" }
        set operation [lindex $args 0]
        if {$operation in {insert replace delete}} {
            set rest [lrange $args 1 end]
            if {$operation eq "delete"} {
                set selector [_radius_selector {*}$rest]
                set absolute [dict get $selector absolute]
                if {$absolute >= 0} {
                    set ::state::radius::attributes [lreplace $::state::radius::attributes $absolute $absolute]
                    radius_rebuild_message
                }
                return ""
            }
            if {[llength $rest] < 1 || ($operation eq "replace" && [llength $rest] < 2)} {
                error "RADIUS::avp $operation requires an attribute and value"
            }
            set code [_radius_attribute_code [lindex $rest 0]]
            set value ""
            if {[llength $rest] > 1} { set value [lindex $rest 1] }
            set type string
            set option_start 2
            if {[llength $rest] > 2 && [lindex $rest 2] in {octet string integer integer64 ip4 ip6 ip4prefix ip6prefix}} {
                set type [_radius_type [lindex $rest 2]]
                set option_start 3
            }
            set selector [_radius_selector [lindex $rest 0] {*}[lrange $rest $option_start end]]
            set vendor [dict get $selector vendor]
            set vendor_type [dict get $selector vendor_type]
            set record [list $code $vendor $vendor_type $type [_radius_data_hex $value $type]]
            if {$operation eq "insert"} {
                lappend ::state::radius::attributes $record
            } else {
                set absolute [dict get $selector absolute]
                if {$absolute < 0} { error "RADIUS attribute was not found" }
                _radius_set_record $absolute $record
                return ""
            }
            radius_rebuild_message
            ::itest::log_decision radius avp_$operation $record
            return ""
        }
        set selector [_radius_selector {*}$args]
        set absolute [dict get $selector absolute]
        if {$absolute < 0} { return "" }
        return [_radius_value [lindex $::state::radius::attributes $absolute] [dict get $selector type]]
    }

    proc radius_code_command {args} {
        _radius_require_event RADIUS::code
        if {[llength $args] != 0} { error "RADIUS::code takes no arguments" }
        return $::state::radius::code
    }

    proc radius_id_command {args} {
        _radius_require_event RADIUS::id
        if {[llength $args] != 0} { error "RADIUS::id takes no arguments" }
        return $::state::radius::id
    }

    proc radius_rtdom_command {args} {
        _radius_require_event RADIUS::rtdom
        if {[llength $args] > 1} { error "RADIUS::rtdom accepts zero or one value" }
        if {[llength $args] == 0} { return $::state::radius::rtdom }
        set ::state::radius::rtdom [_radius_int [lindex $args 0] route_domain 0xffffffff]
        ::itest::log_decision radius rtdom $::state::radius::rtdom
        return $::state::radius::rtdom
    }

    proc radius_subscriber_command {args} {
        _radius_require_event RADIUS::subscriber
        if {[llength $args] > 1} { error "RADIUS::subscriber accepts zero or one value" }
        if {[llength $args] == 0} { return $::state::radius::subscriber }
        set ::state::radius::subscriber [lindex $args 0]
        return $::state::radius::subscriber
    }

    proc radius_authenticate_command {args} {
        ::itest::log_decision radius authenticate $args
        return 0
    }

    proc _mr_require_event {command_name} {
        if {$::itest::current_event ni {
            CLIENT_ACCEPTED CLIENT_CLOSED CLIENT_DATA SERVER_CLOSED SERVER_CONNECTED SERVER_DATA
            MR_INGRESS MR_EGRESS MR_FAILED MR_DATA GENERICMESSAGE_INGRESS GENERICMESSAGE_EGRESS
        }} {
            error "$command_name is not valid during $::itest::current_event"
        }
    }

    proc mr_clear_message {} {
        foreach {name value} {
            payload ""
            payload_length 0
            collect_length 0
            peer ""
            route_status unrouted
            route ""
            route_target ""
            available_for_routing true
            always_match_port false
            ignore_peer_port false
            connect_back_port 0
            connection_instance "0 of 1"
            connection_mode per-peer
            equivalent_transport ""
            flow_id "flow-0"
            instance "/Common/mr_router"
            max_retries 3
            transport "config /Common/mr_router"
            retry_count 0
            stored {}
            streamed ""
            dropped false
            released false
            response ""
        } {
            set ::state::mr::$name $value
        }
        set ::state::message::proto generic
        set ::state::message::type request
        set ::state::message::fields {}
    }

    proc mr_reset_connection {} { mr_clear_message }

    proc mr_prepare_message {} {
        set ::state::mr::route_status unrouted
        set ::state::mr::route ""
        set ::state::mr::route_target ""
        set ::state::mr::retry_count 0
        set ::state::mr::stored {}
        set ::state::mr::streamed ""
        set ::state::mr::dropped false
        set ::state::mr::released false
        set ::state::mr::response ""
    }

    proc _mr_bool {value field} {
        set normalized [string tolower $value]
        if {$normalized ni {0 1 true false enabled disabled}} {
            error "MR $field must be a boolean"
        }
        return [expr {$normalized in {1 true enabled}}]
    }

    proc _mr_toggle {field args} {
        _mr_require_event "MR::$field"
        if {[llength $args] > 1} { error "MR::$field accepts zero or one value" }
        if {[llength $args] == 1} {
            set ::state::mr::$field [_mr_bool [lindex $args 0] $field]
        }
        return [set ::state::mr::$field]
    }

    proc mr_always_match_port_command {args} { return [_mr_toggle always_match_port {*}$args] }
    proc mr_available_for_routing_command {args} { return [_mr_toggle available_for_routing {*}$args] }
    proc mr_ignore_peer_port_command {args} { return [_mr_toggle ignore_peer_port {*}$args] }

    proc mr_collect_command {args} {
        _mr_require_event MR::collect
        if {[llength $args] > 1} { error "MR::collect accepts zero or one byte count" }
        if {[llength $args] == 0} {
            set ::state::mr::collect_length -1
        } else {
            set value [lindex $args 0]
            if {![string is integer -strict $value] || $value < 0} { error "MR::collect requires a non-negative byte count" }
            set ::state::mr::collect_length $value
        }
        return $::state::mr::collect_length
    }

    proc mr_connect_back_port_command {args} {
        _mr_require_event MR::connect_back_port
        if {[llength $args] > 1} { error "MR::connect_back_port accepts zero or one port" }
        if {[llength $args] == 1} {
            set value [lindex $args 0]
            if {![string is integer -strict $value] || $value < 0 || $value > 65535} { error "MR::connect_back_port must be a port" }
            set ::state::mr::connect_back_port $value
        }
        return $::state::mr::connect_back_port
    }

    proc mr_connection_instance_command {args} {
        _mr_require_event MR::connection_instance
        if {[llength $args] != 0} { error "MR::connection_instance takes no arguments" }
        return $::state::mr::connection_instance
    }
    proc mr_connection_mode_command {args} {
        _mr_require_event MR::connection_mode
        if {[llength $args] != 0} { error "MR::connection_mode takes no arguments" }
        return $::state::mr::connection_mode
    }
    proc mr_equivalent_transport_command {args} {
        _mr_require_event MR::equivalent_transport
        if {[llength $args] > 1} { error "MR::equivalent_transport accepts zero or one value" }
        if {[llength $args] == 1} { set ::state::mr::equivalent_transport [lindex $args 0] }
        return $::state::mr::equivalent_transport
    }
    proc mr_flow_id_command {args} {
        _mr_require_event MR::flow_id
        if {[llength $args] != 0} { error "MR::flow_id takes no arguments" }
        return $::state::mr::flow_id
    }
    proc mr_instance_command {args} {
        _mr_require_event MR::instance
        if {[llength $args] != 0} { error "MR::instance takes no arguments" }
        return $::state::mr::instance
    }
    proc mr_max_retries_command {args} {
        _mr_require_event MR::max_retries
        if {[llength $args] != 0} { error "MR::max_retries takes no arguments" }
        return $::state::mr::max_retries
    }
    proc mr_protocol_command {args} {
        _mr_require_event MR::protocol
        if {[llength $args] != 0} { error "MR::protocol takes no arguments" }
        return $::state::message::proto
    }
    proc mr_transport_command {args} {
        _mr_require_event MR::transport
        if {[llength $args] != 0} { error "MR::transport takes no arguments" }
        return $::state::mr::transport
    }

    proc mr_payload_command {args} {
        _mr_require_event MR::payload
        if {[llength $args] > 1} { error "MR::payload accepts only length" }
        if {[llength $args] == 1 && [lindex $args 0] eq "length"} {
            return $::state::mr::payload_length
        }
        if {[llength $args] == 1} { error "MR::payload accepts only length" }
        return $::state::mr::payload
    }

    proc mr_peer_command {args} {
        _mr_require_event MR::peer
        if {[llength $args] < 1} { error "MR::peer requires a peer name" }
        set ::state::mr::peer [lindex $args 0]
        ::itest::log_decision mr peer $args
        return $::state::mr::peer
    }

    proc mr_prime_command {args} {
        _mr_require_event MR::prime
        set ::state::mr::route_status primed
        set ::state::mr::route [join $args " "]
        ::itest::log_decision mr prime $args
        return ""
    }

    proc mr_release_command {args} {
        _mr_require_event MR::release
        if {[llength $args] != 0} { error "MR::release takes no arguments" }
        set ::state::mr::collect_length 0
        set ::state::mr::released true
        return ""
    }

    proc mr_retry_command {args} {
        _mr_require_event MR::retry
        if {[llength $args] != 0} { error "MR::retry takes no arguments" }
        incr ::state::mr::retry_count
        set ::state::mr::route_status unrouted
        ::itest::log_decision mr retry $::state::mr::retry_count
        return ""
    }

    proc mr_return_command {args} {
        _mr_require_event MR::return
        if {[llength $args] > 1} { error "MR::return accepts zero or one route status" }
        set status "returned by irule"
        if {[llength $args] == 1} { set status [lindex $args 0] }
        if {$status ne "returned by irule" && $status ni {
            no_route_found queue_full no_connection connection_closing
            internal_error max_retries_exceeded
        }} {
            error "MR::return route status is invalid"
        }
        set ::state::mr::route_status $status
        set ::state::mr::response returned
        return ""
    }

    proc mr_stream_command {args} {
        _mr_require_event MR::stream
        set end 0
        if {[llength $args] == 2 && [lindex $args 0] eq "end"} {
            set end 1
            set value [lindex $args 1]
        } elseif {[llength $args] == 1} {
            set value [lindex $args 0]
        } else {
            error "MR::stream accepts bytes or end bytes"
        }
        if {[string bytelength $::state::mr::streamed] + [string bytelength $value] > 2097152} {
            error "MR::stream payload exceeds the 2 MiB limit"
        }
        append ::state::mr::streamed $value
        if {$end} { set ::state::mr::route_status streamed }
        return ""
    }

    proc mr_message_command {args} {
        _mr_require_event MR::message
        if {[llength $args] < 1} { error "MR::message requires a subcommand" }
        set subcommand [lindex $args 0]
        switch -- $subcommand {
            clone {
                set count [expr {[llength $args] - 1}]
                if {$count == 2 && [lindex $args 1] eq "-count"} { set count [lindex $args 2] }
                if {![string is integer -strict $count] || $count < 1} { error "MR::message clone requires one or more clones" }
                set ::state::mr::clone_count $count
                ::itest::log_decision mr clone $count
                return $count
            }
            route {
                set ::state::mr::route [join [lrange $args 1 end] " "]
                set ::state::mr::route_status routed
                return $::state::mr::route
            }
            nexthop {
                if {[llength $args] != 2} { error "MR::message nexthop requires a value" }
                set ::state::mr::route_target [lindex $args 1]
                return $::state::mr::route_target
            }
            retry_count { return $::state::mr::retry_count }
            pick_host { return $::state::mr::peer }
            default { error "unsupported MR::message subcommand $subcommand" }
        }
    }

    proc mr_store_command {args} {
        _mr_require_event MR::store
        set stored {}
        foreach name $args {
            if {[catch {uplevel 2 [list set $name]} value]} { continue }
            dict set stored $name $value
        }
        set ::state::mr::stored $stored
        return ""
    }

    proc mr_restore_command {args} {
        _mr_require_event MR::restore
        set stored $::state::mr::stored
        set names $args
        if {[llength $names] == 0} { set names [dict keys $stored] }
        foreach name $names {
            if {![dict exists $stored $name]} { continue }
            uplevel 2 [list set $name [dict get $stored $name]]
        }
        return ""
    }

    proc _message_field_get {name} {
        if {![dict exists $::state::message::fields $name]} { return "" }
        return [dict get $::state::message::fields $name]
    }

    proc message_field_command {args} {
        _mr_require_event MESSAGE::field
        if {[llength $args] == 1 && [lindex $args 0] eq "names"} {
            return [dict keys $::state::message::fields]
        }
        if {[llength $args] >= 2 && [lindex $args 0] eq "value"} {
            set name [lindex $args 1]
            if {[llength $args] == 2} { return [_message_field_get $name] }
            if {[llength $args] == 3} {
                dict set ::state::message::fields $name [lindex $args 2]
                return [lindex $args 2]
            }
        }
        error "MESSAGE::field expects names or value field [value]"
    }

    proc message_proto_command {args} {
        _mr_require_event MESSAGE::proto
        if {[llength $args] != 0} { error "MESSAGE::proto takes no arguments" }
        return [string toupper $::state::message::proto]
    }
    proc message_type_command {args} {
        _mr_require_event MESSAGE::type
        if {[llength $args] != 0} { error "MESSAGE::type takes no arguments" }
        return $::state::message::type
    }

    proc genericmessage_message_command {args} {
        _mr_require_event GENERICMESSAGE::message
        if {[llength $args] == 0} { return $::state::mr::payload }
        set field [string tolower [lindex $args 0]]
        if {$field in {len length}} {
            if {[llength $args] != 1} { error "GENERICMESSAGE::message length takes no value" }
            return $::state::mr::payload_length
        }
        if {$field eq "data"} {
            if {[llength $args] == 1} { return $::state::mr::payload }
            if {[llength $args] == 2} {
                set ::state::mr::payload [lindex $args 1]
                set ::state::mr::payload_length [string bytelength $::state::mr::payload]
                return $::state::mr::payload
            }
        }
        if {$field in {src source dst dest destination}} {
            set key [expr {$field in {src source} ? "src" : "dst"}]
            if {[llength $args] == 1} { return [_message_field_get $key] }
            if {[llength $args] == 2} {
                dict set ::state::message::fields $key [lindex $args 1]
                return [lindex $args 1]
            }
        }
        if {$field eq "is_request"} {
            if {[llength $args] == 1} { return [expr {$::state::message::type eq "request"}] }
            if {[llength $args] == 2} {
                set ::state::message::type [expr {[_mr_bool [lindex $args 1] is_request] ? "request" : "response"}]
                return [expr {$::state::message::type eq "request"}]
            }
        }
        error "unsupported GENERICMESSAGE::message field $field"
    }

    proc genericmessage_peer_command {args} {
        _mr_require_event GENERICMESSAGE::peer
        if {[llength $args] == 0} { return $::state::mr::peer }
        if {[llength $args] != 2 || [lindex $args 0] ne "name"} { error "GENERICMESSAGE::peer accepts name and an optional value" }
        set ::state::mr::peer [lindex $args 1]
        return $::state::mr::peer
    }

    proc genericmessage_route_command {args} {
        _mr_require_event GENERICMESSAGE::route
        if {[llength $args] < 1} { error "GENERICMESSAGE::route requires add, delete, or lookup" }
        switch -- [lindex $args 0] {
            add {
                set ::state::mr::route [join [lrange $args 1 end] " "]
                set ::state::mr::route_status routed
                return $::state::mr::route
            }
            delete {
                set ::state::mr::route ""
                set ::state::mr::route_status unrouted
                return ""
            }
            lookup { return $::state::mr::route }
            default { error "unsupported GENERICMESSAGE::route operation" }
        }
    }

    proc _gtp_require_event {command_name} {
        if {$::itest::current_event ni {
            CLIENT_ACCEPTED CLIENT_CLOSED CLIENT_DATA SERVER_CLOSED SERVER_CONNECTED SERVER_DATA
            GTP_GPDU_INGRESS GTP_GPDU_EGRESS GTP_PRIME_INGRESS GTP_PRIME_EGRESS
            GTP_SIGNALLING_INGRESS GTP_SIGNALLING_EGRESS
        }} {
            error "$command_name is not valid during $::itest::current_event"
        }
    }

    proc gtp_clear_message {} {
        foreach {name value} {
            version 2 type 1 teid 0 sequence 0 npdu 0 length 0 ies {}
            payload "" payload_length 0 message "" message_length 0
            message_hex "" payload_hex "" discarded false responded false
        } {
            set ::state::gtp::$name $value
        }
    }

    proc gtp_reset_connection {} { gtp_clear_message }
    proc gtp_prepare_message {} {
        set ::state::gtp::discarded false
        set ::state::gtp::responded false
    }

    proc _gtp_hex_uint {value width field maximum} {
        if {![string is integer -strict $value] || $value < 0 || $value > $maximum} {
            error "GTP $field must be an integer from 0 to $maximum"
        }
        return [format %0*X $width $value]
    }

    proc _gtp_ie_wire {record version} {
        set ie_type [_gtp_hex_uint [lindex $record 0] 2 type 255]
        set data [lindex $record 2]
        set length [expr {[string length $data] / 2}]
        set wire "$ie_type[_gtp_hex_uint $length 4 length 65535]"
        if {$version == 2} {
            append wire [_gtp_hex_uint [lindex $record 1] 2 instance 15]
        }
        append wire $data
        return $wire
    }

    proc gtp_rebuild_message {} {
        set version $::state::gtp::version
        set type $::state::gtp::type
        set teid $::state::gtp::teid
        set sequence $::state::gtp::sequence
        set npdu $::state::gtp::npdu
        set body ""
        if {$type == 255} {
            set body [binary encode hex $::state::gtp::payload]
        } else {
            foreach record $::state::gtp::ies { append body [_gtp_ie_wire $record $version] }
        }
        if {$version == 1} {
            set rest "[_gtp_hex_uint $teid 8 teid 0xffffffff][_gtp_hex_uint $sequence 4 sequence 65535][_gtp_hex_uint $npdu 2 npdu 255]00$body"
            set message "32[_gtp_hex_uint $type 2 type 255][_gtp_hex_uint [expr {[string length $rest] / 2 - 4}] 4 length 65535]$rest"
        } elseif {$version == 2} {
            set flags [expr {$teid ? 0x48 : 0x40}]
            set header "[_gtp_hex_uint $flags 2 flags 255][_gtp_hex_uint $type 2 type 255]0000"
            if {$teid} { append header [_gtp_hex_uint $teid 8 teid 0xffffffff] }
            append header "[_gtp_hex_uint $sequence 6 sequence 0xffffff]00$body"
            set message "[string range $header 0 3][_gtp_hex_uint [expr {[string length $header] / 2 - 4}] 4 length 65535][string range $header 8 end]"
        } else {
            error "GTP version must be 1 or 2"
        }
        set wire [binary decode hex $message]
        set ::state::gtp::payload_hex [binary encode hex $::state::gtp::payload]
        set ::state::gtp::payload_length [string length $::state::gtp::payload]
        set ::state::gtp::message $wire
        set ::state::gtp::message_hex [binary encode hex $wire]
        set ::state::gtp::message_length [string length $wire]
        set ::state::gtp::length [expr {[string length $wire] - ($version == 1 ? 8 : 4)}]
        return ""
    }

    proc gtp_header_command {args} {
        _gtp_require_event GTP::header
        if {[llength $args] < 1} { error "GTP::header requires a field" }
        set field [string tolower [lindex $args 0]]
        set rest [lrange $args 1 end]
        if {[lindex $rest 0] eq "-message"} {
            if {[llength $rest] < 2} { error "GTP::header -message requires a value" }
            set rest [lrange $rest 2 end]
        }
        if {$field in {version type}} {
            if {[llength $rest] != 0} { error "GTP::header $field is read-only" }
            return [set ::state::gtp::$field]
        }
        if {$field ni {teid npdu sequence}} { error "unsupported GTP header field $field" }
        if {[llength $rest] == 0} { return [set ::state::gtp::$field] }
        set operation [lindex $rest 0]
        if {$operation eq "remove"} {
            if {[llength $rest] != 1} { error "GTP::header $field remove takes no value" }
            set ::state::gtp::$field 0
        } elseif {$operation eq "set"} {
            if {[llength $rest] != 2} { error "GTP::header $field set requires a value" }
            set value [lindex $rest 1]
            set maximum [expr {$field eq "sequence" ? ($::state::gtp::version == 1 ? 0xffff : 0xffffff) : ($field eq "npdu" ? 255 : 0xffffffff)}]
            _gtp_hex_uint $value 1 $field $maximum
            set ::state::gtp::$field $value
        } else {
            error "GTP::header $field expects set or remove"
        }
        gtp_rebuild_message
        return [set ::state::gtp::$field]
    }

    proc _gtp_ie_code {value} {
        array set names {imsi 1 cause 2 recovery 3 apn 71 msisdn 76 rat-type 82 ebi 73 f-teid 87 charging-id 127}
        set key [string tolower [string map {_ -} $value]]
        if {[info exists names($key)]} { return $names($key) }
        return [_gtp_hex_uint $value 1 ie_type 255]
    }

    proc _gtp_ie_selector {path} {
        set pieces [split $path :]
        set code [_gtp_ie_code [lindex $pieces 0]]
        set instance 0
        if {[llength $pieces] > 1} { set instance [_gtp_hex_uint [lindex $pieces 1] 1 instance 15] }
        return [list $code $instance]
    }

    proc _gtp_ie_matches {code instance} {
        set result {}
        set index 0
        foreach record $::state::gtp::ies {
            if {($code < 0 || [lindex $record 0] == $code) &&
                ($instance < 0 || [lindex $record 1] == $instance)} {
                lappend result $index
            }
            incr index
        }
        return $result
    }

    proc _gtp_ie_filter {args} {
        set path ""
        set code -1
        set instance -1
        set cursor 0
        while {$cursor < [llength $args]} {
            set token [lindex $args $cursor]
            switch -- $token {
                -message {
                    if {$cursor + 1 >= [llength $args]} { error "GTP::ie -message requires a value" }
                    incr cursor 2
                }
                -type {
                    if {$cursor + 1 >= [llength $args]} { error "GTP::ie -type requires a value" }
                    set code [_gtp_ie_code [lindex $args [incr cursor]]]
                    incr cursor
                }
                -instance {
                    if {$cursor + 1 >= [llength $args]} { error "GTP::ie -instance requires a value" }
                    set instance [_gtp_hex_uint [lindex $args [incr cursor]] 1 instance 15]
                    incr cursor
                }
                default {
                    if {$path ne ""} { error "GTP::ie accepts only one IE path" }
                    set path $token
                    incr cursor
                }
            }
        }
        if {$path ne ""} {
            lassign [_gtp_ie_selector $path] path_code path_instance
            set code $path_code
            set instance $path_instance
        }
        return [list $code $instance]
    }

    proc gtp_ie_command {args} {
        _gtp_require_event GTP::ie
        if {[llength $args] < 1} { error "GTP::ie requires a subcommand" }
        set operation [lindex $args 0]
        set rest [lrange $args 1 end]
        if {$operation eq "get"} {
            if {[llength $rest] < 1} { error "GTP::ie get requires a field or list" }
            set operation [lindex $rest 0]
            set rest [lrange $rest 1 end]
        }
        if {$operation eq "list"} {
            set filter [_gtp_ie_filter {*}$rest]
            set result {}
            lassign $filter filter_code filter_instance
            foreach absolute [_gtp_ie_matches $filter_code $filter_instance] {
                set record [lindex $::state::gtp::ies $absolute]
                lappend result "[lindex $record 0]:[lindex $record 1]"
            }
            return $result
        }
        if {$operation in {exists count}} {
            set filter [_gtp_ie_filter {*}$rest]
            lassign $filter code instance
            set matches [_gtp_ie_matches $code $instance]
            if {$operation eq "exists"} { return [expr {[llength $matches] > 0}] }
            return [llength $matches]
        }
        if {$operation in {instance length encode-type value}} {
            set path [lindex $rest end]
            if {$path eq "" || [string match "-*" $path]} { error "GTP::ie $operation requires an IE path" }
            lassign [_gtp_ie_selector $path] code instance
            set matches [_gtp_ie_matches $code $instance]
            if {![llength $matches]} { return "" }
            set record [lindex $::state::gtp::ies [lindex $matches 0]]
            switch -- $operation {
                instance { return [lindex $record 1] }
                length { return [expr {[string length [lindex $record 2]] / 2}] }
                encode-type { return [expr {$::state::gtp::version == 2 ? 1 : 0}] }
                value { return [lindex $record 2] }
            }
        }
        error "unsupported GTP::ie operation $operation"
    }

    proc gtp_length_command {args} {
        _gtp_require_event GTP::length
        if {[llength $args] != 0} { error "GTP::length takes no arguments" }
        return $::state::gtp::length
    }
    proc gtp_message_command {args} {
        _gtp_require_event GTP::message
        if {[llength $args] != 0} { error "GTP::message takes no arguments" }
        return $::state::gtp::message
    }
    proc gtp_payload_command {args} {
        _gtp_require_event GTP::payload
        if {[llength $args] == 0} { return $::state::gtp::payload }
        if {[llength $args] == 1 && [lindex $args 0] ne "replace"} {
            set count [lindex $args 0]
            if {![string is integer -strict $count] || $count < 0} { error "GTP::payload count must be non-negative" }
            return [string range $::state::gtp::payload 0 [expr {$count - 1}]]
        }
        if {[lindex $args 0] eq "replace" && [llength $args] == 4} {
            set offset [lindex $args 1]
            set count [lindex $args 2]
            if {![string is integer -strict $offset] || ![string is integer -strict $count] || $offset < 0 || $count < 0} { error "GTP::payload replace offsets must be non-negative integers" }
            set current [::itest::cmd::_payload_bytes $::state::gtp::payload]
            set current_length [string length $current]
            if {$offset > $current_length || $count > $current_length - $offset} {
                error "GTP::payload replace range exceeds payload length"
            }
            set replacement [::itest::cmd::_payload_bytes [lindex $args 3]]
            set before [string range $current 0 [expr {$offset - 1}]]
            set after [string range $current [expr {$offset + $count}] end]
            set ::state::gtp::payload [::itest::cmd::_payload_bytes "$before$replacement$after"]
            gtp_rebuild_message
            return ""
        }
        error "unsupported GTP::payload form"
    }
    proc gtp_discard_command {args} { _gtp_require_event GTP::discard; if {[llength $args] != 0} { error "GTP::discard takes no arguments" }; set ::state::gtp::discarded true; return "" }
    proc gtp_respond_command {args} { _gtp_require_event GTP::respond; if {[llength $args] != 1} { error "GTP::respond requires a message" }; set ::state::gtp::responded true; ::itest::log_decision gtp respond $args; return "" }
    proc gtp_forward_command {args} { _gtp_require_event GTP::forward; if {[llength $args] != 1} { error "GTP::forward requires a message" }; ::itest::log_decision gtp forward $args; return "" }
    proc gtp_clone_command {args} { _gtp_require_event GTP::clone; if {[llength $args] > 1} { error "GTP::clone accepts at most one message" }; ::itest::log_decision gtp clone $args; return $::state::gtp::message }
    proc gtp_new_command {args} { _gtp_require_event GTP::new; if {[llength $args] != 2} { error "GTP::new requires version and type" }; set ::state::gtp::version [lindex $args 0]; set ::state::gtp::type [lindex $args 1]; gtp_rebuild_message; return $::state::gtp::message }
    proc gtp_parse_command {args} { _gtp_require_event GTP::parse; if {[llength $args] != 1} { error "GTP::parse requires a byte stream" }; set ::state::gtp::message [lindex $args 0]; return $::state::gtp::message }
    proc _gtp_tunnel_byte {payload offset} {
        if {$offset < 0 || $offset >= [string length $payload]} { return -1 }
        binary scan [string range $payload $offset $offset] c value
        return [expr {$value & 255}]
    }
    proc _gtp_tunnel_u16 {payload offset} {
        set high [_gtp_tunnel_byte $payload $offset]
        set low [_gtp_tunnel_byte $payload [expr {$offset + 1}]]
        if {$high < 0 || $low < 0} { return -1 }
        return [expr {($high << 8) | $low}]
    }
    proc _gtp_tunnel_ip_info {} {
        if {$::state::gtp::type != 255} { return {} }
        set payload [::itest::cmd::_payload_bytes $::state::gtp::payload]
        if {[string length $payload] < 1} { return {} }
        set first [_gtp_tunnel_byte $payload 0]
        set version [expr {$first >> 4}]
        if {$version == 4} {
            set header_length [expr {($first & 15) * 4}]
            if {$header_length < 20 || [string length $payload] < $header_length} { return {} }
            set source_parts {}
            set destination_parts {}
            for {set index 0} {$index < 4} {incr index} {
                lappend source_parts [_gtp_tunnel_byte $payload [expr {12 + $index}]]
                lappend destination_parts [_gtp_tunnel_byte $payload [expr {16 + $index}]]
            }
            return [list version 4 header_length $header_length protocol [_gtp_tunnel_byte $payload 9] source [join $source_parts .] destination [join $destination_parts .]]
        }
        if {$version == 6 && [string length $payload] >= 40} {
            set source_groups {}
            set destination_groups {}
            for {set index 0} {$index < 16} {incr index 2} {
                lappend source_groups [format %x [_gtp_tunnel_u16 $payload [expr {8 + $index}]]]
                lappend destination_groups [format %x [_gtp_tunnel_u16 $payload [expr {24 + $index}]]]
            }
            return [list version 6 header_length 40 protocol [_gtp_tunnel_byte $payload 6] source [join $source_groups :] destination [join $destination_groups :]]
        }
        return {}
    }
    proc gtp_tunnel_command {args} {
        _gtp_require_event GTP::tunnel
        if {[llength $args] != 1} { error "GTP::tunnel requires a subcommand" }
        set info [_gtp_tunnel_ip_info]
        set subcommand [string tolower [lindex $args 0]]
        if {$subcommand eq "is_ip"} { return [expr {[llength $info] > 0}] }
        if {![llength $info]} { return "" }
        switch -- $subcommand {
            ip_version { return [dict get $info version] }
            ip_proto - ip_protocol { return [dict get $info protocol] }
            ip_src - ip_source - src_addr { return [dict get $info source] }
            ip_dst - ip_destination - dst_addr { return [dict get $info destination] }
            tcp_src_port - tcp_source_port - tcp_dst_port - tcp_destination_port -
            udp_src_port - udp_source_port - udp_dst_port - udp_destination_port {
                set wanted [expr {[string match "tcp_*" $subcommand] ? 6 : 17}]
                if {[dict get $info protocol] != $wanted} { return "" }
                set payload [::itest::cmd::_payload_bytes $::state::gtp::payload]
                set header_length [dict get $info header_length]
                set source_query [expr {$subcommand in {tcp_src_port tcp_source_port udp_src_port udp_source_port}}]
                set offset [expr {$header_length + ($source_query ? 0 : 2)}]
                set port [_gtp_tunnel_u16 $payload $offset]
                if {$port < 0} { return "" }
                return $port
            }
            default { error "unsupported GTP::tunnel subcommand $subcommand" }
        }
    }

    proc lb_snapshot {} {
        if {[info exists ::state::lb::node_status]} {
            return [array get ::state::lb::node_status]
        }
        return [list]
    }

    proc _uri_input {args} {
        if {[llength $args] > 0} {
            return [lindex $args 0]
        }
        return $::state::http::request::uri
    }

    proc _uri_parts {uri} {
        set scheme ""
        set authority ""
        set remainder $uri
        if {[regexp -nocase {^([a-z][a-z0-9+.-]*):\/\/([^\/?#]*)(.*)$} $uri -> scheme authority remainder]} {
            set scheme [string tolower $scheme]
        }
        set fragment_pos [string first # $remainder]
        if {$fragment_pos >= 0} {
            set remainder [string range $remainder 0 [expr {$fragment_pos - 1}]]
        }
        set query ""
        set query_pos [string first ? $remainder]
        if {$query_pos >= 0} {
            set query [string range $remainder [expr {$query_pos + 1}] end]
            set remainder [string range $remainder 0 [expr {$query_pos - 1}]]
        }
        if {$authority ne ""} {
            set host $authority
            set at [string last @ $host]
            if {$at >= 0} {
                set host [string range $host [expr {$at + 1}] end]
            }
            if {[string index $host 0] eq "\["} {
                set close [string first \] $host]
                set host_value [string range $host 1 [expr {$close - 1}]]
                set port ""
                if {$close + 1 < [string length $host] && [string index $host [expr {$close + 1}]] eq ":"} {
                    set port [string range $host [expr {$close + 2}] end]
                }
            } else {
                set colon [string last : $host]
                if {$colon > 0 && [string is integer -strict [string range $host [expr {$colon + 1}] end]]} {
                    set host_value [string range $host 0 [expr {$colon - 1}]]
                    set port [string range $host [expr {$colon + 1}] end]
                } else {
                    set host_value $host
                    set port ""
                }
            }
        } else {
            set host $::state::http::request::host
            set host_value $host
            set port ""
        }
        if {$remainder eq "" && $authority ne ""} {
            set path "/"
        } elseif {$remainder eq ""} {
            set path ""
        } else {
            set path $remainder
        }
        return [list scheme $scheme host $host_value port $port path $path query $query]
    }

    proc _uri_encode_value {value {component 0}} {
        set bytes [encoding convertto utf-8 $value]
        binary scan $bytes c* numbers
        set output ""
        foreach number $numbers {
            set byte [expr {$number & 255}]
            set safe [expr {($byte >= 48 && $byte <= 57) ||
                            ($byte >= 65 && $byte <= 90) ||
                            ($byte >= 97 && $byte <= 122) ||
                            $byte in {45 46 95 126}}]
            if {!$component && $byte in {58 47 63 35 91 93 64 33 36 38 39 40 41 42 43 44 59 61}} {
                set safe 1
            }
            if {$safe} {
                append output [binary format c $byte]
            } else {
                append output %[format %02X $byte]
            }
        }
        return $output
    }

    proc _uri_decode_value {value} {
        set bytes ""
        set output ""
        set length [string length $value]
        set index 0
        while {$index < $length} {
            set char [string index $value $index]
            if {$char eq "%" && $index + 2 < $length} {
                set hex [string range $value [expr {$index + 1}] [expr {$index + 2}]]
                if {[regexp -nocase {^[0-9a-f]{2}$} $hex]} {
                    append bytes [binary format H2 $hex]
                    incr index 3
                    continue
                }
            }
            if {$bytes ne ""} {
                if {[catch {encoding convertfrom utf-8 $bytes} decoded]} {
                    # URI::decode should not make arbitrary percent-encoded
                    # octets fatal; preserve malformed UTF-8 byte-for-byte.
                    set decoded [encoding convertfrom iso8859-1 $bytes]
                }
                append output $decoded
                set bytes ""
            }
            append output $char
            incr index
        }
        if {$bytes ne ""} {
            if {[catch {encoding convertfrom utf-8 $bytes} decoded]} {
                set decoded [encoding convertfrom iso8859-1 $bytes]
            }
            append output $decoded
        }
        return $output
    }

    proc _auth_parts {} {
        set authorization [::state::http::request::header get authorization]
        if {![regexp -nocase {^Basic[ \t]+(.+)$} $authorization -> encoded]} {
            return [list "" ""]
        }
        if {[catch {binary decode base64 $encoded} decoded]} {
            return [list "" ""]
        }
        set separator [string first : $decoded]
        if {$separator < 0} {
            return [list $decoded ""]
        }
        return [list [string range $decoded 0 [expr {$separator - 1}]] [string range $decoded [expr {$separator + 1}] end]]
    }

    proc _ipv4_int {address} {
        set octets [split $address .]
        if {[llength $octets] != 4} {
            error "IP::addr requires IPv4 addresses in this emulator slice"
        }
        set result 0
        foreach octet $octets {
            if {![string is integer -strict $octet] || $octet < 0 || $octet > 255} {
                error "invalid IPv4 address \"$address\""
            }
            set result [expr {(($result << 8) | $octet) & 0xffffffff}]
        }
        return $result
    }

    proc _cidr_parts {address} {
        set slash [string first / $address]
        if {$slash < 0} {
            return [list [_ipv4_int $address] 32]
        }
        set base [string range $address 0 [expr {$slash - 1}]]
        set prefix [string range $address [expr {$slash + 1}] end]
        if {![string is integer -strict $prefix] || $prefix < 0 || $prefix > 32} {
            error "invalid IPv4 prefix length in \"$address\""
        }
        return [list [_ipv4_int $base] $prefix]
    }

    proc profile_exists {args} {
        if {[llength $args] != 1} {
            error "PROFILE::exists requires a profile name"
        }
        return [_profile_enabled [lindex $args 0]]
    }

    proc profile_clientssl {args} { return [_profile_enabled CLIENTSSL] }
    proc profile_fastL4 {args} { return [_profile_enabled FASTL4] }
    proc profile_fasthttp {args} { return [_profile_enabled FASTHTTP] }
    proc profile_http {args} { return [_profile_enabled HTTP] }
    proc profile_serverssl {args} { return [_profile_enabled SERVERSSL] }
    proc profile_tcp {args} { return [_profile_enabled TCP] }
    proc profile_udp {args} { return [_profile_enabled UDP] }

    proc profile_list {args} {
        if {[llength $args] != 1} {
            error "PROFILE::list requires a profile class"
        }
        set requested [string toupper [lindex $args 0]]
        set result [list]
        foreach profile $::orch::config(profiles) {
            set profile_upper [string toupper $profile]
            if {$requested eq "ALL" || $requested eq "ANY" ||
                $requested eq $profile_upper} {
                lappend result $profile
            }
        }
        return $result
    }

    proc stats_set {args} {
        if {[llength $args] < 3} {
            error "STATS::set requires profile, counter, and value"
        }
        variable stats
        set key [_stat_key [lindex $args 0] [lindex $args 1]]
        set value [lindex $args 2]
        set stats($key) $value
        ::itest::log_decision stats set [list [lindex $args 0] [lindex $args 1] $value]
        return $value
    }

    proc stats_get {args} {
        if {[llength $args] < 2} {
            error "STATS::get requires profile and counter"
        }
        variable stats
        set key [_stat_key [lindex $args 0] [lindex $args 1]]
        if {[info exists stats($key)]} {
            return $stats($key)
        }
        return 0
    }

    proc stats_incr {args} {
        if {[llength $args] < 2} {
            error "STATS::incr requires profile and counter"
        }
        set amount 1
        if {[llength $args] > 2} {
            set amount [lindex $args 2]
        }
        set value [expr {[stats_get [lindex $args 0] [lindex $args 1]] + $amount}]
        stats_set [lindex $args 0] [lindex $args 1] $value
        return $value
    }

    proc stats_setmax {args} {
        if {[llength $args] < 3} {
            error "STATS::setmax requires profile, counter, and value"
        }
        variable stats
        set key [_stat_key [lindex $args 0] [lindex $args 1]]
        set exists [info exists stats($key)]
        set current [stats_get [lindex $args 0] [lindex $args 1]]
        set value [lindex $args 2]
        if {![string is double -strict $current] || ![string is double -strict $value]} {
            error "STATS::setmax values must be numeric"
        }
        if {!$exists || $value > $current} {
            return [stats_set {*}$args]
        }
        return $current
    }

    proc stats_setmin {args} {
        if {[llength $args] < 3} {
            error "STATS::setmin requires profile, counter, and value"
        }
        variable stats
        set key [_stat_key [lindex $args 0] [lindex $args 1]]
        set exists [info exists stats($key)]
        set current [stats_get [lindex $args 0] [lindex $args 1]]
        set value [lindex $args 2]
        if {![string is double -strict $current] || ![string is double -strict $value]} {
            error "STATS::setmin values must be numeric"
        }
        if {!$exists || $value < $current} {
            return [stats_set {*}$args]
        }
        return $current
    }

    proc hsl_open {args} {
        variable hsl_handles
        variable next_hsl_handle
        incr next_hsl_handle
        set handle "hsl$next_hsl_handle"
        set hsl_handles($handle) $args
        ::itest::log_decision hsl open [list $handle $args]
        return $handle
    }

    proc hsl_send {args} {
        if {[llength $args] < 2} {
            error "HSL::send requires a handle and message"
        }
        variable hsl_handles
        variable hsl_messages
        set handle [lindex $args 0]
        if {![info exists hsl_handles($handle)]} {
            error "unknown HSL handle \"$handle\""
        }
        set message [lindex $args 1]
        lappend hsl_messages [list $handle $message]
        ::itest::log_decision hsl send [list $handle $message]
        return 1
    }

    proc http_username {args} {
        return [lindex [_auth_parts] 0]
    }

    proc http_password {args} {
        return [lindex [_auth_parts] 1]
    }

    proc http_response {args} {
        return [_http_message_command response {*}$args]
    }

    proc http_has_responded_command {args} {
        if {[llength $args] != 0} {
            error "HTTP::has_responded takes no arguments"
        }
        if {[info exists ::state::http::response_committed] &&
            $::state::http::response_committed} {
            return 1
        }
        return 0
    }

    proc http_redirect_command {args} {
        if {[llength $args] != 1} {
            error "HTTP::redirect requires a URL"
        }
        if {$::itest::current_event ni {
            CACHE_REQUEST CACHE_RESPONSE HTTP_CLASS_FAILED HTTP_CLASS_SELECTED
            HTTP_REQUEST HTTP_REQUEST_DATA HTTP_RESPONSE HTTP_RESPONSE_DATA
            LB_FAILED NAME_RESOLVED
        }} {
            error "HTTP::redirect is not valid in $::itest::current_event"
        }
        if {[info exists ::state::http::response_committed] &&
            $::state::http::response_committed} {
            error "HTTP response has already been committed"
        }
        set location [lindex $args 0]
        set ::state::http::response::status 302
        set ::state::http::response::reason "Found"
        ::state::http::response::header remove "content-length"
        ::state::http::response::header remove "transfer-encoding"
        ::state::http::response::header set "location" $location
        set ::state::http::response::payload ""
        set ::state::http::response_committed 1
        ::itest::log_decision http redirect $location
        return ""
    }

    proc _http_header_name {name} {
        set parts [split $name -]
        set result [list]
        foreach part $parts {
            if {$part eq ""} {
                lappend result ""
            } else {
                lappend result "[string toupper [string index $part 0]][string range $part 1 end]"
            }
        }
        return [join $result -]
    }

    proc _http_message_command {kind args} {
        if {[llength $args] != 0} {
            error "HTTP::$kind takes no arguments"
        }
        set lines [list]
        if {$kind eq "request"} {
            lappend lines "${::state::http::request::method} ${::state::http::request::uri} HTTP/${::state::http::request::version}"
            set headers $::state::http::request::headers
        } else {
            set status $::state::http::response::status
            set reason $::state::http::response::reason
            if {$reason eq "" || $reason eq "OK"} {
                switch -exact -- $status {
                    200 { set reason "OK" }
                    201 { set reason "Created" }
                    202 { set reason "Accepted" }
                    204 { set reason "No Content" }
                    301 { set reason "Moved Permanently" }
                    302 { set reason "Found" }
                    303 { set reason "See Other" }
                    304 { set reason "Not Modified" }
                    305 { set reason "Use Proxy" }
                    307 { set reason "Temporary Redirect" }
                    400 { set reason "Bad Request" }
                    401 { set reason "Unauthorized" }
                    403 { set reason "Forbidden" }
                    404 { set reason "Not Found" }
                    500 { set reason "Internal Server Error" }
                    501 { set reason "Not Implemented" }
                    502 { set reason "Bad Gateway" }
                    503 { set reason "Service Unavailable" }
                    504 { set reason "Gateway Timeout" }
                }
            }
            lappend lines "HTTP/${::state::http::response::version} $status $reason"
            set headers $::state::http::response::headers
        }
        dict for {name values} $headers {
            foreach value $values {
                lappend lines "[_http_header_name $name]: $value"
            }
        }
        return "[join $lines \r\n]\r\n\r\n"
    }

    proc http_reject_reason {args} {
        if {[info exists ::state::http::reject_reason]} {
            return $::state::http::reject_reason
        }
        return ""
    }

    proc http_passthrough_reason {args} {
        if {[info exists ::state::http::passthrough_reason]} {
            return $::state::http::passthrough_reason
        }
        return ""
    }

    proc ip_version {args} {
        set address $::state::connection::client_addr
        return [expr {[string first : $address] >= 0 ? 6 : 4}]
    }

    proc ip_addr {args} {
        if {[llength $args] == 1} {
            return [lindex $args 0]
        }
        if {[llength $args] < 3} {
            error "IP::addr requires an address, operator, and comparison address"
        }
        set left [lindex $args 0]
        set operator [string tolower [lindex $args 1]]
        set right [lindex $args 2]
        if {$operator in {equals eq ==}} {
            if {[string first / $right] >= 0} {
                lassign [_cidr_parts $right] network prefix
                set mask [expr {$prefix == 0 ? 0 : (0xffffffff << (32 - $prefix)) & 0xffffffff}]
                return [expr {([_ipv4_int $left] & $mask) == ($network & $mask)}]
            }
            if {[string first : $left] >= 0 || [string first : $right] >= 0} {
                return [expr {[string tolower $left] eq [string tolower $right]}]
            }
            return [expr {[_ipv4_int $left] == [_ipv4_int $right]}]
        }
        if {$operator in {not ne !=}} {
            return [expr {![ip_addr $left equals $right]}]
        }
        if {$operator eq "mask"} {
            lassign [_cidr_parts $right] network prefix
            set mask [expr {$prefix == 0 ? 0 : (0xffffffff << (32 - $prefix)) & 0xffffffff}]
            return [expr {([_ipv4_int $left] & $mask) == ($network & $mask)}]
        }
        error "unsupported IP::addr operator \"$operator\""
    }

    proc _lb_target {args} {
        if {[llength $args] == 0} {
            if {$::state::lb::node_addr eq ""} {
                error "LB::up/down requires a target"
            }
            return [list node $::state::lb::node_addr $::state::lb::node_port]
        }
        set kind [string tolower [lindex $args 0]]
        switch -exact -- $kind {
            node {
                if {[llength $args] == 2} {
                    return [list node [lindex $args 1] 0]
                }
                if {[llength $args] >= 3} {
                    return [list node [lindex $args 1] [lindex $args 2]]
                }
                error "LB::up/down node requires an address and optional port"
            }
            pool {
                if {[llength $args] >= 2} {
                    return [list pool [lindex $args 1]]
                }
                if {$::state::lb::pool eq ""} {
                    error "LB::up/down pool requires a pool name"
                }
                return [list pool $::state::lb::pool]
            }
            default {
                # A bare target is treated as a pool name, matching the
                # common operational form used in iRules.
                return [list pool [lindex $args 0]]
            }
        }
    }

    proc _lb_set_status {status args} {
        lassign [_lb_target {*}$args] kind target extra
        if {$kind eq "node"} {
            set key "$target:$extra"
        } else {
            set key "pool:$target"
        }
        ::state::lb::set_node_status $key $status
        ::itest::log_decision lb $status $args
        return ""
    }

    proc _member_status {pool_name member} {
        if {[info exists ::state::lb::node_status(pool:$pool_name)] &&
            $::state::lb::node_status(pool:$pool_name) in {down disabled}} {
            return $::state::lb::node_status(pool:$pool_name)
        }
        if {[info exists ::state::lb::node_status($member)]} {
            return $::state::lb::node_status($member)
        }
        return up
    }

    proc _select_available_member {pool_name {exclude_member ""}} {
        set ::state::lb::selected 0
        if {![info exists ::state::lb::pools($pool_name)]} {
            return 0
        }
        set pool_info $::state::lb::pools($pool_name)
        set members [lindex $pool_info 1]
        foreach member $members {
            if {$exclude_member ne "" && $member eq $exclude_member} {
                continue
            }
            if {[_member_status $pool_name $member] in {down disabled}} {
                continue
            }
            set ::state::lb::pool_member $member
            set colonpos [string last ":" $member]
            if {$colonpos >= 0} {
                set ::state::lb::node_addr [string range $member 0 [expr {$colonpos - 1}]]
                set ::state::lb::node_port [string range $member [expr {$colonpos + 1}] end]
            } else {
                set ::state::lb::node_addr $member
                set ::state::lb::node_port 0
            }
            set ::state::lb::selected 1
            ::itest::log_decision lb pool_member_select $member
            return 1
        }
        set ::state::lb::pool_member ""
        set ::state::lb::node_addr ""
        set ::state::lb::node_port 0
        ::itest::log_decision lb pool_no_available $pool_name
        return 0
    }

    proc pool_status_aware {args} {
        set result [eval [linsert $args 0 ::itest::cmd::_testcl_pool_orig]]
        if {[llength $args] == 0} {
            return $result
        }
        set pool_name [lindex $args 0]
        if {![_select_available_member $pool_name]} {
            variable lb_failure_pending
            variable lb_failure_cause
            set lb_failure_pending 1
            if {$lb_failure_cause eq ""} {
                set lb_failure_cause no_member
            }
        }
        return $result
    }

    proc lb_reselect {args} {
        set pool_name $::state::lb::pool
        set explicit_pool 0
        set index 0
        while {$index < [llength $args]} {
            set option [lindex $args $index]
            if {$option eq "pool" && $index + 1 < [llength $args]} {
                incr index
                set pool_name [lindex $args $index]
                set explicit_pool 1
            } else {
                error "LB::reselect supports pool <name>"
            }
            incr index
        }
        set previous_pool $::state::lb::pool
        set previous_member $::state::lb::pool_member
        set exclude_member ""
        if {$explicit_pool && $previous_pool eq $pool_name} {
            set exclude_member $previous_member
        }
        if {$pool_name ne ""} {
            set ::state::lb::pool $pool_name
            if {![_select_available_member $pool_name $exclude_member]} {
                variable lb_failure_pending
                variable lb_failure_cause
                set lb_failure_pending 1
                if {$lb_failure_cause eq ""} {
                    set lb_failure_cause no_member
                }
            }
        }
        ::itest::log_decision lb reselect $args
        return ""
    }

    proc lb_status {args} {
        set pool_name ""
        set member ""
        set index 0
        while {$index < [llength $args]} {
            set option [lindex $args $index]
            switch -exact -- $option {
                pool {
                    incr index
                    set pool_name [lindex $args $index]
                }
                member {
                    incr index
                    set member [lindex $args $index]
                }
                default {
                    error "LB::status supports pool and member selectors"
                }
            }
            incr index
        }
        if {$pool_name eq ""} {
            set pool_name $::state::lb::pool
        }
        if {$member ne ""} {
            return [_member_status $pool_name $member]
        }
        if {$pool_name ne "" &&
            [info exists ::state::lb::node_status(pool:$pool_name)]} {
            return $::state::lb::node_status(pool:$pool_name)
        }
        if {$pool_name ne "" && [info exists ::state::lb::pools($pool_name)]} {
            foreach candidate [lindex $::state::lb::pools($pool_name) 1] {
                if {[_member_status $pool_name $candidate] ni {down disabled}} {
                    return up
                }
            }
            return down
        }
        return up
    }

    proc _maybe_fire_lb_failed {} {
        variable requested_lb_failure
        variable lb_failure_pending
        variable lb_failure_cause
        variable lb_failure_fired
        if {$lb_failure_fired || $::itest::current_event eq "LB_FAILED"} {
            return
        }
        if {[info exists ::state::http::response_committed] &&
            $::state::http::response_committed} {
            return
        }
        if {$requested_lb_failure ne ""} {
            set cause $requested_lb_failure
        } elseif {$lb_failure_pending &&
                  (![info exists ::state::lb::selected] || !$::state::lb::selected)} {
            set cause $lb_failure_cause
        } else {
            return
        }
        if {$cause eq ""} {
            set cause no_member
        }
        set lb_failure_cause $cause
        set lb_failure_fired 1
        set ::state::lb::failure_cause $cause
        uplevel 1 [list ::itest::_testcl_fire_event_orig LB_FAILED]
    }

    proc _tcp_side {} {
        if {[info exists ::itest::semantic::peer_side]} {
            return $::itest::semantic::peer_side
        }
        if {$::itest::current_event in {
            SERVER_DATA SERVER_CONNECTED SERVER_CLOSED SERVER_INIT
            SERVERSSL_DATA SERVERSSL_HANDSHAKE SERVERSSL_SERVERCERT
            SERVERSSL_SERVERHELLO HTTP_RESPONSE HTTP_RESPONSE_CONTINUE HTTP_RESPONSE_DATA
            HTTP_RESPONSE_RELEASE
        }} {
            return server
        }
        return client
    }

    proc _run_on_side {side script} {
        if {$side ni {client server}} {
            error "connection side must be client or server"
        }
        set had_previous [info exists ::itest::semantic::peer_side]
        if {$had_previous} {
            set previous $::itest::semantic::peer_side
        }
        set ::itest::semantic::peer_side $side
        set rc [catch {uplevel 2 $script} result options]
        if {$had_previous} {
            set ::itest::semantic::peer_side $previous
        } else {
            unset ::itest::semantic::peer_side
        }
        if {$rc} {
            return -options $options $result
        }
        return $result
    }

    proc peer_command {args} {
        if {[llength $args] != 1} { error "peer requires a script" }
        set current [_tcp_side]
        set target [expr {$current eq "client" ? "server" : "client"}]
        return [_run_on_side $target [lindex $args 0]]
    }

    proc clientside_command {args} {
        if {[llength $args] != 1} { error "clientside requires a script" }
        return [_run_on_side client [lindex $args 0]]
    }

    proc serverside_command {args} {
        if {[llength $args] != 1} { error "serverside requires a script" }
        return [_run_on_side server [lindex $args 0]]
    }

    proc _tcp_payload_var {} {
        return "::state::connection::[_tcp_side]_payload"
    }

    proc _tcp_collect_key {} {
        return "__testcl_tcp_collect_[_tcp_side]"
    }

    proc tcp_collect_command {args} {
        if {[llength $args] > 2} {
            error "TCP::collect accepts optional length and skip values"
        }
        set length 0
        set skip 0
        set every_packet 1
        if {[llength $args] > 0} { set length [lindex $args 0] }
        if {[llength $args] > 1} { set skip [lindex $args 1] }
        if {[llength $args] > 0} {
            set every_packet 0
            if {![string is integer -strict $length] || $length <= 0} {
                error "TCP::collect length must be a positive integer"
            }
        }
        if {![string is integer -strict $skip] || $skip < 0} {
            error "TCP::collect skip must be a non-negative integer"
        }
        set ::state::vars::connection_vars([_tcp_collect_key]) \
            [list length $length skip $skip every_packet $every_packet]
        ::itest::log_decision tcp collect \
            [list [_tcp_side] $length $skip $every_packet]
        return ""
    }

    proc tcp_collection_request {side} {
        if {$side ni {client server}} {
            error "TCP collection side must be client or server"
        }
        set key "__testcl_tcp_collect_$side"
        if {[info exists ::state::vars::connection_vars($key)]} {
            return $::state::vars::connection_vars($key)
        }
        return ""
    }

    proc tcp_clear_collection {side} {
        if {$side ni {client server}} {
            error "TCP collection side must be client or server"
        }
        unset -nocomplain ::state::vars::connection_vars(__testcl_tcp_collect_$side)
    }

    proc tcp_clear_event_state {} {
        unset -nocomplain ::state::vars::connection_vars(__testcl_tcp_released)
        unset -nocomplain ::state::vars::connection_vars(__testcl_tcp_emissions)
    }

    proc tcp_event_released {} {
        if {[info exists ::state::vars::connection_vars(__testcl_tcp_released)]} {
            return 1
        }
        return 0
    }

    proc tcp_emission_snapshot {} {
        if {[info exists ::state::vars::connection_vars(__testcl_tcp_emissions)]} {
            return $::state::vars::connection_vars(__testcl_tcp_emissions)
        }
        return ""
    }

    proc tcp_payload_command {args} {
        set payload_var [_tcp_payload_var]
        if {[llength $args] == 0} {
            return [set $payload_var]
        }
        set subcmd [lindex $args 0]
        switch -exact -- $subcmd {
            length {
                if {[llength $args] != 1} { error "TCP::payload length takes no arguments" }
                return [::itest::cmd::_payload_bytelength [set $payload_var]]
            }
            replace {
                if {[llength $args] != 4} {
                    error "TCP::payload replace requires offset, length, and data"
                }
                set offset [lindex $args 1]
                set length [lindex $args 2]
                if {![string is integer -strict $offset] || $offset < 0 ||
                    ![string is integer -strict $length] || $length < 0} {
                    error "TCP::payload replace offsets must be non-negative integers"
                }
                set updated [::itest::cmd::_payload_splice \
                    [set $payload_var] $offset $length [lindex $args 3]]
                set $payload_var $updated
                ::itest::log_decision tcp payload_replace \
                    [list [_tcp_side] $offset $length [lindex $args 3]]
                return ""
            }
            default {
                if {![string is integer -strict $subcmd] || $subcmd < 0 ||
                    [llength $args] != 1} {
                    error "TCP::payload accepts an optional non-negative size"
                }
                return [::itest::cmd::_payload_first [set $payload_var] $subcmd]
            }
        }
    }

    proc tcp_offset_command {args} {
        if {[llength $args] != 0} { error "TCP::offset takes no arguments" }
        return [::itest::cmd::_payload_bytelength [set [_tcp_payload_var]]]
    }

    proc tcp_release_command {args} {
        if {[llength $args] > 1} { error "TCP::release accepts an optional length" }
        set payload_var [_tcp_payload_var]
        set available [::itest::cmd::_payload_bytelength [set $payload_var]]
        set length $available
        if {[llength $args] == 1} { set length [lindex $args 0] }
        if {![string is integer -strict $length] || $length < 0} {
            error "TCP::release length must be a non-negative integer"
        }
        if {$length > $available} { set length $available }
        if {$length > 0} {
            set $payload_var [::itest::cmd::_payload_splice [set $payload_var] 0 $length ""]
        }
        set ::state::vars::connection_vars(__testcl_tcp_released) 1
        tcp_clear_collection [_tcp_side]
        ::itest::log_decision tcp release [list [_tcp_side] $length]
        return $length
    }

    proc tcp_respond_command {args} {
        if {[llength $args] != 1} { error "TCP::respond requires a payload" }
        set response [lindex $args 0]
        lappend ::state::vars::connection_vars(__testcl_tcp_emissions) \
            [list kind data side [_tcp_side] payload $response byte_length [string bytelength $response]]
        ::itest::log_decision tcp respond [list [_tcp_side] $response]
        return ""
    }

    proc tcp_close_command {args} {
        if {[llength $args] != 0} { error "TCP::close takes no arguments" }
        set side [_tcp_side]
        set fin_key "__testcl_tcp_fin_sent_$side"
        if {![info exists ::state::vars::connection_vars($fin_key)]} {
            lappend ::state::vars::connection_vars(__testcl_tcp_emissions) \
                [list kind fin side $side]
            set ::state::vars::connection_vars($fin_key) 1
        }
        set ::state::connection::state closing
        ::itest::log_decision tcp close [list $side]
        return ""
    }

    proc _cookie_in_response {} {
        return [expr {$::itest::current_event in {
            HTTP_RESPONSE HTTP_RESPONSE_DATA HTTP_RESPONSE_RELEASE
        }}]
    }

    proc _cookie_header_values {} {
        if {[_cookie_in_response]} {
            return [::state::http::response::header values "set-cookie"]
        }
        set header [::state::http::request::header get "cookie"]
        if {$header eq ""} { return [list] }
        return [list $header]
    }

    proc _cookie_records {} {
        set records [dict create]
        foreach header [_cookie_header_values] {
            set pair [string trim [lindex [split $header ";"] 0]]
            set equals [string first "=" $pair]
            if {$equals < 1} { continue }
            set name [string trim [string range $pair 0 [expr {$equals - 1}]]]
            set value [string trim [string range $pair [expr {$equals + 1}] end]]
            dict set records $name $value
        }
        return $records
    }

    proc _cookie_write_request {records} {
        set pairs [list]
        foreach name [dict keys $records] {
            lappend pairs "$name=[dict get $records $name]"
        }
        if {[llength $pairs] == 0} {
            ::state::http::request::header remove "cookie"
        } else {
            ::state::http::request::header set "cookie" [join $pairs "; "]
        }
    }

    proc _cookie_response_insert {name value attributes} {
        set header "$name=$value"
        foreach {attribute attribute_value} $attributes {
            if {$attribute_value eq ""} {
                append header "; $attribute"
            } else {
                append header "; $attribute=$attribute_value"
            }
        }
        ::state::http::response::header insert "set-cookie" $header
    }

    proc _cookie_attribute_pairs {args} {
        set attributes [list]
        set index 0
        while {$index < [llength $args]} {
            set attribute [string tolower [lindex $args $index]]
            incr index
            set value ""
            if {$index < [llength $args] &&
                [string tolower [lindex $args $index]] ni {
                    path domain secure httponly maxage expires version comment commenturl ports
                }} {
                set value [lindex $args $index]
                incr index
            }
            switch -exact -- $attribute {
                path { lappend attributes Path $value }
                domain { lappend attributes Domain $value }
                secure { lappend attributes Secure "" }
                httponly { lappend attributes HttpOnly "" }
                maxage { lappend attributes Max-Age $value }
                expires { lappend attributes Expires $value }
                version { lappend attributes Version $value }
                comment { lappend attributes Comment $value }
                commenturl { lappend attributes CommentURL $value }
                ports { lappend attributes Port $value }
                default { error "unsupported HTTP::cookie attribute \"$attribute\"" }
            }
        }
        return $attributes
    }

    proc cookie_command {args} {
        if {[llength $args] == 0} {
            error "HTTP::cookie requires a subcommand"
        }
        set subcmd [string tolower [lindex $args 0]]
        set rest [lrange $args 1 end]
        set records [_cookie_records]
        switch -exact -- $subcmd {
            value {
                if {[llength $rest] < 1 || [llength $rest] > 2} {
                    error "HTTP::cookie value requires a name and optional value"
                }
                set name [lindex $rest 0]
                if {[llength $rest] == 1} {
                    if {[dict exists $records $name]} { return [dict get $records $name] }
                    return ""
                }
                set value [lindex $rest 1]
                if {[_cookie_in_response]} {
                    _cookie_response_insert $name $value [list]
                } else {
                    dict set records $name $value
                    _cookie_write_request $records
                }
                ::itest::log_decision http cookie_value_set [list $name $value]
                return ""
            }
            names { return [dict keys $records] }
            count { return [dict size $records] }
            exists {
                if {[llength $rest] != 1} { error "HTTP::cookie exists requires a name" }
                return [dict exists $records [lindex $rest 0]]
            }
            insert {
                set name_index [lsearch -exact $rest name]
                set value_index [lsearch -exact $rest value]
                if {$name_index < 0 || $value_index < 0 ||
                    $name_index + 1 >= [llength $rest] ||
                    $value_index + 1 >= [llength $rest]} {
                    error "HTTP::cookie insert requires name and value pairs"
                }
                set name [lindex $rest [expr {$name_index + 1}]]
                set value [lindex $rest [expr {$value_index + 1}]]
                set attributes [list]
                if {$value_index + 2 < [llength $rest]} {
                    set attributes [_cookie_attribute_pairs \
                        {*}[lrange $rest [expr {$value_index + 2}] end]]
                }
                if {[_cookie_in_response]} {
                    _cookie_response_insert $name $value $attributes
                } else {
                    dict set records $name $value
                    _cookie_write_request $records
                }
                ::itest::log_decision http cookie_insert [list $name $value]
                return ""
            }
            remove {
                if {[llength $rest] != 1} { error "HTTP::cookie remove requires a name" }
                set name [lindex $rest 0]
                if {[_cookie_in_response]} {
                    _cookie_response_insert $name "" [list Max-Age 0]
                } elseif {[dict exists $records $name]} {
                    dict unset records $name
                    _cookie_write_request $records
                }
                ::itest::log_decision http cookie_remove $name
                return ""
            }
            default {
                return [eval [linsert $args 0 ::itest::cmd::_testcl_http_cookie_orig]]
            }
        }
    }

    proc _class_parse_options {args} {
        set options [dict create \
            all 0 \
            value 0 \
            name 0 \
            index 0 \
            element 0 \
            nocase 0 \
            list 0]
        set positional [list]
        set stop_options 0
        foreach arg $args {
            if {!$stop_options && $arg eq "--"} {
                set stop_options 1
                continue
            }
            if {!$stop_options && [string match -* $arg]} {
                switch -exact -- $arg {
                    -all { dict set options all 1 }
                    -value { dict set options value 1 }
                    -name { dict set options name 1 }
                    -index { dict set options index 1 }
                    -element { dict set options element 1 }
                    -nocase { dict set options nocase 1 }
                    -list { dict set options list 1 }
                    default { error "unsupported class option \"$arg\"" }
                }
            } else {
                lappend positional $arg
            }
        }
        if {[dict get $options value] && [dict get $options name]} {
            error "class -value and -name are mutually exclusive"
        }
        return [list $options $positional]
    }

    proc _class_group {name} {
        if {![info exists ::state::datagroup::groups($name)]} {
            error "class \"$name\" not found"
        }
        set group $::state::datagroup::groups($name)
        return [list [lindex $group 1] [lindex $group 3]]
    }

    proc _class_equal {left right nocase} {
        if {$nocase} {
            return [expr {[string tolower $left] eq [string tolower $right]}]
        }
        return [expr {$left eq $right}]
    }

    proc _class_compare {left operator right nocase} {
        set op [string tolower $operator]
        if {$nocase} {
            set left [string tolower $left]
            set right [string tolower $right]
        }
        switch -exact -- $op {
            equals - eq { return [expr {$left eq $right}] }
            contains { return [expr {[string first $right $left] >= 0}] }
            starts_with { return [expr {[string first $right $left] == 0}] }
            ends_with {
                return [expr {[string last $right $left] ==
                    ([string length $left] - [string length $right])}]
            }
            matches_glob { return [string match $right $left] }
            matches_regex {
                if {$nocase} { return [regexp -nocase -- $right $left] }
                return [regexp -- $right $left]
            }
            default { error "unsupported class operator \"$operator\"" }
        }
    }

    proc _class_matching_records {type records item operator nocase check_value} {
        set matches [list]
        set index 0
        foreach {name value} $records {
            set candidate [expr {$check_value ? $value : $name}]
            if {[_class_compare $item $operator $candidate $nocase]} {
                lappend matches [list $index $name $value]
            }
            incr index
        }
        return $matches
    }

    proc _class_result {matches options} {
        if {[llength $matches] == 0} {
            if {[dict get $options all] || [dict get $options list] ||
                [dict get $options value] || [dict get $options name] ||
                [dict get $options index] || [dict get $options element]} {
                return [list]
            }
            return 0
        }
        set output [list]
        foreach match $matches {
            lassign $match index name value
            if {[dict get $options value]} {
                lappend output $value
            } elseif {[dict get $options index]} {
                lappend output $index
            } elseif {[dict get $options element]} {
                lappend output [list $name $value]
            } elseif {[dict get $options name]} {
                lappend output $name
            } else {
                return 1
            }
        }
        if {[dict get $options all] || [dict get $options list]} {
            return $output
        }
        return [lindex $output 0]
    }

    proc _class_search_state {} {
        if {![info exists ::state::vars::connection_vars(__testcl_class_searches)]} {
            set ::state::vars::connection_vars(__testcl_class_searches) [dict create \
                next_id 0 searches [dict create]]
        }
        return $::state::vars::connection_vars(__testcl_class_searches)
    }

    proc class_command {args} {
        if {[llength $args] == 0} {
            error "class requires a subcommand"
        }
        set subcmd [string tolower [lindex $args 0]]
        lassign [_class_parse_options {*}[lrange $args 1 end]] options positional
        switch -exact -- $subcmd {
            match - search {
                if {[llength $positional] != 3} {
                    error "class $subcmd requires item, operator, and class"
                }
                if {$subcmd eq "match"} {
                    set item [lindex $positional 0]
                    set operator [lindex $positional 1]
                    set class_name [lindex $positional 2]
                } else {
                    set class_name [lindex $positional 0]
                    set operator [lindex $positional 1]
                    set item [lindex $positional 2]
                }
                lassign [_class_group $class_name] type records
                set check_value [dict get $options value]
                set matches [_class_matching_records $type $records $item $operator \
                    [dict get $options nocase] $check_value]
                return [_class_result $matches $options]
            }
            lookup {
                if {[llength $positional] != 2} {
                    error "class lookup requires a name and class"
                }
                lassign [_class_group [lindex $positional 1]] type records
                foreach {name value} $records {
                    if {[_class_equal $name [lindex $positional 0] [dict get $options nocase]]} {
                        return $value
                    }
                }
                return ""
            }
            element {
                if {[llength $positional] != 2} {
                    error "class element requires an index and class"
                }
                set index [lindex $positional 0]
                if {![string is integer -strict $index] || $index < 0} {
                    error "class element index must be a non-negative integer"
                }
                lassign [_class_group [lindex $positional 1]] type records
                set entries [list]
                foreach {name value} $records {
                    lappend entries [list $name $value]
                }
                if {$index >= [llength $entries]} { return "" }
                lassign [lindex $entries $index] name value
                if {[dict get $options value]} { return $value }
                if {[dict get $options name]} { return $name }
                return [list $name $value]
            }
            type {
                if {[llength $positional] != 1} { error "class type requires a class" }
                lassign [_class_group [lindex $positional 0]] type ignored
                return $type
            }
            exists {
                if {[llength $positional] != 1} { error "class exists requires a class" }
                return [expr {[info exists ::state::datagroup::groups([lindex $positional 0])]}]
            }
            size {
                if {[llength $positional] != 1} { error "class size requires a class" }
                lassign [_class_group [lindex $positional 0]] type records
                return [expr {[llength $records] / 2}]
            }
            names - get {
                if {[llength $positional] < 1 || [llength $positional] > 2} {
                    error "class $subcmd requires a class and optional pattern"
                }
                set class_name [lindex $positional 0]
                lassign [_class_group $class_name] type records
                set pattern "*"
                if {[llength $positional] == 2} { set pattern [lindex $positional 1] }
                set result [list]
                foreach {name value} $records {
                    set match_name $name
                    set match_pattern $pattern
                    if {[dict get $options nocase]} {
                        set match_name [string tolower $match_name]
                        set match_pattern [string tolower $match_pattern]
                    }
                    if {[string match $match_pattern $match_name]} {
                        if {$subcmd eq "names"} {
                            lappend result $name
                        } else {
                            lappend result $name $value
                        }
                    }
                }
                if {[dict get $options list] || $subcmd eq "get"} { return $result }
                return $result
            }
            startsearch {
                if {[llength $positional] != 1} { error "class startsearch requires a class" }
                set class_name [lindex $positional 0]
                lassign [_class_group $class_name] type records
                set state [_class_search_state]
                set next_id [expr {[dict get $state next_id] + 1}]
                set search_id "search$next_id"
                set searches [dict get $state searches]
                dict set searches $search_id [list class $class_name names \
                    [::state::datagroup::names $class_name] index 0]
                dict set state next_id $next_id
                dict set state searches $searches
                set ::state::vars::connection_vars(__testcl_class_searches) $state
                return $search_id
            }
            nextelement {
                if {[llength $positional] != 1} { error "class nextelement requires a search id" }
                set state [_class_search_state]
                set searches [dict get $state searches]
                set search_id [lindex $positional 0]
                if {![dict exists $searches $search_id]} { error "invalid class search id" }
                set search [dict get $searches $search_id]
                set names [dict get $search names]
                set index [dict get $search index]
                if {$index >= [llength $names]} { return "" }
                set name [lindex $names $index]
                dict set search index [expr {$index + 1}]
                dict set searches $search_id $search
                dict set state searches $searches
                set ::state::vars::connection_vars(__testcl_class_searches) $state
                if {[dict get $options value]} {
                    return [::state::datagroup::lookup [dict get $search class] $name]
                }
                return $name
            }
            anymore {
                if {[llength $positional] != 1} { error "class anymore requires a search id" }
                set state [_class_search_state]
                set searches [dict get $state searches]
                set search_id [lindex $positional 0]
                if {![dict exists $searches $search_id]} { return 0 }
                set search [dict get $searches $search_id]
                return [expr {[dict get $search index] < [llength [dict get $search names]]}]
            }
            donesearch {
                if {[llength $positional] != 1} { error "class donesearch requires a search id" }
                set state [_class_search_state]
                set searches [dict get $state searches]
                dict unset searches [lindex $positional 0]
                dict set state searches $searches
                set ::state::vars::connection_vars(__testcl_class_searches) $state
                return ""
            }
            default { error "unsupported class subcommand \"$subcmd\"" }
        }
    }

    proc _table_parse_options {args} {
        set options [dict create \
            subtable "" \
            mustexist 0 \
            excl 0 \
            notouch 0 \
            georedundancy 0 \
            remaining 0 \
            count 0 \
            all 0]
        set positional [list]
        set stop_options 0
        set index 0
        while {$index < [llength $args]} {
            set arg [lindex $args $index]
            if {!$stop_options && $arg eq "--"} {
                set stop_options 1
                incr index
                continue
            }
            if {!$stop_options && [string match -* $arg]} {
                switch -exact -- $arg {
                    -mustexist { dict set options mustexist 1 }
                    -excl { dict set options excl 1 }
                    -notouch { dict set options notouch 1 }
                    -georedundancy { dict set options georedundancy 1 }
                    -remaining { dict set options remaining 1 }
                    -count { dict set options count 1 }
                    -all { dict set options all 1 }
                    -subtable {
                        incr index
                        if {$index >= [llength $args]} {
                            error "table -subtable requires a name"
                        }
                        dict set options subtable [lindex $args $index]
                    }
                    default { error "unsupported table option \"$arg\"" }
                }
            } else {
                lappend positional $arg
            }
            incr index
        }
        if {[dict get $options mustexist] && [dict get $options excl]} {
            error "table -mustexist and -excl are mutually exclusive"
        }
        return [list $options $positional]
    }

    proc _table_duration {value label} {
        if {[string tolower $value] eq "indefinite"} {
            return 0
        }
        if {![string is integer -strict $value] || $value < 0} {
            error "table $label must be a non-negative integer or indefinite"
        }
        return $value
    }

    proc _table_new_record {value lifetime timeout} {
        set now [clock seconds]
        return [list \
            value $value \
            lifetime $lifetime \
            timeout $timeout \
            created $now \
            touched $now]
    }

    proc _table_put {subtable key record} {
        if {![info exists ::state::table::tables($subtable)]} {
            set ::state::table::tables($subtable) [dict create]
        }
        dict set ::state::table::tables($subtable) $key $record
    }

    proc _table_remove {subtable key} {
        if {![info exists ::state::table::tables($subtable)]} {
            return
        }
        set bucket $::state::table::tables($subtable)
        if {[dict exists $bucket $key]} {
            dict unset bucket $key
            set ::state::table::tables($subtable) $bucket
        }
    }

    proc _table_fetch {subtable key {touch 1}} {
        if {![info exists ::state::table::tables($subtable)]} {
            return [list 0 [list]]
        }
        set bucket $::state::table::tables($subtable)
        if {![dict exists $bucket $key]} {
            return [list 0 [list]]
        }
        set record [dict get $bucket $key]
        if {[catch {dict size $record}]} {
            # Normalize records created by the upstream mock before this
            # adapter overlay was loaded.
            set value [lindex $record 0]
            set timeout [lindex $record 1]
            set lifetime [lindex $record 2]
            set record [_table_new_record $value $lifetime $timeout]
        }
        set now [clock seconds]
        set lifetime [dict get $record lifetime]
        set timeout [dict get $record timeout]
        set created [dict get $record created]
        set touched [dict get $record touched]
        if {($lifetime > 0 && $now >= ($created + $lifetime)) ||
            ($timeout > 0 && $now >= ($touched + $timeout))} {
            _table_remove $subtable $key
            return [list 0 [list]]
        }
        if {$touch} {
            dict set record touched $now
            _table_put $subtable $key $record
        }
        return [list 1 $record]
    }

    proc _table_remaining {record field} {
        set duration [dict get $record $field]
        if {$duration == 0} {
            return 0
        }
        if {$field eq "lifetime"} {
            set expires [expr {[dict get $record created] + $duration}]
        } else {
            set expires [expr {[dict get $record touched] + $duration}]
        }
        set remaining [expr {$expires - [clock seconds]}]
        if {$remaining < 0} { return 0 }
        return $remaining
    }

    proc table_command {args} {
        if {[llength $args] == 0} {
            error "table requires a subcommand"
        }
        set subcmd [string tolower [lindex $args 0]]
        lassign [_table_parse_options {*}[lrange $args 1 end]] options positional
        set subtable [dict get $options subtable]
        set touch [expr {![dict get $options notouch]}]
        switch -exact -- $subcmd {
            set - add - replace {
                if {[llength $positional] < 2 || [llength $positional] > 4} {
                    error "table $subcmd requires key, value, optional lifetime, and timeout"
                }
                set key [lindex $positional 0]
                set value [lindex $positional 1]
                set lifetime 0
                set timeout 0
                if {[llength $positional] > 2} {
                    set lifetime [_table_duration [lindex $positional 2] lifetime]
                }
                if {[llength $positional] > 3} {
                    set timeout [_table_duration [lindex $positional 3] timeout]
                }
                lassign [_table_fetch $subtable $key 0] exists ignored
                if {$subcmd eq "add" && $exists} {
                    error "table add key already exists"
                }
                if {$subcmd eq "replace" && !$exists} {
                    error "table replace key does not exist"
                }
                if {[dict get $options mustexist] && !$exists} {
                    error "table -mustexist key does not exist"
                }
                if {[dict get $options excl] && $exists} {
                    error "table -excl key already exists"
                }
                _table_put $subtable $key [_table_new_record $value $lifetime $timeout]
                ::itest::log_decision table $subcmd [list $subtable $key $value]
                return $value
            }
            lookup {
                if {[llength $positional] != 1} {
                    error "table lookup requires a key"
                }
                lassign [_table_fetch $subtable [lindex $positional 0] $touch] exists record
                if {!$exists} { return "" }
                if {[dict get $options remaining]} {
                    return [_table_remaining $record timeout]
                }
                return [dict get $record value]
            }
            incr {
                if {[llength $positional] < 1 || [llength $positional] > 2} {
                    error "table incr requires a key and optional amount"
                }
                set key [lindex $positional 0]
                set amount 1
                if {[llength $positional] == 2} {
                    set amount [lindex $positional 1]
                }
                if {![string is integer -strict $amount]} {
                    error "table incr amount must be an integer"
                }
                lassign [_table_fetch $subtable $key $touch] exists record
                if {!$exists} {
                    set record [_table_new_record 0 0 0]
                }
                set current [dict get $record value]
                if {![string is integer -strict $current]} {
                    error "table incr value must be an integer"
                }
                set value [expr {$current + $amount}]
                dict set record value $value
                if {$touch} { dict set record touched [clock seconds] }
                _table_put $subtable $key $record
                ::itest::log_decision table incr [list $subtable $key $amount]
                return $value
            }
            append {
                if {[llength $positional] != 2} {
                    error "table append requires a key and string"
                }
                set key [lindex $positional 0]
                lassign [_table_fetch $subtable $key $touch] exists record
                if {!$exists} {
                    set record [_table_new_record "" 0 0]
                }
                set value "[dict get $record value][lindex $positional 1]"
                dict set record value $value
                if {$touch} { dict set record touched [clock seconds] }
                _table_put $subtable $key $record
                ::itest::log_decision table append [list $subtable $key $value]
                return $value
            }
            delete {
                if {[dict get $options all]} {
                    if {[llength $positional] != 0} {
                        error "table delete -all does not accept a key"
                    }
                    unset -nocomplain ::state::table::tables($subtable)
                    ::itest::log_decision table delete_all $subtable
                    return ""
                }
                if {[llength $positional] != 1} {
                    error "table delete requires a key"
                }
                _table_remove $subtable [lindex $positional 0]
                ::itest::log_decision table delete [list $subtable [lindex $positional 0]]
                return ""
            }
            timeout - lifetime {
                if {[llength $positional] < 1 || [llength $positional] > 2} {
                    error "table $subcmd requires a key and optional value"
                }
                set key [lindex $positional 0]
                lassign [_table_fetch $subtable $key $touch] exists record
                if {!$exists} { return 0 }
                if {[llength $positional] == 1} {
                    if {[dict get $options remaining]} {
                        return [_table_remaining $record $subcmd]
                    }
                    return [dict get $record $subcmd]
                }
                set duration [_table_duration [lindex $positional 1] $subcmd]
                dict set record $subcmd $duration
                if {$touch} { dict set record touched [clock seconds] }
                _table_put $subtable $key $record
                return $duration
            }
            keys {
                if {[llength $positional] > 1} {
                    error "table keys accepts an optional pattern"
                }
                set pattern "*"
                if {[llength $positional] == 1} {
                    set pattern [lindex $positional 0]
                }
                set result [list]
                if {[info exists ::state::table::tables($subtable)]} {
                    foreach key [dict keys $::state::table::tables($subtable)] {
                        lassign [_table_fetch $subtable $key $touch] exists ignored
                        if {$exists && [string match $pattern $key]} {
                            lappend result $key
                        }
                    }
                }
                if {[dict get $options count]} {
                    return [llength $result]
                }
                return $result
            }
            default {
                error "unsupported table subcommand \"$subcmd\""
            }
        }
    }

    proc table_snapshot {} {
        set result [list]
        foreach subtable [array names ::state::table::tables] {
            set bucket $::state::table::tables($subtable)
            foreach key [dict keys $bucket] {
                lassign [_table_fetch $subtable $key 0] exists record
                if {$exists} {
                    lappend result [list \
                        subtable $subtable \
                        key $key \
                        value [dict get $record value] \
                        lifetime [dict get $record lifetime] \
                        timeout [dict get $record timeout]]
                }
            }
        }
        return $result
    }

    proc _persist_key {kind key} {
        return "[string tolower $kind]|$key"
    }

    proc _persist_member_fields {member fallback_port} {
        set colonpos [string last ":" $member]
        if {$colonpos < 0} {
            return [list $member $fallback_port]
        }
        return [list \
            [string range $member 0 [expr {$colonpos - 1}]] \
            [string range $member [expr {$colonpos + 1}] end]]
    }

    proc _persist_record {pool member timeout} {
        set node $::state::lb::node_addr
        set port $::state::lb::node_port
        if {$member ne ""} {
            lassign [_persist_member_fields $member $port] node port
        }
        return [list \
            pool $pool \
            node $node \
            port $port \
            member $member \
            timeout $timeout \
            created [clock seconds]]
    }

    proc _persist_lookup {kind key} {
        set stored [::state::persist::lookup_entry [_persist_key $kind $key]]
        if {$stored eq ""} {
            return [list]
        }
        if {[dict exists $stored timeout] && [dict exists $stored created] &&
            [dict get $stored timeout] > 0 &&
            [clock seconds] >= ([dict get $stored created] + [dict get $stored timeout])} {
            _persist_delete $kind $key
            return [list]
        }
        return $stored
    }

    proc _persist_delete {kind key} {
        set entries $::state::persist::entries
        set entry_key [_persist_key $kind $key]
        if {[dict exists $entries $entry_key]} {
            dict unset entries $entry_key
            set ::state::persist::entries $entries
        }
    }

    proc _persist_command {args} {
        set subcmd [string tolower [lindex $args 0]]
        switch -exact -- $subcmd {
            add {
                if {[llength $args] < 3} {
                    error "persist add requires a type and key"
                }
                set kind [lindex $args 1]
                set key [lindex $args 2]
                set kind [string tolower $kind]
                if {$key eq ""} {
                    error "persist add requires a non-empty key"
                }
                if {$kind ne "uie"} {
                    error "persist add currently supports uie records only"
                }
                set extra [lrange $args 3 end]
                set timeout 0
                set pool $::state::lb::pool
                set member $::state::lb::pool_member
                if {[llength $extra] > 0} {
                    set timeout [lindex $extra 0]
                    if {![string is integer -strict $timeout] || $timeout < 0} {
                        error "persist add timeout must be a non-negative integer"
                    }
                }
                if {[llength $extra] > 1} {
                    set pool [lindex $extra 1]
                }
                if {[llength $extra] > 2} {
                    set member [lindex $extra 2]
                }
                if {[llength $extra] > 3} {
                    error "persist add accepts timeout, pool, and node only"
                }
                if {[llength $extra] > 2} {
                    set member [lindex $extra 2]
                } elseif {$member eq "" && $::state::lb::node_addr ne ""} {
                    set member "$::state::lb::node_addr:$::state::lb::node_port"
                }
                if {$member eq ""} {
                    error "persist add requires a selected pool member or node"
                }
                ::state::persist::add [_persist_key $kind $key] [_persist_record $pool $member $timeout]
                ::itest::log_decision persist add [list $kind $key $timeout $pool $member]
                return ""
            }
            lookup {
                if {[llength $args] < 3 || [llength $args] > 4} {
                    error "persist lookup requires a type and key"
                }
                set record [_persist_lookup [lindex $args 1] [lindex $args 2]]
                if {[llength $args] < 4} {
                    if {[llength $record] == 0} { return "" }
                    return [dict get $record member]
                }
                set selector [string tolower [lindex $args 3]]
                if {[llength $record] == 0} { return "" }
                switch -exact -- $selector {
                    all { return $record }
                    node { return [dict get $record node] }
                    port { return [dict get $record port] }
                    pool { return [dict get $record pool] }
                    default { error "unsupported persist lookup selector \"$selector\"" }
                }
            }
            delete {
                if {[llength $args] != 3} {
                    error "persist delete requires a type and key"
                }
                _persist_delete [lindex $args 1] [lindex $args 2]
                ::itest::log_decision persist delete [lrange $args 1 2]
                return ""
            }
            default {
                if {$subcmd eq "cookie"} {
                    set ::state::persist::mode cookie
                    set rest [lrange $args 1 end]
                    set cookie_mode [string tolower [lindex $rest 0]]
                    switch -exact -- $cookie_mode {
                        insert - rewrite {
                            if {[llength $rest] > 3} {
                                error "persist cookie $cookie_mode accepts a name and expiration"
                            }
                            if {[llength $rest] > 1} {
                                set ::state::persist::cookie_name [lindex $rest 1]
                            }
                        }
                        passive {
                            if {[llength $rest] > 2} {
                                error "persist cookie passive accepts a name"
                            }
                            if {[llength $rest] > 1} {
                                set ::state::persist::cookie_name [lindex $rest 1]
                            }
                        }
                        hash {
                            if {[llength $rest] < 2 || [llength $rest] > 5} {
                                error "persist cookie hash requires a name and optional hash parameters"
                            }
                            set ::state::persist::cookie_name [lindex $rest 1]
                        }
                        default {
                            if {[llength $rest] > 1} {
                                error "persist cookie accepts one cookie name or a cookie mode"
                            }
                            if {[llength $rest] == 1 && $cookie_mode ne ""} {
                                set ::state::persist::cookie_name $cookie_mode
                            }
                        }
                    }
                    ::itest::log_decision persist mode $args
                    return ""
                }
                return [eval [linsert $args 0 ::itest::cmd::_testcl_persist_orig]]
            }
        }
    }

    proc lb_persist {args} {
        if {[llength $args] > 1} {
            error "LB::persist accepts one key or cookie selector"
        }
        if {[llength $args] == 0} {
            return $::state::lb::pool_member
        }
        set key [lindex $args 0]
        set kind uie
        if {[string tolower $key] eq "cookie"} {
            set key [::itest::cmd::http_cookie value $::state::persist::cookie_name]
            set kind cookie
        }
        set record [_persist_lookup $kind $key]
        if {[llength $record] == 0} {
            ::itest::log_decision lb persist_miss $key
            return ""
        }
        set member [dict get $record member]
        if {$member eq ""} {
            ::itest::log_decision lb persist_miss $key
            return ""
        }
        if {[_member_status [dict get $record pool] $member] in {down disabled}} {
            ::itest::log_decision lb persist_unavailable [list $key $member]
            return ""
        }
        if {[dict get $record pool] ne ""} {
            set ::state::lb::pool [dict get $record pool]
        }
        set ::state::lb::pool_member $member
        set ::state::lb::node_addr [dict get $record node]
        set ::state::lb::node_port [dict get $record port]
        set ::state::lb::selected 1
        ::itest::log_decision lb persist_hit $key
        return $member
    }

    proc lb_down {args} { return [_lb_set_status down {*}$args] }
    proc lb_up {args} { return [_lb_set_status up {*}$args] }

    proc uri_host {args} {
        return [dict get [_uri_parts [_uri_input {*}$args]] host]
    }

    proc uri_path {args} {
        return [dict get [_uri_parts [_uri_input {*}$args]] path]
    }

    proc uri_query {args} {
        return [dict get [_uri_parts [_uri_input {*}$args]] query]
    }

    proc uri_protocol {args} {
        return [dict get [_uri_parts [_uri_input {*}$args]] scheme]
    }

    proc uri_port {args} {
        set parts [_uri_parts [_uri_input {*}$args]]
        set port [dict get $parts port]
        if {$port ne ""} {
            return $port
        }
        set scheme [dict get $parts scheme]
        if {$scheme eq "https"} { return 443 }
        if {$scheme eq "http"} { return 80 }
        return 0
    }

    proc uri_basename {args} {
        set path [dict get [_uri_parts [_uri_input {*}$args]] path]
        set path [string trimright $path /]
        if {$path eq ""} { return "" }
        return [lindex [split $path /] end]
    }

    proc uri_encode {args} {
        if {[llength $args] != 1} { error "URI::encode requires one value" }
        return [_uri_encode_value [lindex $args 0] 0]
    }

    proc uri_encode_component {args} {
        if {[llength $args] != 1} { error "URI::encode_component requires one value" }
        return [_uri_encode_value [lindex $args 0] 1]
    }

    proc uri_decode {args} {
        if {[llength $args] != 1} { error "URI::decode requires one value" }
        return [_uri_decode_value [lindex $args 0]]
    }

    proc _uri_canonical {uri} {
        set parts [_uri_parts $uri]
        set scheme [string tolower [dict get $parts scheme]]
        set host [string tolower [dict get $parts host]]
        set port [dict get $parts port]
        if {($scheme eq "http" && $port eq "80") ||
            ($scheme eq "https" && $port eq "443")} {
            set port ""
        }
        set path [dict get $parts path]
        if {$path eq ""} {
            set path "/"
        }
        return [list \
            scheme $scheme \
            host $host \
            port $port \
            path $path \
            query [dict get $parts query]]
    }

    proc uri_compare {args} {
        if {[llength $args] != 2} {
            error "URI::compare requires two URI strings"
        }
        return [expr {[_uri_canonical [lindex $args 0]] eq
                     [_uri_canonical [lindex $args 1]]}]
    }

    proc uri_escape {args} {
        if {[llength $args] != 1} { error "URI::escape requires one value" }
        return [_uri_encode_value [lindex $args 0] 0]
    }

    # ── HTTP/2 transaction state ──────────────────────────────────────
    # The adapter supplies decoded transaction metadata. These commands
    # model the iRule-visible state without implementing an HTTP/2 frame
    # parser or a live multiplexing endpoint.
    proc http2_active_command {args} {
        if {[llength $args] != 0} { error "HTTP2::active takes no arguments" }
        return [expr {$::state::http2::active && $::state::http2::enabled}]
    }

    proc http2_set_pending {args} {
        variable http2_pending
        if {[llength $args] != 12} { error "invalid pending HTTP2 state" }
        set fields {
            active version stream_id stream_priority concurrency requests enabled
            clientside_enabled serverside_enabled disconnected discarded pseudo_headers
        }
        set http2_pending [dict create]
        foreach field $fields value $args {
            dict set http2_pending $field $value
        }
    }

    proc http2_clear_pending {} {
        variable http2_pending
        set http2_pending [dict create]
    }

    proc http2_apply_pending {} {
        variable http2_pending
        if {[dict size $http2_pending] == 0} { return }
        foreach field {
            active version stream_id stream_priority concurrency requests enabled
            clientside_enabled serverside_enabled disconnected discarded pseudo_headers
        } {
            set ::state::http2::$field [dict get $http2_pending $field]
        }
    }

    proc http2_concurrency_command {args} {
        if {[llength $args] != 0} { error "HTTP2::concurrency takes no arguments" }
        return $::state::http2::concurrency
    }

    proc _http2_set_enabled {side value} {
        if {$side eq "clientside"} {
            set ::state::http2::clientside_enabled $value
        } elseif {$side eq "serverside"} {
            set ::state::http2::serverside_enabled $value
        } else {
            set ::state::http2::clientside_enabled $value
            set ::state::http2::serverside_enabled $value
        }
        set ::state::http2::enabled [expr {$::state::http2::clientside_enabled &&
            $::state::http2::serverside_enabled}]
    }

    proc _http2_control_command {operation args} {
        set side ""
        set discard 0
        foreach arg $args {
            if {$arg in {clientside serverside}} {
                if {$side ne ""} { error "HTTP2::$operation accepts at most one side" }
                set side $arg
            } elseif {$arg eq "discard" && $operation eq "disable"} {
                if {$discard} { error "HTTP2::disable accepts discard once" }
                set discard 1
            } else {
                error "HTTP2::$operation received unsupported option $arg"
            }
        }
        _http2_set_enabled $side [expr {$operation eq "enable"}]
        if {$operation eq "disable" && $discard} {
            set ::state::http2::discarded 1
        }
        ::itest::log_decision http2 $operation [concat $side [expr {$discard ? {discard} : {}}]]
        return ""
    }

    proc http2_disable_command {args} {
        return [_http2_control_command disable {*}$args]
    }

    proc http2_enable_command {args} {
        return [_http2_control_command enable {*}$args]
    }

    proc http2_disconnect_command {args} {
        if {[llength $args] != 0} { error "HTTP2::disconnect takes no arguments" }
        set ::state::http2::disconnected 1
        ::itest::log_decision http2 disconnect
        return ""
    }

    proc http2_requests_command {args} {
        if {[llength $args] != 0} { error "HTTP2::requests takes no arguments" }
        return $::state::http2::requests
    }

    proc http2_version_command {args} {
        if {[llength $args] != 0} { error "HTTP2::version takes no arguments" }
        return [expr {[http2_active_command] ? $::state::http2::version : 0}]
    }

    proc http2_header_command {args} {
        if {[llength $args] < 1 || [llength $args] > 3} {
            error "HTTP2::header requires a name or a mutation"
        }
        set operation [lindex $args 0]
        if {$operation eq "replace"} {
            if {[llength $args] ni {2 3}} { error "HTTP2::header replace requires a name and optional value" }
            set name [lindex $args 1]
            set value [expr {[llength $args] == 3 ? [lindex $args 2] : ""}]
            if {![string match :* $name] || $name ne [string tolower $name]} {
                error "HTTP2 pseudo-header names must be lowercase and begin with :"
            }
            dict set ::state::http2::pseudo_headers $name $value
            ::itest::log_decision http2 header_replace [list $name $value]
            return ""
        }
        if {$operation eq "remove"} {
            if {[llength $args] != 2} { error "HTTP2::header remove requires a name" }
            set name [lindex $args 1]
            if {[dict exists $::state::http2::pseudo_headers $name]} {
                dict unset ::state::http2::pseudo_headers $name
            }
            ::itest::log_decision http2 header_remove $name
            return ""
        }
        if {[llength $args] != 1} { error "HTTP2::header getter requires one name" }
        if {[dict exists $::state::http2::pseudo_headers $operation]} {
            return [dict get $::state::http2::pseudo_headers $operation]
        }
        return ""
    }

    proc http2_stream_command {args} {
        if {[llength $args] > 2} { error "HTTP2::stream accepts an optional selector and value" }
        if {[llength $args] == 0 || [lindex $args 0] eq "id"} {
            if {[llength $args] == 2} { error "HTTP2::stream id takes no value" }
            return $::state::http2::stream_id
        }
        if {[lindex $args 0] ne "priority"} {
            error "HTTP2::stream selector must be id or priority"
        }
        if {[llength $args] == 1} { return $::state::http2::stream_priority }
        set value [lindex $args 1]
        if {![string is integer -strict $value] || $value < 0 || $value > 255} {
            error "HTTP2 stream priority must be between 0 and 255"
        }
        set ::state::http2::stream_priority $value
        ::itest::log_decision http2 stream_priority_set $value
        return 0
    }

    # ── TLS/SSL inspection and control semantics ─────────────────────
    proc _ssl_namespace {{side ""}} {
        if {$side eq "serverside" || [string match "SERVERSSL_*" $::itest::current_event]} {
            return ::state::tls::server
        }
        return ::state::tls::client
    }

    proc _ssl_value {field {default ""}} {
        set variable [_ssl_namespace]::$field
        if {[info exists $variable]} { return [set $variable] }
        return $default
    }

    proc ssl_sni_command {args} {
        if {[llength $args] != 1 || [lindex $args 0] ni {name required}} {
            error "SSL::sni requires name or required"
        }
        set field [lindex $args 0]
        if {$field eq "name"} { return [_ssl_value sni] }
        return [_ssl_value sni_required 0]
    }

    proc ssl_cipher_command {args} {
        if {[llength $args] != 1 || [lindex $args 0] ni {bits name version clientlist}} {
            error "SSL::cipher requires bits, name, version, or clientlist"
        }
        set field [lindex $args 0]
        set field [dict get [dict create \
            bits cipher_bits name cipher_name version cipher_version \
            clientlist cipher_clientlist] $field]
        return [_ssl_value $field]
    }

    proc ssl_sessionid_command {args} {
        if {[llength $args] > 1 || ([llength $args] == 1 && [lindex $args 0] ne "desired")} {
            error "SSL::sessionid accepts an optional desired argument"
        }
        return [_ssl_value session_id]
    }

    proc _ssl_cert_count {ns} {
        set count_variable ${ns}::cert_count
        if {[info exists $count_variable] && [string is integer -strict [set $count_variable]]} {
            set count [set $count_variable]
            if {$count > 0} { return $count }
        }
        set subject_variable ${ns}::cert_subject
        if {[info exists $subject_variable] && [set $subject_variable] ne ""} { return 1 }
        return 0
    }

    proc _ssl_cert_handle {index} {
        variable ssl_cert_counter
        variable ssl_cert_objects
        set ns [_ssl_namespace]
        set count [_ssl_cert_count $ns]
        if {![string is integer -strict $index] || $index < 0 || $index >= $count} {
            error "SSL::cert index is outside the peer certificate chain"
        }
        set handle "cert${ssl_cert_counter}_${index}"
        if {[dict exists $ssl_cert_objects $ns $index]} {
            return [dict get $ssl_cert_objects $ns $index]
        }
        incr ssl_cert_counter
        set handle "cert$ssl_cert_counter"
        set subject [_ssl_value cert_subject]
        set issuer [_ssl_value cert_issuer]
        set serial [_ssl_value cert_serial]
        set hash [_ssl_value cert_hash]
        dict set ssl_cert_objects $ns $index $handle
        dict set ssl_cert_objects objects $handle [dict create \
            subject $subject issuer $issuer serial $serial hash $hash]
        return $handle
    }

    proc _ssl_cert_get {certificate field} {
        variable ssl_cert_objects
        if {![dict exists $ssl_cert_objects objects $certificate $field]} {
            error "invalid X509 certificate object"
        }
        return [dict get $ssl_cert_objects objects $certificate $field]
    }

    proc ssl_cert_command {args} {
        if {[llength $args] < 1 || [llength $args] > 2} {
            error "SSL::cert requires count, issuer, mode, or an index"
        }
        set operation [lindex $args 0]
        if {$operation eq "count"} {
            if {[llength $args] != 1} { error "SSL::cert count takes no arguments" }
            return [_ssl_cert_count [_ssl_namespace]]
        }
        if {$operation eq "mode"} {
            if {[llength $args] == 2} {
                if {[lindex $args 1] ni {ignore request require}} {
                    error "SSL::cert mode must be ignore, request, or require"
                }
                set variable [_ssl_namespace]::cert_mode
                set $variable [lindex $args 1]
            }
            return [_ssl_value cert_mode ignore]
        }
        if {$operation eq "issuer"} {
            if {[llength $args] != 2} { error "SSL::cert issuer requires an index" }
            return [_ssl_cert_handle [lindex $args 1]]
        }
        if {[llength $args] != 1 || ![string is integer -strict $operation]} {
            error "SSL::cert requires count, issuer, mode, or an index"
        }
        return [_ssl_cert_handle $operation]
    }

    proc ssl_verify_result_command {args} {
        if {[llength $args] > 1} { error "SSL::verify_result accepts one optional result code" }
        set variable [_ssl_namespace]::verify_result
        if {[llength $args] == 1} {
            set value [lindex $args 0]
            if {![string is integer -strict $value] || $value < 0} {
                error "SSL::verify_result requires a non-negative integer"
            }
            set $variable $value
        }
        if {[info exists $variable]} { return [set $variable] }
        return 0
    }

    proc _ssl_set_disabled {side value} {
        set variable [_ssl_namespace $side]::disabled
        set $variable $value
        ::itest::log_decision ssl [expr {$value ? "disable" : "enable"}] $side
        return ""
    }

    proc ssl_disable_command {args} {
        if {[llength $args] > 1 || ([llength $args] == 1 && [lindex $args 0] ni {clientside serverside})} {
            error "SSL::disable accepts optional clientside or serverside"
        }
        return [_ssl_set_disabled [expr {[llength $args] ? [lindex $args 0] : ""}] 1]
    }

    proc ssl_enable_command {args} {
        if {[llength $args] > 1 || ([llength $args] == 1 && [lindex $args 0] ni {clientside serverside})} {
            error "SSL::enable accepts optional clientside or serverside"
        }
        return [_ssl_set_disabled [expr {[llength $args] ? [lindex $args 0] : ""}] 0]
    }

    proc x509_subject_command {args} {
        if {[llength $args] < 1 || [llength $args] > 2} {
            error "X509::subject requires a certificate and optional commonName"
        }
        set subject [_ssl_cert_get [lindex $args 0] subject]
        if {[llength $args] == 2} {
            if {[lindex $args 1] ne "commonName"} { error "X509::subject supports commonName" }
            if {[regexp -nocase {(?:^|[,/])(?:cn|commonname)=([^,/]+)} $subject -> common_name]} {
                return $common_name
            }
            return ""
        }
        return $subject
    }

    proc x509_issuer_command {args} {
        if {[llength $args] != 1} { error "X509::issuer requires a certificate" }
        return [_ssl_cert_get [lindex $args 0] issuer]
    }

    # ── DNS message and resource-record semantics ────────────────────
    #
    # The upstream harness recognizes the DNS namespace, but its older
    # answer/header mocks use ad-hoc lists and cannot model RR objects.  Keep
    # opaque RR handles in this overlay so the common F5 pattern
    #   foreach rr [DNS::answer] { DNS::ttl $rr 30 }
    # behaves like a real rule while the event snapshot remains readable.

    proc _dns_rr_create {name type rr_class ttl rdata} {
        variable dns_rr_counter
        variable dns_rr_objects
        if {$name eq "" || $type eq "" || $rr_class eq ""} {
            error "DNS::rr requires name, type, and class"
        }
        if {![string is integer -strict $ttl] || $ttl < 0 || $ttl > 0xffffffff} {
            error "DNS::rr ttl must be between 0 and 4294967295"
        }
        incr dns_rr_counter
        set handle "rr$dns_rr_counter"
        dict set dns_rr_objects $handle [dict create \
            name $name type [string toupper $type] class [string toupper $rr_class] \
            ttl $ttl rdata $rdata]
        return $handle
    }

    proc _dns_rr_object {value} {
        variable dns_rr_objects
        if {[dict exists $dns_rr_objects $value]} {
            return $value
        }
        set parts $value
        if {[llength $parts] < 5} {
            error "invalid DNS resource record object"
        }
        set name [lindex $parts 0]
        if {[string is integer -strict [lindex $parts 1]]} {
            set ttl [lindex $parts 1]
            set rr_class [lindex $parts 2]
            set type [lindex $parts 3]
        } else {
            set type [lindex $parts 1]
            set rr_class [lindex $parts 2]
            set ttl [lindex $parts 3]
        }
        return [_dns_rr_create $name $type $rr_class $ttl [join [lrange $parts 4 end] " "]]
    }

    proc _dns_rr_get {rr field} {
        variable dns_rr_objects
        set handle [_dns_rr_object $rr]
        return [dict get $dns_rr_objects $handle $field]
    }

    proc _dns_rr_set {rr field value} {
        variable dns_rr_objects
        set handle [_dns_rr_object $rr]
        if {$field eq "ttl" && (![string is integer -strict $value] ||
            $value < 0 || $value > 0xffffffff)} {
            error "DNS::ttl value must be between 0 and 4294967295"
        }
        if {$field in {name type class} && $value eq ""} {
            error "DNS resource record $field cannot be empty"
        }
        if {$field in {type class}} { set value [string toupper $value] }
        dict set dns_rr_objects $handle $field $value
        return $value
    }

    proc _dns_rr_snapshot {rr} {
        return [list \
            [_dns_rr_get $rr name] \
            [_dns_rr_get $rr type] \
            [_dns_rr_get $rr class] \
            [_dns_rr_get $rr ttl] \
            [_dns_rr_get $rr rdata]]
    }

    # DNSMSG/RESOLVER use opaque dns_message and resource-record handles.
    # The resolver data is deliberately supplied by the scenario so lookups
    # stay deterministic and never reach the network.
    proc resolver_clear {} {
        variable resolver_records
        variable dns_message_counter
        variable dns_message_objects
        set resolver_records [dict create]
        set dns_message_counter 0
        set dns_message_objects [dict create]
    }

    proc resolver_set {name records} {
        variable resolver_records
        if {$name eq ""} { error "resolver name cannot be empty" }
        if {[catch {llength $records}]} {
            error "resolver records must be a Tcl list"
        }
        dict set resolver_records $name $records
    }

    proc _dns_message_get {message} {
        variable dns_message_objects
        if {![dict exists $dns_message_objects $message]} {
            error "invalid DNS message object"
        }
        return [dict get $dns_message_objects $message]
    }

    proc _dns_message_create {qname qtype rr_class records} {
        variable dns_message_counter
        variable dns_message_objects
        set answer_objects {}
        foreach record $records {
            if {$record eq ""} { continue }
            lappend answer_objects [_dns_rr_object $record]
        }
        set question [_dns_rr_create $qname $qtype $rr_class 0 ""]
        incr dns_message_counter
        set handle "dnsmsg$dns_message_counter"
        dict set dns_message_objects $handle [dict create \
            id 0 qr 1 opcode 0 aa 0 tc 0 rd 1 ra 1 ad 0 cd 0 \
            rcode 0 question $question answer $answer_objects \
            authority {} additional {}]
        return $handle
    }

    proc dnsmsg_header_command {args} {
        if {[llength $args] != 2} {
            error "DNSMSG::header requires a DNS message and field"
        }
        set message [_dns_message_get [lindex $args 0]]
        set field [string tolower [lindex $args 1]]
        if {$field ni {rcode opcode id ra rd tc qr aa ad cd}} {
            error "unsupported DNSMSG::header field $field"
        }
        return [dict get $message $field]
    }

    proc dnsmsg_section_command {args} {
        if {[llength $args] != 2} {
            error "DNSMSG::section requires a DNS message and section"
        }
        set message [_dns_message_get [lindex $args 0]]
        set section [string tolower [lindex $args 1]]
        if {$section ni {question answer authority additional}} {
            error "unsupported DNSMSG::section section $section"
        }
        if {$section eq "question"} {
            return [list [dict get $message question]]
        }
        return [dict get $message $section]
    }

    proc dnsmsg_record_command {args} {
        if {[llength $args] != 2} {
            error "DNSMSG::record requires a resource record and field"
        }
        set field [string tolower [lindex $args 1]]
        if {$field eq "owner"} { set field name }
        if {$field ni {name type ttl class rdata}} {
            error "unsupported DNSMSG::record field $field"
        }
        return [_dns_rr_get [lindex $args 0] $field]
    }

    proc resolver_name_lookup {args} {
        variable resolver_records
        if {[llength $args] != 3} {
            error "RESOLVER::name_lookup requires resolver, name, and type"
        }
        set resolver [lindex $args 0]
        if {![dict exists $resolver_records $resolver]} {
            error "unknown network resolver $resolver"
        }
        set wanted_name [string tolower [string trimright [lindex $args 1] .]]
        set wanted_type [string toupper [lindex $args 2]]
        set matched {}
        foreach record [dict get $resolver_records $resolver] {
            set rr [_dns_rr_object $record]
            set rr_name [string tolower [string trimright [_dns_rr_get $rr name] .]]
            set rr_type [string toupper [_dns_rr_get $rr type]]
            if {$rr_name eq $wanted_name &&
                ($rr_type eq $wanted_type || $wanted_type eq "ANY")} {
                lappend matched [_dns_rr_snapshot $rr]
            }
        }
        set message [_dns_message_create [lindex $args 1] $wanted_type IN $matched]
        ::itest::log_decision dns resolver_lookup [list $resolver [lindex $args 1] $wanted_type]
        return $message
    }

    proc resolver_summarize {args} {
        if {[llength $args] != 1} {
            error "RESOLVER::summarize requires a DNS message"
        }
        set message [_dns_message_get [lindex $args 0]]
        set result [dict get $message answer]
        foreach section {authority additional} {
            set result [concat $result [dict get $message $section]]
        }
        return $result
    }

    proc _dns_refresh_state {{recalculate_length 0}} {
        foreach section {answers authority additional} {
            set count [llength [set ::state::dns::$section]]
            set field [expr {$section eq "answers" ? "ancount" : \
                ($section eq "authority" ? "nscount" : "arcount")}]
            set ::state::dns::$field $count
        }
        if {![info exists ::state::dns::qdcount]} { set ::state::dns::qdcount 1 }
        if {![info exists ::state::dns::qr]} { set ::state::dns::qr 0 }
        if {![info exists ::state::dns::rcode]} { set ::state::dns::rcode 0 }
        set qr [expr {$::state::dns::qr in {1 true TRUE}}]
        if {$::state::dns::rcode eq "NXDOMAIN"} { set rcode 3 } else { set rcode $::state::dns::rcode }
        if {![string is integer -strict $rcode]} { set rcode 0 }
        if {!$qr} {
            set ::state::dns::ptype QUESTION
        } elseif {$rcode == 3} {
            set ::state::dns::ptype NXDOMAIN
        } elseif {$::state::dns::ancount > 0} {
            set ::state::dns::ptype ANSWER
        } elseif {$::state::dns::nscount > 0} {
            set ::state::dns::ptype REFERRAL
        } else {
            set ::state::dns::ptype NODATA
        }
        if {$recalculate_length || ![info exists ::state::dns::message_length] ||
            $::state::dns::message_length eq "" || $::state::dns::message_length == 0} {
            set length [expr {12 + [string length $::state::dns::qname] + 6}]
            foreach section {answers authority additional} {
                foreach rr [set ::state::dns::$section] {
                    incr length [expr {10 + [string length [_dns_rr_get $rr name]] + \
                        [string length [_dns_rr_get $rr rdata]]}]
                }
            }
            set ::state::dns::message_length $length
        }
    }

    proc dns_prepare_message {} {
        variable dns_rr_objects
        if {![info exists ::state::dns::qname]} { set ::state::dns::qname "" }
        if {![info exists ::state::dns::qtype]} { set ::state::dns::qtype A }
        if {![info exists ::state::dns::qclass]} { set ::state::dns::qclass IN }
        foreach {field default} {
            qr 0 rcode 0 opcode 0 id 0 aa 0 tc 0 rd 1 ra 0 cd 0 ad 0
            qdcount 1 ancount 0 nscount 0 arcount 0 ptype QUESTION
            message_length 0 message_hex "" disabled 0 dropped 0 last_act "" edns0 ""
            rpz_policy "" wideips {} response_sent 0
        } {
            if {![info exists ::state::dns::$field]} {
                set ::state::dns::$field $default
            }
        }
        if {![info exists ::state::dns::answers]} { set ::state::dns::answers {} }
        if {![info exists ::state::dns::authority]} { set ::state::dns::authority {} }
        if {![info exists ::state::dns::additional]} { set ::state::dns::additional {} }
        foreach section {answers authority additional} {
            set objects {}
            foreach record [set ::state::dns::$section] {
                if {$record eq ""} { continue }
                lappend objects [_dns_rr_object $record]
            }
            set ::state::dns::$section $objects
        }
        _dns_refresh_state
    }

    proc dns_snapshot_section {section} {
        if {$section ni {answers authority additional}} {
            error "invalid DNS section $section"
        }
        set result {}
        foreach rr [set ::state::dns::$section] {
            lappend result [_dns_rr_snapshot $rr]
        }
        return $result
    }

    proc dns_section_command {section args} {
        _dns_refresh_state
        set current [set ::state::dns::$section]
        if {[llength $args] == 0} {
            return $current
        }
        set operation [string tolower [lindex $args 0]]
        switch -exact -- $operation {
            clear {
                if {[llength $args] != 1} { error "DNS::$section clear takes no arguments" }
                set ::state::dns::$section {}
                _dns_refresh_state 1
                ::itest::log_decision dns ${section}_clear
                return ""
            }
            count {
                if {[llength $args] != 1} { error "DNS::$section count takes no arguments" }
                return [llength $current]
            }
            insert - remove {
                if {[llength $args] != 2} { error "DNS::$section $operation requires an RR object" }
                set handle [_dns_rr_object [lindex $args 1]]
                set index [lsearch -exact $current $handle]
                if {$operation eq "insert"} {
                    if {$index < 0} { lappend current $handle }
                } elseif {$index >= 0} {
                    set current [lreplace $current $index $index]
                }
                set ::state::dns::$section $current
                _dns_refresh_state 1
                ::itest::log_decision dns ${section}_$operation $handle
                return ""
            }
            default {
                if {[llength $args] == 1 && [string is integer -strict $operation] &&
                    $operation >= 0 && $operation < [llength $current]} {
                    return [lindex $current $operation]
                }
                error "unsupported DNS::$section operation $operation"
            }
        }
    }

    proc dns_answer_command {args} { return [dns_section_command answers {*}$args] }
    proc dns_authority_command {args} { return [dns_section_command authority {*}$args] }
    proc dns_additional_command {args} { return [dns_section_command additional {*}$args] }
    proc dns_name_command {args} { return [dns_rr_field_command name {*}$args] }
    proc dns_class_command {args} { return [dns_rr_field_command class {*}$args] }
    proc dns_rdata_command {args} { return [dns_rr_field_command rdata {*}$args] }
    proc dns_ttl_command {args} { return [dns_rr_field_command ttl {*}$args] }
    proc dns_type_command {args} { return [dns_rr_field_command type {*}$args] }

    proc dns_rr_command {args} {
        if {[llength $args] == 1} {
            return [_dns_rr_object [lindex $args 0]]
        }
        if {[llength $args] < 5} {
            error "DNS::rr requires name, type, class, ttl, and rdata"
        }
        return [_dns_rr_create [lindex $args 0] [lindex $args 1] [lindex $args 2] \
            [lindex $args 3] [join [lrange $args 4 end] " "]]
    }

    proc dns_rr_field_command {field args} {
        if {[llength $args] < 1 || [llength $args] > 2} {
            error "DNS::$field requires an RR object and optional value"
        }
        set rr [lindex $args 0]
        if {[llength $args] == 1} {
            return [_dns_rr_get $rr $field]
        }
        return [_dns_rr_set $rr $field [lindex $args 1]]
    }

    proc dns_header_command {args} {
        if {[llength $args] < 1 || [llength $args] > 2} {
            error "DNS::header requires a field and optional value"
        }
        _dns_refresh_state
        set field [string tolower [lindex $args 0]]
        set fields {id qr opcode aa tc rd ra ad cd rcode qdcount ancount nscount arcount}
        if {$field ni $fields} { error "unsupported DNS header field $field" }
        if {[llength $args] == 2} {
            set value [lindex $args 1]
            if {$field in {qr aa tc rd ra ad cd}} {
                if {$value ni {0 1 true false TRUE FALSE}} {
                    error "DNS::header $field must be boolean"
                }
                set value [expr {$value in {1 true TRUE} ? 1 : 0}]
            } elseif {$field eq "rcode"} {
                set names [dict create NOERROR 0 FORMERR 1 SERVFAIL 2 NXDOMAIN 3 \
                    NOTIMP 4 REFUSED 5 YXDOMAIN 6 YXRRSET 7 NXRRSET 8 NOTAUTH 9 NOTZONE 10]
                set key [string toupper $value]
                if {[dict exists $names $key]} { set value [dict get $names $key] }
                if {![string is integer -strict $value] || $value < 0 || $value > 15} {
                    error "DNS::header rcode must be a valid DNS response code"
                }
            } elseif {$field eq "opcode"} {
                set names [dict create QUERY 0 IQUERY 1 STATUS 2 NOTIFY 4 UPDATE 5]
                set key [string toupper $value]
                if {[dict exists $names $key]} { set value [dict get $names $key] }
                if {![string is integer -strict $value] || $value < 0 || $value > 15} {
                    error "DNS::header opcode must be a valid DNS operation code"
                }
            } else {
                if {![string is integer -strict $value] || $value < 0 || $value > 65535} {
                    error "DNS::header $field must be an unsigned 16-bit integer"
                }
            }
            set ::state::dns::$field $value
            _dns_refresh_state 1
            ::itest::log_decision dns header_set [list $field $value]
        }
        set value [set ::state::dns::$field]
        if {$field eq "rcode"} {
            set names [dict create 0 NOERROR 1 FORMERR 2 SERVFAIL 3 NXDOMAIN 4 NOTIMP \
                5 REFUSED 6 YXDOMAIN 7 YXRRSET 8 NXRRSET 9 NOTAUTH 10 NOTZONE]
            if {[dict exists $names $value]} { return [dict get $names $value] }
        } elseif {$field eq "opcode"} {
            set names [dict create 0 QUERY 1 IQUERY 2 STATUS 4 NOTIFY 5 UPDATE]
            if {[dict exists $names $value]} { return [dict get $names $value] }
        }
        return $value
    }

    proc dns_len_command {args} {
        if {[llength $args] != 0} { error "DNS::len takes no arguments" }
        _dns_refresh_state
        return $::state::dns::message_length
    }

    proc dns_ptype_command {args} {
        if {[llength $args] != 0} { error "DNS::ptype takes no arguments" }
        _dns_refresh_state
        return $::state::dns::ptype
    }

    proc dns_drop_command {args} {
        if {[llength $args] != 0} { error "DNS::drop takes no arguments" }
        set ::state::dns::dropped 1
        ::itest::log_decision dns drop
        return ""
    }

    proc dns_disable_command {args} {
        if {[llength $args] != 0} { error "DNS::disable takes no arguments" }
        set ::state::dns::disabled 1
        ::itest::log_decision dns disable
        return ""
    }

    proc dns_enable_command {args} {
        if {[llength $args] != 0} { error "DNS::enable takes no arguments" }
        set ::state::dns::disabled 0
        ::itest::log_decision dns enable
        return ""
    }

    proc dns_return_command {args} {
        if {[llength $args] != 0} { error "DNS::return takes no arguments" }
        set ::state::dns::response_sent 1
        ::itest::log_decision dns return
        return ""
    }

    proc dns_last_act_command {args} {
        if {[llength $args] == 0} {
            if {![info exists ::state::dns::last_act]} { return "" }
            return $::state::dns::last_act
        }
        if {[llength $args] != 1 || [lindex $args 0] ni {allow drop reject hint noerror}} {
            error "DNS::last_act requires allow, drop, reject, hint, or noerror"
        }
        set ::state::dns::last_act [lindex $args 0]
        ::itest::log_decision dns last_act [lindex $args 0]
        return $::state::dns::last_act
    }

    proc dns_rpz_policy_command {args} {
        if {[llength $args] != 0} { error "DNS::rpz_policy takes no arguments" }
        if {![info exists ::state::dns::rpz_policy]} { return "" }
        return $::state::dns::rpz_policy
    }

    proc dns_is_wideip_command {args} {
        if {[llength $args] != 1} { error "DNS::is_wideip requires a hostname" }
        if {![info exists ::state::dns::wideips]} { return 0 }
        set wanted [string tolower [string trimright [lindex $args 0] .]]
        foreach candidate $::state::dns::wideips {
            if {[string tolower [string trimright $candidate .]] eq $wanted} { return 1 }
        }
        return 0
    }

    proc dns_log_command {args} {
        ::itest::log_decision dns log $args
        return ""
    }

    proc _dns_edns_state {} {
        if {![info exists ::state::dns::edns0] ||
            [catch {dict size $::state::dns::edns0}]} {
            set ::state::dns::edns0 [dict create exists 0 do 0 sz 512 nsid "" \
                subnet_address "" subnet_source 0 subnet_scope 0]
        }
        foreach {key default} {exists 0 do 0 sz 512 nsid "" subnet_address "" subnet_source 0 subnet_scope 0} {
            if {![dict exists $::state::dns::edns0 $key]} {
                dict set ::state::dns::edns0 $key $default
            }
        }
        return $::state::dns::edns0
    }

    proc dns_edns0_command {args} {
        if {[llength $args] < 1 || [llength $args] > 3} {
            error "DNS::edns0 requires a field and optional value"
        }
        set state [_dns_edns_state]
        set field [string tolower [lindex $args 0]]
        if {$field eq "exists"} {
            if {[llength $args] == 2 && [lindex $args 1] eq "nsid"} {
                return [expr {[dict get $state exists] && [dict get $state nsid] ne ""}]
            }
            if {[llength $args] != 1} { error "DNS::edns0 exists accepts only nsid" }
            return [dict get $state exists]
        }
        if {$field eq "subnet"} {
            if {[llength $args] < 2 || [llength $args] > 3} {
                error "DNS::edns0 subnet requires address, source, or scope"
            }
            set subfield [string tolower [lindex $args 1]]
            set key [dict create address subnet_address source subnet_source scope subnet_scope]
            if {![dict exists $key $subfield]} { error "unsupported DNS::edns0 subnet field $subfield" }
            set state_key [dict get $key $subfield]
            if {[llength $args] == 3} { dict set state $state_key [lindex $args 2]; dict set state exists 1 }
            set ::state::dns::edns0 $state
            return [dict get $state $state_key]
        }
        if {$field ni {do sz nsid}} { error "unsupported DNS::edns0 field $field" }
        if {[llength $args] == 2} {
            dict set state $field [lindex $args 1]
            dict set state exists 1
            set ::state::dns::edns0 $state
        } elseif {[llength $args] != 1} {
            error "DNS::edns0 $field accepts one optional value"
        }
        return [dict get $state $field]
    }

    proc dns_query_command {args} {
        if {[llength $args] < 3 || [llength $args] > 4} {
            error "DNS::query requires dnsx, name, type, and optional dnssec"
        }
        if {[string tolower [lindex $args 0]] ne "dnsx"} {
            error "DNS::query supports only the dnsx target in this emulator"
        }
        set wanted_name [string tolower [string trimright [lindex $args 1] .]]
        set wanted_type [string toupper [lindex $args 2]]
        set result {}
        foreach section {answers authority additional} {
            set section_result {}
            foreach rr [set ::state::dns::$section] {
                if {[string tolower [string trimright [_dns_rr_get $rr name] .]] eq $wanted_name &&
                    ([string toupper [_dns_rr_get $rr type]] eq $wanted_type || $wanted_type eq "ANY")} {
                    lappend section_result $rr
                }
            }
            lappend result $section_result
        }
        ::itest::log_decision dns query [list [lindex $args 1] $wanted_type]
        return $result
    }

    proc dns_scrape_command {args} {
        if {[llength $args] < 2} { error "DNS::scrape requires a section and field" }
        set section [string tolower [lindex $args 0]]
        set section_map [dict create answer answers authority authority additional additional all {answers authority additional}]
        if {![dict exists $section_map $section]} { error "unsupported DNS::scrape section $section" }
        set fields [lrange $args 1 end]
        set valid {type ttl qname qnamelen rdata rdatalen class}
        foreach field $fields { if {$field ni $valid} { error "unsupported DNS::scrape field $field" } }
        set sections [dict get $section_map $section]
        set records {}
        foreach current_section $sections {
            foreach rr [set ::state::dns::$current_section] { lappend records $rr }
        }
        set result {}
        foreach rr $records {
            set values {}
            foreach field $fields {
                switch -exact -- $field {
                    type - ttl - class { lappend values [_dns_rr_get $rr $field] }
                    qname { lappend values [_dns_rr_get $rr name] }
                    qnamelen { lappend values [string bytelength [_dns_rr_get $rr name]] }
                    rdata { lappend values [_dns_rr_get $rr rdata] }
                    rdatalen { lappend values [string bytelength [_dns_rr_get $rr rdata]] }
                }
            }
            if {[llength $fields] == 1} { lappend result [lindex $values 0] } else { lappend result $values }
        }
        return $result
    }

    proc dns_question {args} {
        if {[llength $args] == 1} {
            switch -exact -- [string tolower [lindex $args 0]] {
                name { return $::state::dns::qname }
                type { return $::state::dns::qtype }
                class { return $::state::dns::qclass }
                default { error "DNS::question supports name, type, and class" }
            }
        }
        if {[llength $args] == 2} {
            set field [string tolower [lindex $args 0]]
            switch -exact -- $field {
                name { set ::state::dns::qname [lindex $args 1] }
                type { set ::state::dns::qtype [lindex $args 1] }
                class { set ::state::dns::qclass [lindex $args 1] }
                default { error "DNS::question supports name, type, and class" }
            }
            return [lindex $args 1]
        }
        error "DNS::question requires name or type, with an optional value"
    }

    proc dns_origin {args} {
        if {[llength $args] != 0} {
            error "DNS::origin takes no arguments"
        }
        if {$::itest::current_event eq "DNS_RESPONSE"} {
            return server
        }
        return client
    }

    proc findstr_command {args} {
        if {[llength $args] < 2 || [llength $args] > 4} {
            error "findstr requires a string, search string, and optional skip/terminator"
        }
        set source [lindex $args 0]
        set search [lindex $args 1]
        set match [string first $search $source]
        if {$match < 0} { return "" }
        set skip 0
        if {[llength $args] > 2} {
            set skip [lindex $args 2]
            if {![string is integer -strict $skip] || $skip < 0} {
                error "findstr skip must be a non-negative integer"
            }
        }
        set start [expr {$match + $skip}]
        if {$start >= [string length $source]} { return "" }
        if {[llength $args] < 4} {
            return [string range $source $start end]
        }
        set terminator [lindex $args 3]
        if {[string is integer -strict $terminator]} {
            if {$terminator < 0} { error "findstr terminator length must be non-negative" }
            return [string range $source $start [expr {$start + $terminator - 1}]]
        }
        set end [string first $terminator $source $start]
        if {$end < 0} { set end [string length $source] }
        return [string range $source $start [expr {$end - 1}]]
    }

    proc getfield_command {args} {
        if {[llength $args] != 3} {
            error "getfield requires a string, delimiter, and one-based field number"
        }
        set source [lindex $args 0]
        set delimiter [lindex $args 1]
        set field [lindex $args 2]
        if {![string is integer -strict $field] || $field < 1} {
            error "getfield field number must be a positive integer"
        }
        if {$delimiter eq ""} {
            return [string index $source [expr {$field - 1}]]
        }
        set fields [list]
        set cursor 0
        set delimiter_length [string length $delimiter]
        while {1} {
            set position [string first $delimiter $source $cursor]
            if {$position < 0} {
                lappend fields [string range $source $cursor end]
                break
            }
            lappend fields [string range $source $cursor [expr {$position - 1}]]
            set cursor [expr {$position + $delimiter_length}]
        }
        if {$field > [llength $fields]} { return "" }
        return [lindex $fields [expr {$field - 1}]]
    }

    proc findclass_command {args} {
        if {[llength $args] < 2 || [llength $args] > 3} {
            error "findclass requires a key, class, and optional separator"
        }
        set key [lindex $args 0]
        lassign [_class_group [lindex $args 1]] type records
        foreach {name value} $records {
            if {$name ne $key} { continue }
            if {[llength $args] == 3} { return $value }
            if {$value eq ""} { return $name }
            return "$name $value"
        }
        return ""
    }

    proc matchclass_command {args} {
        if {[llength $args] != 3} {
            error "matchclass requires a value/class, operator, and class/value"
        }
        set left [lindex $args 0]
        set operator [lindex $args 1]
        set right [lindex $args 2]
        if {[info exists ::state::datagroup::groups($left)]} {
            set class_name $left
            set item $right
            set class_first 1
        } else {
            set class_name $right
            set item $left
            set class_first 0
        }
        lassign [_class_group $class_name] type records
        set index 0
        foreach {name value} $records {
            set matched [expr {$class_first
                ? [_class_compare $name $operator $item 0]
                : [_class_compare $item $operator $name 0]}]
            if {$matched} { return [expr {$index + 1}] }
            incr index
        }
        return 0
    }

    proc _active_pool_members {pool_name} {
        if {![info exists ::state::lb::pools($pool_name)]} { return [list] }
        set members [list]
        foreach member [lindex $::state::lb::pools($pool_name) 1] {
            if {[_member_status $pool_name $member] ni {down disabled}} {
                lappend members $member
            }
        }
        return $members
    }

    proc _member_endpoint {member} {
        set separator [string last : $member]
        if {$separator < 0} { return [list $member 0] }
        return [list [string range $member 0 [expr {$separator - 1}]] \
            [string range $member [expr {$separator + 1}] end]]
    }

    proc active_members_command {args} {
        set list_mode 0
        if {[llength $args] == 2 && [lindex $args 0] eq "-list"} {
            set list_mode 1
            set pool_name [lindex $args 1]
        } elseif {[llength $args] == 1} {
            set pool_name [lindex $args 0]
        } else {
            error "active_members requires a pool or -list pool"
        }
        set members [_active_pool_members $pool_name]
        if {!$list_mode} { return [llength $members] }
        set result [list]
        foreach member $members { lappend result [_member_endpoint $member] }
        return $result
    }

    proc active_nodes_command {args} {
        set list_mode 0
        if {[llength $args] == 2 && [lindex $args 0] eq "-list"} {
            set list_mode 1
            set pool_name [lindex $args 1]
        } elseif {[llength $args] == 1} {
            set pool_name [lindex $args 0]
        } else {
            error "active_nodes requires a pool or -list pool"
        }
        set members [_active_pool_members $pool_name]
        if {!$list_mode} { return [llength $members] }
        set result [list]
        foreach member $members {
            lassign [_member_endpoint $member] address ignored
            lappend result $address
        }
        return $result
    }

    proc members_command {args} {
        set list_mode 0
        if {[llength $args] == 2 && [lindex $args 0] eq "-list"} {
            set list_mode 1
            set pool_name [lindex $args 1]
        } elseif {[llength $args] == 1} {
            set pool_name [lindex $args 0]
        } else {
            error "members requires a pool or -list pool"
        }
        if {![info exists ::state::lb::pools($pool_name)]} {
            if {$list_mode} { return [list] }
            return 0
        }
        set members [lindex $::state::lb::pools($pool_name) 1]
        if {!$list_mode} { return [llength $members] }
        set result [list]
        foreach member $members { lappend result [_member_endpoint $member] }
        return $result
    }

    proc nodes_command {args} {
        set list_mode 0
        if {[llength $args] == 2 && [lindex $args 0] eq "-list"} {
            set list_mode 1
            set pool_name [lindex $args 1]
        } elseif {[llength $args] == 1} {
            set pool_name [lindex $args 0]
        } else {
            error "nodes requires a pool or -list pool"
        }
        if {![info exists ::state::lb::pools($pool_name)]} {
            if {$list_mode} { return [list] }
            return 0
        }
        set members [lindex $::state::lb::pools($pool_name) 1]
        if {!$list_mode} { return [llength $members] }
        set result [list]
        foreach member $members {
            lassign [_member_endpoint $member] address ignored
            lappend result $address
        }
        return $result
    }

    proc substr_command {args} {
        if {[llength $args] < 2 || [llength $args] > 3} {
            error "substr requires a string, skip count, and optional terminator"
        }
        set source [lindex $args 0]
        set start [lindex $args 1]
        if {![string is integer -strict $start] || $start < 0} {
            error "substr skip count must be a non-negative integer"
        }
        if {$start >= [string length $source]} { return "" }
        if {[llength $args] == 2} { return [string range $source $start end] }
        set terminator [lindex $args 2]
        if {[string is integer -strict $terminator]} {
            if {$terminator < 0} { error "substr terminator length must be non-negative" }
            return [string range $source $start [expr {$start + $terminator - 1}]]
        }
        set end [string first $terminator $source $start]
        if {$end < 0} { set end [string length $source] }
        return [string range $source $start [expr {$end - 1}]]
    }

    proc decode_uri_command {args} {
        if {[llength $args] != 1} { error "decode_uri requires one value" }
        return [_uri_decode_value [lindex $args 0]]
    }

    proc domain_command {args} {
        if {[llength $args] != 2} { error "domain requires a name and count" }
        set source [lindex $args 0]
        set count [lindex $args 1]
        if {![string is integer -strict $count] || $count < 1} {
            error "domain count must be a positive integer"
        }
        set labels [split $source "."]
        set start [expr {[llength $labels] - $count}]
        if {$start < 0} { set start 0 }
        return [join [lrange $labels $start end] "."]
    }

    proc llookup_command {args} {
        if {[llength $args] != 2} { error "llookup requires a multimap and key" }
        set multimap [lindex $args 0]
        set key [lindex $args 1]
        if {[catch {llength $multimap} pair_count]} { return "" }
        set values [list]
        foreach pair $multimap {
            if {[catch {llength $pair} field_count] || $field_count != 2} {
                return ""
            }
            if {[lindex $pair 0] eq $key} {
                lappend values [lindex $pair 1]
            }
        }
        if {[llength $values] == 0} { return "" }
        return $values
    }

    proc _connection_value {field args} {
        if {[llength $args] != 0} { error "$field takes no arguments" }
        if {$field in {server_addr server_port} &&
            [info exists ::state::lb::selected] && $::state::lb::selected} {
            switch -exact -- $field {
                server_addr { return $::state::lb::node_addr }
                server_port { return $::state::lb::node_port }
            }
        }
        if {[info exists ::state::connection::$field]} {
            return [set ::state::connection::$field]
        }
        return ""
    }

    proc client_addr_command {args} { return [_connection_value client_addr {*}$args] }
    proc client_port_command {args} { return [_connection_value client_port {*}$args] }
    proc local_addr_command {args} { return [_connection_value local_addr {*}$args] }
    proc local_port_command {args} { return [_connection_value local_port {*}$args] }
    proc remote_addr_command {args} { return [_connection_value remote_addr {*}$args] }
    proc remote_port_command {args} { return [_connection_value remote_port {*}$args] }
    proc server_addr_command {args} { return [_connection_value server_addr {*}$args] }
    proc server_port_command {args} { return [_connection_value server_port {*}$args] }

    proc _http_response_context {} {
        return [expr {$::itest::current_event in {
            HTTP_RESPONSE HTTP_RESPONSE_CONTINUE HTTP_RESPONSE_DATA HTTP_RESPONSE_RELEASE
        }}]
    }

    proc _http_header_value {name} {
        if {[_http_response_context]} {
            return [::state::http::response::header get $name]
        }
        return [::state::http::request::header get $name]
    }

    proc _http_version_value {} {
        if {[_http_response_context]} {
            if {![catch {set version $::state::http::response::version}]} {
                return $version
            }
        }
        if {![catch {set version $::state::http::request::version}]} {
            return $version
        }
        return 1.1
    }

    proc http_is_keepalive_command {args} {
        if {[llength $args] != 0} {
            error "HTTP::is_keepalive takes no arguments"
        }
        set connection [string tolower [_http_header_value connection]]
        if {[regexp {(^|[,[:space:]])close([,[:space:]]|$)} $connection]} {
            return 0
        }
        if {[regexp {(^|[,[:space:]])keep-alive([,[:space:]]|$)} $connection]} {
            return 1
        }
        set version [_http_version_value]
        if {[catch {expr {double($version) >= 1.1}} keepalive]} {
            return 1
        }
        return $keepalive
    }

    proc http_is_redirect_command {args} {
        if {[llength $args] != 0} {
            error "HTTP::is_redirect takes no arguments"
        }
        set status $::state::http::response::status
        if {[lsearch -exact {301 302 303 305 307} $status] < 0} {
            return 0
        }
        return [expr {[_http_header_value location] ne ""}]
    }

    proc http_request_num_command {args} {
        if {[llength $args] != 0} {
            error "HTTP::request_num takes no arguments"
        }
        variable http_request_number
        return $http_request_number
    }

    proc http_close_command {args} {
        if {[llength $args] != 0} {
            error "HTTP::close takes no arguments"
        }
        variable http_close_requested
        set http_close_requested 1
        set ::state::connection::state closing
        set ::state::http::response_committed 1
        ::itest::log_decision http close
        return ""
    }

    proc lb_server_command {args} {
        if {[llength $args] > 1} {
            error "LB::server accepts at most one selector"
        }
        set pool $::state::lb::pool
        set selected 0
        if {[info exists ::state::lb::selected]} {
            set selected $::state::lb::selected
        }
        set addr ""
        set port ""
        if {$selected} {
            set addr $::state::lb::node_addr
            set port $::state::lb::node_port
            set member $::state::lb::pool_member
            if {$member eq ""} {
                set selected 0
            } else {
                set separator [string last ":" $member]
                if {$separator < 0} {
                    if {$member ne $addr} { set selected 0 }
                } elseif {[string range $member 0 [expr {$separator - 1}]] ne $addr ||
                          [string range $member [expr {$separator + 1}] end] ne $port} {
                    set selected 0
                }
            }
            if {!$selected} {
                set addr ""
                set port ""
            }
        }
        if {[llength $args] == 0 || [lindex $args 0] eq "name"} {
            if {!$selected} { return $pool }
            return [list $pool $addr $port]
        }
        switch -exact -- [lindex $args 0] {
            pool { return $pool }
            addr { return $addr }
            port { return $port }
            priority - ratio { if {$selected} { return 1 }; return "" }
            route_domain - weight - ripeness { return "" }
            default { error "unsupported LB::server selector" }
        }
    }

    proc http_retry_command {args} {
        if {$::itest::current_event ni {HTTP_RESPONSE HTTP_RESPONSE_DATA}} {
            error "HTTP::retry is valid only during HTTP_RESPONSE or HTTP_RESPONSE_DATA"
        }
        if {[llength $args] > 2} {
            error "HTTP::retry accepts an optional -reset and request"
        }
        set reset 0
        if {[llength $args] > 0 && [lindex $args 0] eq "-reset"} {
            set reset 1
            set args [lrange $args 1 end]
        }
        if {[llength $args] > 1} {
            error "HTTP::retry accepts one request"
        }
        set request ""
        if {[llength $args] == 1} {
            set request [lindex $args 0]
        }
        set ::itest::semantic::http_retry_requested 1
        set ::itest::semantic::http_retry_request $request
        set ::itest::semantic::http_retry_reset $reset
        ::itest::log_decision http retry [list $reset $request]
        return ""
    }

    proc http_release_command {args} {
        if {[llength $args] != 0} {
            error "HTTP::release takes no arguments"
        }
        if {$::itest::current_event ni {HTTP_REQUEST_DATA HTTP_RESPONSE_DATA}} {
            error "HTTP::release is valid only during HTTP_REQUEST_DATA or HTTP_RESPONSE_DATA"
        }
        variable http_release_requested
        set http_release_requested 1
        if {$::itest::current_event eq "HTTP_REQUEST_DATA"} {
            set ::state::http::collect_request 0
            set ::state::http::collect_request_length 0
        } else {
            set ::state::http::collect_response 0
            set ::state::http::collect_response_length 0
        }
        ::itest::log_decision http release
        return ""
    }

    proc http_collect_command {args} {
        if {$::itest::current_event in {
            HTTP_REQUEST_RELEASE HTTP_RESPONSE_RELEASE HTTP_RESPONSE_CONTINUE
        }} {
            error "HTTP::collect is not valid in $::itest::current_event"
        }
        return [eval [linsert $args 0 ::itest::cmd::_testcl_http_collect_orig]]
    }

    proc http_payload_command {args} {
        if {$::itest::current_event in {
            HTTP_REQUEST_RELEASE HTTP_RESPONSE_RELEASE HTTP_RESPONSE_CONTINUE
        }} {
            error "HTTP::payload is not valid in $::itest::current_event"
        }
        return [eval [linsert $args 0 ::itest::cmd::_testcl_http_payload_semantic_orig]]
    }

    proc crc32_command {args} {
        if {[llength $args] != 1} { error "crc32 requires one value" }
        if {[catch {zlib crc32 [lindex $args 0]} value]} { return "" }
        if {$value > 0x7fffffff} {
            return [expr {$value - 0x100000000}]
        }
        return $value
    }

    proc _digest_command {algorithm args} {
        if {[llength $args] != 1} { error "$algorithm requires one value" }
        set value [binary encode base64 [lindex $args 0]]
        set encoded [::itest::semantic::py_digest $algorithm $value]
        return [binary decode base64 $encoded]
    }

    proc md5_command {args} { return [_digest_command md5 {*}$args] }
    proc sha1_command {args} { return [_digest_command sha1 {*}$args] }
    proc sha256_command {args} { return [_digest_command sha256 {*}$args] }
    proc sha384_command {args} { return [_digest_command sha384 {*}$args] }
    proc sha512_command {args} { return [_digest_command sha512 {*}$args] }

    proc b64encode_command {args} {
        if {[llength $args] != 1} { error "b64encode requires one value" }
        return [binary encode base64 [lindex $args 0]]
    }

    proc b64decode_command {args} {
        if {[llength $args] != 1} { error "b64decode requires one value" }
        if {[catch {binary decode base64 [lindex $args 0]} decoded]} {
            return ""
        }
        return $decoded
    }
}

# Preserve the upstream pool behavior and replace only its member choice.
if {[::tmm::_orig_info commands ::itest::cmd::cmd_pool] ne ""} {
    ::tmm::_orig_rename ::itest::cmd::cmd_pool ::itest::cmd::_testcl_pool_orig
    proc ::itest::cmd::cmd_pool {args} {
        return [eval [linsert $args 0 ::itest::semantic::pool_status_aware]]
    }
}
if {[::tmm::_orig_info commands ::itest::cmd::cmd_persist] ne ""} {
    ::tmm::_orig_rename ::itest::cmd::cmd_persist ::itest::cmd::_testcl_persist_orig
    proc ::itest::cmd::cmd_persist {args} {
        return [eval [linsert $args 0 ::itest::semantic::_persist_command]]
    }
}
if {[::tmm::_orig_info commands ::itest::cmd::cmd_table] ne ""} {
    ::tmm::_orig_rename ::itest::cmd::cmd_table ::itest::cmd::_testcl_table_orig
    proc ::itest::cmd::cmd_table {args} {
        return [eval [linsert $args 0 ::itest::semantic::table_command]]
    }
}
if {[::tmm::_orig_info commands ::itest::cmd::cmd_class] ne ""} {
    ::tmm::_orig_rename ::itest::cmd::cmd_class ::itest::cmd::_testcl_class_orig
    proc ::itest::cmd::cmd_class {args} {
        return [eval [linsert $args 0 ::itest::semantic::class_command]]
    }
}
if {[::tmm::_orig_info commands ::itest::cmd::cmd_event] ne ""} {
    ::tmm::_orig_rename ::itest::cmd::cmd_event ::itest::cmd::_testcl_event_orig
    proc ::itest::cmd::cmd_event {args} {
        if {[llength $args] == 1 && [lindex $args 0] eq "info"} {
            if {[info exists ::state::lb::failure_cause] &&
                $::itest::current_event eq "LB_FAILED"} {
                return $::state::lb::failure_cause
            }
            return ""
        }
        return [eval [linsert $args 0 ::itest::cmd::_testcl_event_orig]]
    }
}
if {[::tmm::_orig_info commands ::itest::cmd::http_retry] ne ""} {
    ::tmm::_orig_rename ::itest::cmd::http_retry ::itest::cmd::_testcl_http_retry_orig
    proc ::itest::cmd::http_retry {args} {
        return [eval [linsert $args 0 ::itest::semantic::http_retry_command]]
    }
}
if {[::tmm::_orig_info commands ::itest::cmd::http_close] ne ""} {
    ::tmm::_orig_rename ::itest::cmd::http_close ::itest::cmd::_testcl_http_close_orig
    proc ::itest::cmd::http_close {args} {
        return [eval [linsert $args 0 ::itest::semantic::http_close_command]]
    }
}
if {[::tmm::_orig_info commands ::itest::cmd::http_request] ne ""} {
    ::tmm::_orig_rename ::itest::cmd::http_request ::itest::cmd::_testcl_http_request_orig
    proc ::itest::cmd::http_request {args} {
        return [eval [linsert $args 0 ::itest::semantic::_http_message_command request]]
    }
}
if {[::tmm::_orig_info commands ::itest::cmd::lb_server] ne ""} {
    ::tmm::_orig_rename ::itest::cmd::lb_server ::itest::cmd::_testcl_lb_server_orig
    proc ::itest::cmd::lb_server {args} {
        return [eval [linsert $args 0 ::itest::semantic::lb_server_command]]
    }
}
foreach {original replacement} {
    http_is_keepalive http_is_keepalive_command
    http_is_redirect http_is_redirect_command
    http_request_num http_request_num_command
    http_has_responded http_has_responded_command
    http_redirect http_redirect_command
    http_release http_release_command
} {
    if {[::tmm::_orig_info commands ::itest::cmd::$original] ne ""} {
        ::tmm::_orig_rename ::itest::cmd::$original ::itest::cmd::_testcl_${original}_orig
        proc ::itest::cmd::$original {args} [format {
            return [eval [linsert $args 0 ::itest::semantic::%s]]
        } $replacement]
    }
}
foreach {original replacement} {
    mqtt_clean_session mqtt_clean_session_command
    mqtt_client_id mqtt_client_id_command
    mqtt_collect mqtt_collect_command
    mqtt_disable mqtt_disable_command
    mqtt_disconnect mqtt_disconnect_command
    mqtt_drop mqtt_drop_command
    mqtt_dup mqtt_dup_command
    mqtt_enable mqtt_enable_command
    mqtt_keep_alive mqtt_keep_alive_command
    mqtt_length mqtt_length_command
    mqtt_message mqtt_message_command
    mqtt_packet_id mqtt_packet_id_command
    mqtt_password mqtt_password_command
    mqtt_payload mqtt_payload_command
    mqtt_protocol_name mqtt_protocol_name_command
    mqtt_protocol_version mqtt_protocol_version_command
    mqtt_qos mqtt_qos_command
    mqtt_release mqtt_release_command
    mqtt_retain mqtt_retain_command
    mqtt_return_code mqtt_return_code_command
    mqtt_return_code_list mqtt_return_code_list_command
    mqtt_session_present mqtt_session_present_command
    mqtt_topic mqtt_topic_command
    mqtt_type mqtt_type_command
    mqtt_username mqtt_username_command
} {
    if {[::tmm::_orig_info commands ::itest::cmd::$original] ne ""} {
        ::tmm::_orig_rename ::itest::cmd::$original ::itest::cmd::_testcl_${original}_orig
        proc ::itest::cmd::$original {args} [format {
            return [eval [linsert $args 0 ::itest::semantic::%s]]
        } $replacement]
    }
}
if {[::tmm::_orig_info commands ::itest::cmd::http_header] ne ""} {
    ::tmm::_orig_rename ::itest::cmd::http_header ::itest::cmd::_testcl_http_header_orig
    proc ::itest::cmd::http_header {args} {
        if {[llength $args] == 1 && [lindex $args 0] eq "is_keepalive"} {
            return [::itest::semantic::http_is_keepalive_command]
        }
        if {[llength $args] == 1 && [lindex $args 0] eq "is_redirect"} {
            return [::itest::semantic::http_is_redirect_command]
        }
        if {$::itest::current_event eq "HTTP_RESPONSE_CONTINUE"} {
            set previous_event $::itest::current_event
            set ::itest::current_event HTTP_RESPONSE
            set rc [catch {
                eval [linsert $args 0 ::itest::cmd::_testcl_http_header_orig]
            } result options]
            set ::itest::current_event $previous_event
            if {$rc} {
                return -options $options $result
            }
            return $result
        }
        if {[info exists ::state::http::response_committed] &&
            $::state::http::response_committed && [llength $args] > 0 &&
            [lindex $args 0] in {insert replace remove sanitize}} {
            error "HTTP response has already been committed"
        }
        return [eval [linsert $args 0 ::itest::cmd::_testcl_http_header_orig]]
    }
}
if {[::tmm::_orig_info commands ::itest::cmd::http_cookie] ne ""} {
    ::tmm::_orig_rename ::itest::cmd::http_cookie ::itest::cmd::_testcl_http_cookie_orig
    proc ::itest::cmd::http_cookie {args} {
        return [eval [linsert $args 0 ::itest::semantic::cookie_command]]
    }
}
if {[::tmm::_orig_info commands ::itest::cmd::http_collect] ne ""} {
    ::tmm::_orig_rename ::itest::cmd::http_collect ::itest::cmd::_testcl_http_collect_orig
    proc ::itest::cmd::http_collect {args} {
        return [eval [linsert $args 0 ::itest::semantic::http_collect_command]]
    }
}
if {[::tmm::_orig_info commands ::itest::cmd::http_payload] ne ""} {
    ::tmm::_orig_rename ::itest::cmd::http_payload ::itest::cmd::_testcl_http_payload_semantic_orig
    proc ::itest::cmd::http_payload {args} {
        return [eval [linsert $args 0 ::itest::semantic::http_payload_command]]
    }
}
if {[::tmm::_orig_info commands ::itest::fire_event] ne "" &&
    [::tmm::_orig_info commands ::itest::_testcl_fire_event_orig] eq ""} {
    ::tmm::_orig_rename ::itest::fire_event ::itest::_testcl_fire_event_orig
    proc ::itest::fire_event {event_name} {
        set gated [info exists ::itest::semantic::automatic_http_flow]
        set is_request_data [expr {$event_name eq "HTTP_REQUEST_DATA"}]
        set is_response_data [expr {$event_name eq "HTTP_RESPONSE_DATA"}]
        if {$gated && ($is_request_data || $is_response_data)} {
            if {$is_request_data} {
                set collecting $::state::http::collect_request
                set length $::state::http::collect_request_length
                set payload $::state::http::request::payload
            } else {
                set collecting $::state::http::collect_response
                set length $::state::http::collect_response_length
                set payload $::state::http::response::payload
            }
            if {!$collecting ||
                ![string is integer -strict $length] ||
                ($length > 0 && [string bytelength $payload] < $length)} {
                return [list fired 0 reason "collect_not_ready"]
            }
            # HTTP data collection is released when its data event completes.
            # Clearing before dispatch lets the handler explicitly re-arm it.
            if {$is_request_data} {
                set ::state::http::collect_request 0
            } else {
                set ::state::http::collect_response 0
            }
        }
        set result [uplevel 1 [list ::itest::_testcl_fire_event_orig $event_name]]
        if {$gated && $event_name eq "HTTP_REQUEST"} {
            ::itest::semantic::_maybe_fire_lb_failed
        }
        return $result
    }
}
foreach {original replacement} {
    tcp_close tcp_close_command
    tcp_collect tcp_collect_command
    tcp_payload tcp_payload_command
    tcp_release tcp_release_command
    tcp_respond tcp_respond_command
} {
    if {[::tmm::_orig_info commands ::itest::cmd::$original] ne ""} {
        ::tmm::_orig_rename ::itest::cmd::$original ::itest::cmd::_testcl_${original}_orig
        proc ::itest::cmd::$original {args} [format {
            return [eval [linsert $args 0 ::itest::semantic::%s]]
        } $replacement]
    }
}
foreach {original replacement} {
    ws_collect ws_collect_command
    ws_disconnect ws_disconnect_command
    ws_enabled ws_enabled_command
    ws_frame ws_frame_command
    ws_masking ws_masking_command
    ws_message ws_message_command
    ws_payload ws_payload_command
    ws_release ws_release_command
    ws_request ws_request_command
    ws_response ws_response_command
} {
    if {[::tmm::_orig_info commands ::itest::cmd::$original] ne ""} {
        ::tmm::_orig_rename ::itest::cmd::$original ::itest::cmd::_testcl_${original}_orig
        proc ::itest::cmd::$original {args} [format {
            return [eval [linsert $args 0 ::itest::semantic::%s]]
        } $replacement]
    }
}
foreach {original replacement} {
    active_members active_members_command
    active_nodes active_nodes_command
    b64decode b64decode_command
    b64encode b64encode_command
    client_addr client_addr_command
    client_port client_port_command
    crc32 crc32_command
    decode_uri decode_uri_command
    domain domain_command
    findclass findclass_command
    findstr findstr_command
    getfield getfield_command
    llookup llookup_command
    matchclass matchclass_command
    md5 md5_command
    members members_command
    nodes nodes_command
    peer peer_command
    clientside clientside_command
    local_addr local_addr_command
    local_port local_port_command
    remote_addr remote_addr_command
    remote_port remote_port_command
    serverside serverside_command
    server_addr server_addr_command
    server_port server_port_command
    sha1 sha1_command
    sha256 sha256_command
    sha384 sha384_command
    sha512 sha512_command
    substr substr_command
} {
    if {[::tmm::_orig_info commands ::itest::cmd::cmd_$original] ne ""} {
        ::tmm::_orig_rename ::itest::cmd::cmd_$original ::itest::cmd::_testcl_${original}_orig
        proc ::itest::cmd::cmd_$original {args} [format {
            return [eval [linsert $args 0 ::itest::semantic::%s]]
        } $replacement]
    }
}
foreach {original replacement} {
    diameter_avp diameter_avp_command
    diameter_command diameter_command_command
    diameter_disconnect diameter_disconnect_command
    diameter_drop diameter_drop_command
    diameter_dynamic_route_insertion diameter_dynamic_route_insertion_command
    diameter_dynamic_route_lookup diameter_dynamic_route_lookup_command
    diameter_header diameter_header_command
    diameter_host diameter_host_command
    diameter_is_request diameter_is_request_command
    diameter_is_response diameter_is_response_command
    diameter_is_retransmission diameter_is_retransmission_command
    diameter_length diameter_length_command
    diameter_message diameter_message_command
    diameter_payload diameter_payload_command
    diameter_persist diameter_persist_command
    diameter_realm diameter_realm_command
    diameter_respond diameter_respond_command
    diameter_result diameter_result_command
    diameter_retransmission diameter_retransmission_command
    diameter_retransmission_default diameter_retransmission_default_command
    diameter_retransmission_reason diameter_retransmission_reason_command
    diameter_retransmit diameter_retransmit_command
    diameter_retry diameter_retry_command
    diameter_route_status diameter_route_status_command
    diameter_session diameter_session_command
    diameter_skip_capabilities_exchange diameter_skip_capabilities_exchange_command
    diameter_state diameter_state_command
} {
    if {[::tmm::_orig_info commands ::itest::cmd::$original] ne ""} {
        ::tmm::_orig_rename ::itest::cmd::$original ::itest::cmd::_testcl_${original}_orig
        proc ::itest::cmd::$original {args} [format {
            return [eval [linsert $args 0 ::itest::semantic::%s]]
        } $replacement]
    }
}
foreach {original replacement} {
    radius_avp radius_avp_command
    radius_code radius_code_command
    radius_id radius_id_command
    radius_rtdom radius_rtdom_command
    radius_subscriber radius_subscriber_command
} {
    if {[::tmm::_orig_info commands ::itest::cmd::$original] ne ""} {
        ::tmm::_orig_rename ::itest::cmd::$original ::itest::cmd::_testcl_${original}_orig
        proc ::itest::cmd::$original {args} [format {
            return [eval [linsert $args 0 ::itest::semantic::%s]]
        } $replacement]
    }
}
if {[::tmm::_orig_info commands ::itest::cmd::cmd_radius_authenticate] ne ""} {
    ::tmm::_orig_rename ::itest::cmd::cmd_radius_authenticate ::itest::cmd::_testcl_cmd_radius_authenticate_orig
    proc ::itest::cmd::cmd_radius_authenticate {args} {
        return [eval [linsert $args 0 ::itest::semantic::radius_authenticate_command]]
    }
}
foreach {original replacement} {
    gtp_clone gtp_clone_command
    gtp_discard gtp_discard_command
    gtp_forward gtp_forward_command
    gtp_header gtp_header_command
    gtp_ie gtp_ie_command
    gtp_length gtp_length_command
    gtp_message gtp_message_command
    gtp_new gtp_new_command
    gtp_parse gtp_parse_command
    gtp_payload gtp_payload_command
    gtp_respond gtp_respond_command
    gtp_tunnel gtp_tunnel_command
} {
    if {[::tmm::_orig_info commands ::itest::cmd::$original] ne ""} {
        ::tmm::_orig_rename ::itest::cmd::$original ::itest::cmd::_testcl_${original}_orig
        proc ::itest::cmd::$original {args} [format {
            return [eval [linsert $args 0 ::itest::semantic::%s]]
        } $replacement]
    }
}
foreach {original replacement} {
    sip_call_id sip_call_id_command
    sip_discard sip_discard_command
    sip_from sip_from_command
    sip_header sip_header_command
    sip_message sip_message_command
    sip_method sip_method_command
    sip_payload sip_payload_command
    sip_persist sip_persist_command
    sip_record_route sip_record_route_command
    sip_respond sip_respond_command
    sip_response sip_response_command
    sip_route sip_route_command
    sip_route_status sip_route_status_command
    sip_to sip_to_command
    sip_uri sip_uri_command
    sip_via sip_via_command
} {
    if {[::tmm::_orig_info commands ::itest::cmd::$original] ne ""} {
        ::tmm::_orig_rename ::itest::cmd::$original ::itest::cmd::_testcl_${original}_orig
        proc ::itest::cmd::$original {args} [format {
            return [eval [linsert $args 0 ::itest::semantic::%s]]
        } $replacement]
    }
}

# Override only the catalogued generated stubs implemented above. The mapping
# stays in the upstream dispatcher, so Tcl command resolution and profiling
# retain the original iRule spelling.
foreach {name proc_name} {
    HSL::open ::itest::semantic::hsl_open
    HSL::send ::itest::semantic::hsl_send
    HTTP::passthrough_reason ::itest::semantic::http_passthrough_reason
    HTTP::password ::itest::semantic::http_password
    HTTP::reject_reason ::itest::semantic::http_reject_reason
    HTTP::response ::itest::semantic::http_response
    HTTP::username ::itest::semantic::http_username
    HTTP::cookie ::itest::cmd::http_cookie
    TCP::collect ::itest::cmd::tcp_collect
    TCP::offset ::itest::semantic::tcp_offset_command
    TCP::payload ::itest::cmd::tcp_payload
    TCP::release ::itest::cmd::tcp_release
    TCP::respond ::itest::cmd::tcp_respond
    peer ::itest::cmd::cmd_peer
    clientside ::itest::cmd::cmd_clientside
    serverside ::itest::cmd::cmd_serverside
    IP::addr ::itest::semantic::ip_addr
    IP::version ::itest::semantic::ip_version
    PROFILE::clientssl ::itest::semantic::profile_clientssl
    PROFILE::exists ::itest::semantic::profile_exists
    PROFILE::fastL4 ::itest::semantic::profile_fastL4
    PROFILE::fasthttp ::itest::semantic::profile_fasthttp
    PROFILE::http ::itest::semantic::profile_http
    PROFILE::list ::itest::semantic::profile_list
    PROFILE::serverssl ::itest::semantic::profile_serverssl
    PROFILE::tcp ::itest::semantic::profile_tcp
    PROFILE::udp ::itest::semantic::profile_udp
    STATS::get ::itest::semantic::stats_get
    STATS::incr ::itest::semantic::stats_incr
    STATS::set ::itest::semantic::stats_set
    STATS::setmax ::itest::semantic::stats_setmax
    STATS::setmin ::itest::semantic::stats_setmin
    LB::down ::itest::semantic::lb_down
    LB::persist ::itest::semantic::lb_persist
    LB::reselect ::itest::semantic::lb_reselect
    LB::status ::itest::semantic::lb_status
    LB::up ::itest::semantic::lb_up
    pool ::itest::cmd::cmd_pool
    table ::itest::cmd::cmd_table
    URI::basename ::itest::semantic::uri_basename
    URI::decode ::itest::semantic::uri_decode
    URI::encode ::itest::semantic::uri_encode
    URI::encode_component ::itest::semantic::uri_encode_component
    URI::escape ::itest::semantic::uri_escape
    URI::host ::itest::semantic::uri_host
    URI::path ::itest::semantic::uri_path
    URI::port ::itest::semantic::uri_port
    URI::protocol ::itest::semantic::uri_protocol
    URI::query ::itest::semantic::uri_query
    URI::compare ::itest::semantic::uri_compare
    DNS::origin ::itest::semantic::dns_origin
    DNS::question ::itest::semantic::dns_question
    DNS::additional ::itest::semantic::dns_additional_command
    DNS::answer ::itest::semantic::dns_answer_command
    DNS::authority ::itest::semantic::dns_authority_command
    DNS::class ::itest::semantic::dns_class_command
    DNS::disable ::itest::semantic::dns_disable_command
    DNS::drop ::itest::semantic::dns_drop_command
    DNS::edns0 ::itest::semantic::dns_edns0_command
    DNS::enable ::itest::semantic::dns_enable_command
    DNS::header ::itest::semantic::dns_header_command
    DNS::is_wideip ::itest::semantic::dns_is_wideip_command
    DNS::last_act ::itest::semantic::dns_last_act_command
    DNS::len ::itest::semantic::dns_len_command
    DNS::log ::itest::semantic::dns_log_command
    DNS::name ::itest::semantic::dns_name_command
    DNS::ptype ::itest::semantic::dns_ptype_command
    DNS::query ::itest::semantic::dns_query_command
    DNS::rdata ::itest::semantic::dns_rdata_command
    DNS::return ::itest::semantic::dns_return_command
    DNS::rpz_policy ::itest::semantic::dns_rpz_policy_command
    DNS::rr ::itest::semantic::dns_rr_command
    DNS::scrape ::itest::semantic::dns_scrape_command
    DNS::ttl ::itest::semantic::dns_ttl_command
    DNS::type ::itest::semantic::dns_type_command
    DNSMSG::header ::itest::semantic::dnsmsg_header_command
    DNSMSG::record ::itest::semantic::dnsmsg_record_command
    DNSMSG::section ::itest::semantic::dnsmsg_section_command
    RESOLVER::name_lookup ::itest::semantic::resolver_name_lookup
    RESOLVER::summarize ::itest::semantic::resolver_summarize
    SSL::cert ::itest::semantic::ssl_cert_command
    SSL::cipher ::itest::semantic::ssl_cipher_command
    SSL::disable ::itest::semantic::ssl_disable_command
    SSL::enable ::itest::semantic::ssl_enable_command
    SSL::sessionid ::itest::semantic::ssl_sessionid_command
    SSL::sni ::itest::semantic::ssl_sni_command
    SSL::verify_result ::itest::semantic::ssl_verify_result_command
    X509::issuer ::itest::semantic::x509_issuer_command
    X509::subject ::itest::semantic::x509_subject_command
    HTTP2::active ::itest::semantic::http2_active_command
    HTTP2::concurrency ::itest::semantic::http2_concurrency_command
    HTTP2::disable ::itest::semantic::http2_disable_command
    HTTP2::disconnect ::itest::semantic::http2_disconnect_command
    HTTP2::enable ::itest::semantic::http2_enable_command
    HTTP2::header ::itest::semantic::http2_header_command
    HTTP2::requests ::itest::semantic::http2_requests_command
    HTTP2::stream ::itest::semantic::http2_stream_command
    HTTP2::version ::itest::semantic::http2_version_command
    class ::itest::cmd::cmd_class
    MQTT::clean_session ::itest::cmd::mqtt_clean_session
    MQTT::client_id ::itest::cmd::mqtt_client_id
    MQTT::collect ::itest::cmd::mqtt_collect
    MQTT::disable ::itest::cmd::mqtt_disable
    MQTT::disconnect ::itest::cmd::mqtt_disconnect
    MQTT::drop ::itest::cmd::mqtt_drop
    MQTT::dup ::itest::cmd::mqtt_dup
    MQTT::enable ::itest::cmd::mqtt_enable
    MQTT::keep_alive ::itest::cmd::mqtt_keep_alive
    MQTT::length ::itest::cmd::mqtt_length
    MQTT::message ::itest::cmd::mqtt_message
    MQTT::packet_id ::itest::cmd::mqtt_packet_id
    MQTT::password ::itest::cmd::mqtt_password
    MQTT::payload ::itest::cmd::mqtt_payload
    MQTT::protocol_name ::itest::cmd::mqtt_protocol_name
    MQTT::protocol_version ::itest::cmd::mqtt_protocol_version
    MQTT::qos ::itest::cmd::mqtt_qos
    MQTT::release ::itest::cmd::mqtt_release
    MQTT::retain ::itest::cmd::mqtt_retain
    MQTT::return_code ::itest::cmd::mqtt_return_code
    MQTT::return_code_list ::itest::cmd::mqtt_return_code_list
    MQTT::session_present ::itest::cmd::mqtt_session_present
    MQTT::topic ::itest::cmd::mqtt_topic
    MQTT::type ::itest::cmd::mqtt_type
    MQTT::username ::itest::cmd::mqtt_username
    SIP::call_id ::itest::semantic::sip_call_id_command
    SIP::discard ::itest::semantic::sip_discard_command
    SIP::from ::itest::semantic::sip_from_command
    SIP::header ::itest::semantic::sip_header_command
    SIP::message ::itest::semantic::sip_message_command
    SIP::method ::itest::semantic::sip_method_command
    SIP::payload ::itest::semantic::sip_payload_command
    SIP::persist ::itest::semantic::sip_persist_command
    SIP::record-route ::itest::semantic::sip_record_route_command
    SIP::respond ::itest::semantic::sip_respond_command
    SIP::response ::itest::semantic::sip_response_command
    SIP::route ::itest::semantic::sip_route_command
    SIP::route_status ::itest::semantic::sip_route_status_command
    SIP::to ::itest::semantic::sip_to_command
    SIP::uri ::itest::semantic::sip_uri_command
    SIP::via ::itest::semantic::sip_via_command
    DIAMETER::avp ::itest::semantic::diameter_avp_command
    DIAMETER::command ::itest::semantic::diameter_command_command
    DIAMETER::disconnect ::itest::semantic::diameter_disconnect_command
    DIAMETER::drop ::itest::semantic::diameter_drop_command
    DIAMETER::dynamic_route_insertion ::itest::semantic::diameter_dynamic_route_insertion_command
    DIAMETER::dynamic_route_lookup ::itest::semantic::diameter_dynamic_route_lookup_command
    DIAMETER::header ::itest::semantic::diameter_header_command
    DIAMETER::host ::itest::semantic::diameter_host_command
    DIAMETER::is_request ::itest::semantic::diameter_is_request_command
    DIAMETER::is_response ::itest::semantic::diameter_is_response_command
    DIAMETER::is_retransmission ::itest::semantic::diameter_is_retransmission_command
    DIAMETER::length ::itest::semantic::diameter_length_command
    DIAMETER::message ::itest::semantic::diameter_message_command
    DIAMETER::payload ::itest::semantic::diameter_payload_command
    DIAMETER::persist ::itest::semantic::diameter_persist_command
    DIAMETER::realm ::itest::semantic::diameter_realm_command
    DIAMETER::respond ::itest::semantic::diameter_respond_command
    DIAMETER::result ::itest::semantic::diameter_result_command
    DIAMETER::retransmission ::itest::semantic::diameter_retransmission_command
    DIAMETER::retransmission_default ::itest::semantic::diameter_retransmission_default_command
    DIAMETER::retransmission_reason ::itest::semantic::diameter_retransmission_reason_command
    DIAMETER::retransmit ::itest::semantic::diameter_retransmit_command
    DIAMETER::retry ::itest::semantic::diameter_retry_command
    DIAMETER::route_status ::itest::semantic::diameter_route_status_command
    DIAMETER::session ::itest::semantic::diameter_session_command
    DIAMETER::skip_capabilities_exchange ::itest::semantic::diameter_skip_capabilities_exchange_command
    DIAMETER::state ::itest::semantic::diameter_state_command
    RADIUS::avp ::itest::semantic::radius_avp_command
    RADIUS::code ::itest::semantic::radius_code_command
    RADIUS::id ::itest::semantic::radius_id_command
    RADIUS::rtdom ::itest::semantic::radius_rtdom_command
    RADIUS::subscriber ::itest::semantic::radius_subscriber_command
    radius_authenticate ::itest::semantic::radius_authenticate_command
    MESSAGE::field ::itest::semantic::message_field_command
    MESSAGE::proto ::itest::semantic::message_proto_command
    MESSAGE::type ::itest::semantic::message_type_command
    GENERICMESSAGE::message ::itest::semantic::genericmessage_message_command
    GENERICMESSAGE::peer ::itest::semantic::genericmessage_peer_command
    GENERICMESSAGE::route ::itest::semantic::genericmessage_route_command
    MR::always_match_port ::itest::semantic::mr_always_match_port_command
    MR::available_for_routing ::itest::semantic::mr_available_for_routing_command
    MR::collect ::itest::semantic::mr_collect_command
    MR::connect_back_port ::itest::semantic::mr_connect_back_port_command
    MR::connection_instance ::itest::semantic::mr_connection_instance_command
    MR::connection_mode ::itest::semantic::mr_connection_mode_command
    MR::equivalent_transport ::itest::semantic::mr_equivalent_transport_command
    MR::flow_id ::itest::semantic::mr_flow_id_command
    MR::ignore_peer_port ::itest::semantic::mr_ignore_peer_port_command
    MR::instance ::itest::semantic::mr_instance_command
    MR::max_retries ::itest::semantic::mr_max_retries_command
    MR::message ::itest::semantic::mr_message_command
    MR::payload ::itest::semantic::mr_payload_command
    MR::peer ::itest::semantic::mr_peer_command
    MR::prime ::itest::semantic::mr_prime_command
    MR::protocol ::itest::semantic::mr_protocol_command
    MR::release ::itest::semantic::mr_release_command
    MR::restore ::itest::semantic::mr_restore_command
    MR::retry ::itest::semantic::mr_retry_command
    MR::return ::itest::semantic::mr_return_command
    MR::store ::itest::semantic::mr_store_command
    MR::stream ::itest::semantic::mr_stream_command
    MR::transport ::itest::semantic::mr_transport_command
    GTP::clone ::itest::semantic::gtp_clone_command
    GTP::discard ::itest::semantic::gtp_discard_command
    GTP::forward ::itest::semantic::gtp_forward_command
    GTP::header ::itest::semantic::gtp_header_command
    GTP::ie ::itest::semantic::gtp_ie_command
    GTP::length ::itest::semantic::gtp_length_command
    GTP::message ::itest::semantic::gtp_message_command
    GTP::new ::itest::semantic::gtp_new_command
    GTP::parse ::itest::semantic::gtp_parse_command
    GTP::payload ::itest::semantic::gtp_payload_command
    GTP::respond ::itest::semantic::gtp_respond_command
    GTP::tunnel ::itest::semantic::gtp_tunnel_command
} {
    ::itest::register_command $name $proc_name
}

# The upstream HTTP orchestrator resets per-request state internally. Apply
# adapter-supplied HTTP/2 metadata immediately before each event so that the
# metadata survives that reset while direct event calls remain unaffected.
if {[::tmm::_orig_info commands ::itest::semantic::_testcl_fire_event_orig] eq "" &&
    [::tmm::_orig_info commands ::itest::fire_event] ne ""} {
    ::tmm::_orig_rename ::itest::fire_event ::itest::semantic::_testcl_fire_event_orig
    proc ::itest::fire_event {args} {
        ::itest::semantic::http2_apply_pending
        return [eval [linsert $args 0 ::itest::semantic::_testcl_fire_event_orig]]
    }
}
