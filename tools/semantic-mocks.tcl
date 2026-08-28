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

    proc dns_question {args} {
        if {[llength $args] == 1} {
            switch -exact -- [string tolower [lindex $args 0]] {
                name { return $::state::dns::qname }
                type { return $::state::dns::qtype }
                default { error "DNS::question supports name and type" }
            }
        }
        if {[llength $args] == 2} {
            set field [string tolower [lindex $args 0]]
            switch -exact -- $field {
                name { set ::state::dns::qname [lindex $args 1] }
                type { set ::state::dns::qtype [lindex $args 1] }
                default { error "DNS::question supports name and type" }
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
} {
    ::itest::register_command $name $proc_name
}
