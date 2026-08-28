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
    variable http_close_requested 0
    variable http_request_number 0

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

    proc http_retry_snapshot {} {
        variable http_retry_requested
        variable http_retry_request
        variable http_retry_reset
        return [list requested $http_retry_requested request $http_retry_request reset $http_retry_reset]
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
            SERVERSSL_SERVERHELLO HTTP_RESPONSE HTTP_RESPONSE_DATA
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
            HTTP_RESPONSE HTTP_RESPONSE_DATA HTTP_RESPONSE_RELEASE
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
} {
    ::itest::register_command $name $proc_name
}
