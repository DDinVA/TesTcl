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
        return $::state::http::response::status
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

    proc _select_available_member {pool_name} {
        if {![info exists ::state::lb::pools($pool_name)]} {
            return 0
        }
        set pool_info $::state::lb::pools($pool_name)
        set members [lindex $pool_info 1]
        foreach member $members {
            if {[_member_status $pool_name $member] in {down disabled}} {
                continue
            }
            set ::state::lb::pool_member $member
            set colonpos [string last ":" $member]
            if {$colonpos >= 0} {
                set ::state::lb::node_addr [string range $member 0 [expr {$colonpos - 1}]]
                set ::state::lb::node_port [string range $member [expr {$colonpos + 1}] end]
            }
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
        _select_available_member $pool_name
        return $result
    }

    proc lb_reselect {args} {
        if {$::state::lb::pool ne ""} {
            _select_available_member $::state::lb::pool
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
}

# Preserve the upstream pool behavior and replace only its member choice.
if {[::tmm::_orig_info commands ::itest::cmd::cmd_pool] ne ""} {
    ::tmm::_orig_rename ::itest::cmd::cmd_pool ::itest::cmd::_testcl_pool_orig
    proc ::itest::cmd::cmd_pool {args} {
        return [eval [linsert $args 0 ::itest::semantic::pool_status_aware]]
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
    LB::reselect ::itest::semantic::lb_reselect
    LB::status ::itest::semantic::lb_status
    LB::up ::itest::semantic::lb_up
    pool ::itest::cmd::cmd_pool
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
} {
    ::itest::register_command $name $proc_name
}
