# semantic-mocks.tcl -- TesTcl's adapter-owned semantic iRule mocks
#
# The upstream tcl-lsp framework provides broad command recognition and
# generated placeholders. This small overlay implements high-value behavior
# that depends on the adapter's scenario state without modifying the external
# tcl-lsp checkout.

namespace eval ::itest::semantic {
    variable stats
    array set stats {}
    variable istats
    array set istats {}
    variable oneconnect_detach_enabled 1
    variable oneconnect_reuse_enabled 1
    variable oneconnect_select_mode none
    variable oneconnect_label ""
    variable adapt_contexts {}
    variable adapt_context_counter 0
    variable adapt_current_handle "static:request"
    variable adapt_current_side request
    variable crypto_contexts {}
    variable crypto_context_max_bytes 16777216
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
    variable http_proxy_default_enabled 1
    variable http_proxy_default_uri_rewrite 1
    variable http_proxy_default_resolved 0
    variable http_proxy_default_addr ""
    variable http_proxy_default_port 0
    variable http_proxy_default_rtdom 0
    variable http_proxy_default_iptuple ""
    variable http_proxy_default_chain_enabled 1
    variable http_proxy_default_chain_host ""
    variable http_proxy_default_chain_port 0
    variable http_proxy_enabled 1
    variable http_proxy_uri_rewrite 1
    variable http_proxy_resolved 0
    variable http_proxy_addr ""
    variable http_proxy_port 0
    variable http_proxy_rtdom 0
    variable http_proxy_iptuple ""
    variable http_proxy_chain_enabled 1
    variable http_proxy_chain_host ""
    variable http_proxy_chain_port 0
    variable http_proxy_chain_retry_requested 0
    variable rewrite_default_enabled 1
    variable rewrite_enabled 1
    variable rewrite_post_process 0
    variable rewrite_payload_side ""
    variable rewrite_payload_replaced 0
    variable rewrite_injecting 0
    variable html_enabled 0
    variable html_processing 0
    variable html_current_type ""
    variable html_current_name ""
    variable html_current_raw ""
    variable html_current_prepend ""
    variable html_current_append ""
    variable html_current_removed 0
    variable html_token_count 0
    variable html_mutated 0
    variable compress_request_enabled 0
    variable compress_response_enabled 0
    variable compress_request_method "gzip"
    variable compress_response_method "gzip"
    variable compress_request_buffer_size 0
    variable compress_response_buffer_size 0
    variable compress_request_gzip_level 6
    variable compress_response_gzip_level 6
    variable compress_request_gzip_memory_level 8
    variable compress_response_gzip_memory_level 8
    variable compress_request_gzip_window_size 15
    variable compress_response_gzip_window_size 15
    variable compress_request_nodelay 0
    variable compress_response_nodelay 0
    variable decompress_request_enabled 0
    variable decompress_response_enabled 0
    variable compress_applied 0
    variable compress_applied_side ""
    variable compress_input_length 0
    variable compress_output_length 0
    variable decompress_applied 0
    variable decompress_applied_side ""
    variable decompress_input_length 0
    variable decompress_output_length 0
    variable compression_codec_error ""
    variable httplog_enabled 0
    variable httplog_records {}
    variable psm_enabled
    array set psm_enabled {FTP 1 HTTP 1 SMTP 1}
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
    variable mqtt_response_requested 0
    variable mqtt_response_message {}
    variable mqtt_insertions {}
    variable mqtt_operations {}
    variable mqtt_message_replaced 0

    variable ip_default_hops 0
    variable ip_hops 0
    variable ip_intelligence_records [dict create]
    variable ip_reputation_records [dict create]
    variable ip_drop_rates [dict create]
    variable ip_global_gray_list_rate 0
    variable ip_global_rate 0
    variable ip_stats_pkts_in 0
    variable ip_stats_pkts_out 0
    variable ip_stats_bytes_in 0
    variable ip_stats_bytes_out 0
    variable ip_stats_age_ms 0

    variable dns_rr_counter 0
    variable dns_rr_objects [dict create]
    variable dns_message_counter 0
    variable dns_message_objects [dict create]
    variable resolver_records [dict create]
    variable ssl_cert_counter 0
    variable ssl_cert_objects [dict create]
    variable http2_push_counter 0
    variable http2_pending [dict create]
    variable udp_unused_port_next 40000
    variable tcp_unused_port_next 49152
    variable tcp_unused_ports [dict create]
    variable rtsp_collection_requested 0
    variable rtsp_collection_length 0
    variable rtsp_release_requested 0
    variable cache_tick 0
    variable cache_update_tick -1
    variable cache_objects
    array set cache_objects {}
    variable route_metrics [dict create]

    variable lb_bias 0
    variable lb_class ""
    variable lb_command ""
    variable lb_context_id ""
    variable lb_dst_tag ""
    variable lb_src_tag ""
    variable lb_decisionlog_enabled 0
    variable lb_connect_requested 0
    variable lb_prime_requested 0
    variable lb_connlimits
    variable lb_queue_on 0
    variable lb_queue_queued 0
    variable lb_queue_depth 0
    variable lb_queue_limit_depth 0
    variable lb_queue_limit_time 0
    variable lb_queue_age_head 0
    variable lb_queue_age_max 0
    variable lb_queue_age_edm 0
    variable lb_queue_age_ema 0
    set lb_connlimits [dict create]
    variable profile_settings
    set profile_settings [dict create]
    variable dosl7_default_enabled 1
    variable dosl7_enabled 1
    variable dosl7_health 0
    variable dosl7_profile ""
    variable dosl7_default_mitigated 0
    variable dosl7_mitigated 0
    variable dosl7_profile_object ""
    variable dosl7_greylist
    set dosl7_greylist [dict create]

    variable asm_default_enabled 1
    variable asm_enabled 1
    variable asm_default_policy ""
    variable asm_policy ""
    variable asm_default_client_ip ""
    variable asm_client_ip ""
    variable asm_default_fingerprint 0
    variable asm_fingerprint 0
    variable asm_default_username ""
    variable asm_username ""
    variable asm_default_login_status not_logged_in
    variable asm_login_status not_logged_in
    variable asm_default_microservice ""
    variable asm_microservice ""
    variable asm_default_status ""
    variable asm_status Clear
    variable asm_default_severity ""
    variable asm_severity ""
    variable asm_default_support_id ""
    variable asm_support_id ""
    variable asm_default_captcha_status not_received
    variable asm_captcha_status not_received
    variable asm_default_captcha_age -1
    variable asm_captcha_age -1
    variable asm_payload ""
    variable asm_default_payload ""
    variable asm_default_violations {}
    variable asm_violations {}
    variable asm_default_signatures [dict create]
    variable asm_signatures [dict create]
    variable asm_default_campaigns [dict create]
    variable asm_campaigns [dict create]
    variable asm_captcha_sent 0
    variable asm_uncaptcha 0
    variable asm_unblocked 0
    variable asm_conviction 0
    variable asm_deception 0

    variable botdefense_default_enabled 1
    variable botdefense_enabled 1
    variable botdefense_default_action allow
    variable botdefense_action allow
    variable botdefense_action_overridden 0
    variable botdefense_default_bot_anomalies {}
    variable botdefense_bot_anomalies {}
    variable botdefense_default_bot_categories {}
    variable botdefense_bot_categories {}
    variable botdefense_default_bot_name ""
    variable botdefense_bot_name ""
    variable botdefense_default_bot_signature ""
    variable botdefense_bot_signature ""
    variable botdefense_default_bot_signature_category ""
    variable botdefense_bot_signature_category ""
    variable botdefense_default_captcha_age -1
    variable botdefense_captcha_age -1
    variable botdefense_default_captcha_status not_received
    variable botdefense_captcha_status not_received
    variable botdefense_default_client_class unknown
    variable botdefense_client_class unknown
    variable botdefense_default_client_type uncategorized
    variable botdefense_client_type uncategorized
    variable botdefense_default_cookie_age -1
    variable botdefense_cookie_age -1
    variable botdefense_default_cookie_status ""
    variable botdefense_cookie_status ""
    variable botdefense_default_cs_allowed 1
    variable botdefense_cs_allowed 1
    variable botdefense_default_cs_attribute_device_id 1
    variable botdefense_cs_attribute_device_id 1
    variable botdefense_default_cs_possible 1
    variable botdefense_cs_possible 1
    variable botdefense_default_device_id 0
    variable botdefense_device_id 0
    variable botdefense_default_intent ""
    variable botdefense_intent ""
    variable botdefense_default_micro_service [list "" ""]
    variable botdefense_micro_service [list "" ""]
    variable botdefense_default_previous_action undetermined
    variable botdefense_previous_action undetermined
    variable botdefense_default_previous_request_age 0
    variable botdefense_previous_request_age 0
    variable botdefense_default_previous_support_id 0
    variable botdefense_previous_support_id 0
    variable botdefense_default_reason ""
    variable botdefense_reason ""
    variable botdefense_default_support_id ""
    variable botdefense_support_id ""

    variable antifraud_default_enabled 1
    variable antifraud_enabled 1
    variable antifraud_default_profile ""
    variable antifraud_profile ""
    variable antifraud_default_login_requested 0
    variable antifraud_default_alert_requested 0
    variable antifraud_default_client_id ""
    variable antifraud_client_id ""
    variable antifraud_default_device_id ""
    variable antifraud_device_id ""
    variable antifraud_default_fingerprint ""
    variable antifraud_fingerprint ""
    variable antifraud_default_geo ""
    variable antifraud_geo ""
    variable antifraud_default_guid ""
    variable antifraud_guid ""
    variable antifraud_default_result passed
    variable antifraud_result passed
    variable antifraud_default_username ""
    variable antifraud_username ""
    variable antifraud_default_license_id ""
    variable antifraud_license_id ""
    variable antifraud_default_alert_fields [dict create]
    variable antifraud_alert_fields [dict create]
    variable antifraud_login_requested 0
    variable antifraud_alert_requested 0
    variable antifraud_alert_disabled 0
    variable antifraud_log_enabled 0
    variable antifraud_log_level Informational
    variable antifraud_disabled_features [dict create]
    foreach field {
        alert_additional_info alert_bait_signatures alert_component alert_defined_value
        alert_details alert_device_id alert_expected_value alert_fingerprint
        alert_forbidden_added_element alert_guid alert_html alert_http_referrer alert_id
        alert_min alert_origin alert_resolved_value alert_score alert_transaction_data
        alert_transaction_id alert_type alert_username alert_view_id
    } {
        dict set antifraud_default_alert_fields $field ""
        dict set antifraud_alert_fields $field ""
    }
    foreach feature {
        app_layer_encryption auto_transactions injection malware phishing
    } {
        dict set antifraud_disabled_features $feature 0
    }

    variable auth_default_enabled 1
    variable auth_enabled 1
    variable auth_default_result success
    variable auth_configured_result success
    variable auth_default_type pam
    variable auth_type pam
    variable auth_default_service default_radius
    variable auth_service default_radius
    variable auth_default_prompt Password:
    variable auth_prompt Password:
    variable auth_default_prompt_style echo_off
    variable auth_prompt_style echo_off
    variable auth_default_credential_type password
    variable auth_credential_type password
    variable auth_default_ldap_status ""
    variable auth_ldap_status ""
    variable auth_default_ldap_username ""
    variable auth_ldap_username ""
    variable auth_default_response_data [dict create]
    variable auth_sessions [dict create]
    variable auth_next_id 0
    variable auth_last_event_session_id ""
    variable auth_last_event ""
    variable auth_current_session_id ""

    variable aaa_default_enabled 1
    variable aaa_enabled 1
    variable aaa_default_auth_result OK
    variable aaa_auth_result OK
    variable aaa_default_acct_result OK
    variable aaa_acct_result OK
    variable aaa_requests [dict create]
    variable aaa_next_id 0

    variable access_default_enabled 1
    variable access_enabled 1
    variable access_default_acl_result Allow
    variable access_acl_result Allow
    variable access_default_acl_lookup {}
    variable access_acl_lookup {}
    variable access_default_acl_matched {}
    variable access_acl_matched {}
    variable access_acl_evaluated {}
    variable access_default_policy_result allow
    variable access_policy_result allow
    variable access_default_policy_agent_id ""
    variable access_policy_agent_id ""
    variable access_default_policy_uri 0
    variable access_policy_uri 0
    variable access_default_flow_id ""
    variable access_flow_id ""
    variable access_request_enabled 1
    variable access_restrict_irule_events 1
    variable access_default_session_data [dict create]
    variable access_session_data [dict create]
    variable access_default_perflow [dict create]
    variable access_perflow [dict create]
    variable access_sessions [dict create]
    variable access_current_sid ""
    variable access_next_sid 0
    variable access_ephemeral_auth_password temporary-password
    variable access_ephemeral [dict create]
    variable access_ephemeral_next 0
    variable access_oauth_next 0
    variable access_user_keys [dict create]
    variable access_saml [dict create authn "" assertion "" slo_req "" slo_resp ""]

    # FLOW:: is represented by deterministic synthetic handles.  The base
    # connection always has one client and one server flow; related flows are
    # added by FLOW::create_related.  flow_clock advances once per dispatched
    # event so idle-duration assertions do not depend on wall-clock time.
    variable flow_clock 0
    variable flow_current_side client
    variable flow_next_related 0
    variable flow_handles [dict create]
    variable event_errors {}

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
        variable payload_ivs ""
        variable payload_processing enable
    }

    namespace eval ::state::route {
        variable domain 0
        variable destination ""
        variable gateway ""
        variable age 0
        variable expiration 0
        variable mtu 0
        variable rtt 0
        variable rttvar 0
        variable cwnd 0
        variable bandwidth 0
        variable cleared 0
    }

    namespace eval ::state::udp {
        variable payload ""
        variable payload_length 0
        variable client_port 0
        variable server_port 0
        variable local_port 0
        variable remote_port 0
        variable mss 1460
        variable max_buf_pkts 0
        variable max_rate 0
        variable sendbuffer 0
        variable debug_queue 0
        variable dropped 0
        variable held 0
        variable released 0
        variable responded 0
        variable response ""
        variable response_length 0
    }

    namespace eval ::state::sctp {
        variable payload ""
        variable payload_length 0
        variable client_port 0
        variable server_port 0
        variable local_port 0
        variable remote_port 0
        variable mss 1460
        variable ppi 0
        variable collect_requested 0
        variable collect_length 0
        variable released 0
        variable released_length 0
        variable responded 0
        variable response ""
        variable response_length 0
        variable rto_initial 1000
        variable rto_max 60000
        variable rto_min 100
        variable sack_timeout 200
    }

    namespace eval ::state::dhcp {
        variable version 4
    }

    namespace eval ::state::dhcpv4 {
        variable chaddr ""
        variable ciaddr 0.0.0.0
        variable drop 0
        variable giaddr 0.0.0.0
        variable hlen 6
        variable hops 0
        variable len 0
        variable opcode 1
        variable options {}
        variable reject 0
        variable secs 0
        variable siaddr 0.0.0.0
        variable type DISCOVER
        variable xid 0
        variable yiaddr 0.0.0.0
        variable payload ""
        variable payload_length 0
    }

    namespace eval ::state::dhcpv6 {
        variable drop 0
        variable hop_count 0
        variable len 0
        variable link_address ::
        variable msg_type SOLICIT
        variable options {}
        variable peer_address ::
        variable reject 0
        variable transaction_id 000000
        variable payload ""
        variable payload_length 0
    }

    namespace eval ::state::ftp {
        variable allow_active_mode disable
        variable command ""
        variable disabled 0
        variable enabled 1
        variable enforce_tls_session_reuse disable
        variable ftps_mode allow
        variable payload ""
        variable payload_length 0
        variable port_first 1024
        variable port_last 65535
        variable response_code 0
        variable tls_active 0
        variable tls_session_reused 0
        variable type command
        variable dropped 0
        variable rejected 0
    }

    namespace eval ::state::imap {
        variable activation_mode none
        variable command ""
        variable disabled 0
        variable enabled 1
        variable payload ""
        variable payload_length 0
        variable tls_active 0
        variable type command
    }

    namespace eval ::state::pop3 {
        variable activation_mode none
        variable command ""
        variable disabled 0
        variable enabled 1
        variable payload ""
        variable payload_length 0
        variable tls_active 0
        variable type command
    }

    namespace eval ::state::ldap {
        variable activation_mode none
        variable command ""
        variable disabled 0
        variable enabled 1
        variable payload ""
        variable payload_length 0
        variable tls_active 0
        variable type command
    }

    namespace eval ::state::smtps {
        variable activation_mode none
        variable command ""
        variable disabled 0
        variable enabled 1
        variable payload ""
        variable payload_length 0
        variable tls_active 0
        variable type command
    }

    namespace eval ::state::ntlm {
        variable disabled 0
        variable enabled 1
        variable payload ""
        variable payload_length 0
    }

    namespace eval ::state::protocol_inspection {
        variable disabled 0
        variable enabled 1
        variable ids {}
        variable matched 0
        variable payload ""
        variable payload_length 0
    }

    namespace eval ::state::classification {
        variable app ""
        variable category ""
        variable classify_application_add {}
        variable classify_application_set ""
        variable classify_additions {}
        variable classify_category_add {}
        variable classify_category_set ""
        variable classify_classified 0
        variable classify_defer 0
        variable classify_urlcat_add {}
        variable classify_urlcat_set ""
        variable classify_username ""
        variable classify_username_context ""
        variable detected 1
        variable deferred 0
        variable disabled 0
        variable enabled 1
        variable payload ""
        variable payload_length 0
        variable protocol ""
        variable result {}
        variable urlcat ""
        variable username ""
    }

    namespace eval ::state::category {
        variable analytics disable
        variable categories {}
        variable detected 1
        variable filetype_mimetype application/octet-stream
        variable filetype_mimesubtype octet-stream
        variable lookup_url ""
        variable matchtype request_default
        variable matched 1
        variable payload ""
        variable payload_length 0
        variable safesearch {}
        variable url ""
    }

    namespace eval ::state::icap {
        variable headers {Host icap.example.net}
        variable method REQMOD
        variable payload ""
        variable payload_length 0
        variable status 200
        variable type request
        variable uri icap://icap.example.net/reqmod
    }

    namespace eval ::state::datagram {
        variable ip_version 4
        variable ip_tos 0
        variable ip_ttl 64
        variable ip_flags 0
        variable ip_options {}
        variable ip6_hop_limit 64
        variable ip6_options {}
        variable l2_dest ""
        variable protocol 0
        variable tcp_flags 0
        variable tcp_window 0
        variable tcp_options {}
        variable payload ""
        variable payload_length 0
        variable dns_id 0
        variable dns_qr 0
        variable dns_opcode QUERY
        variable dns_qdcount 0
        variable dns_ancount 0
        variable dns_nscount 0
        variable dns_arcount 0
    }

    namespace eval ::state::tcp {
        variable abc enable
        variable analytics disable
        variable analytics_key ""
        variable autowin enable
        variable delayed_ack enable
        variable dsack enable
        variable earlyrxmit enable
        variable ecn enable
        variable enhanced_loss_recovery enable
        variable limxmit enable
        variable lossfilter_rate 0
        variable lossfilter_burst 0
        variable nagle auto
        variable naglemode auto
        variable naglestate enabled
        variable keepalive 0
        variable idletime 300
        variable sendbuf 0
        variable recvwnd 0
        variable rcv_size 65535
        variable snd_wnd 65535
        variable snd_cwnd 14600
        variable rto 1000
        variable rttvar 0
        variable rexmt_thresh 3
        variable rt_metrics_timeout 0
        variable rcv_scale 0
        variable snd_scale 0
        variable snd_ssthresh 1073725440
        variable pacing 0
        variable proxybuffer_high 0
        variable proxybuffer_low 0
        variable push_flag default
        variable congestion ""
    }

    namespace eval ::state::rtsp {
        variable type request
        variable method ""
        variable uri ""
        variable version "RTSP/1.0"
        variable status 200
        variable phrase "OK"
        variable msg_source client
        variable headers {}
        variable payload ""
        variable payload_length 0
        variable dropped 0
        variable responded 0
        variable response_status 0
        variable response_phrase ""
        variable response_headers {}
        variable response_body ""
    }

    namespace eval ::state::cache {
        variable uri ""
        variable useragent ""
        variable userkey ""
        variable accept_encoding ""
        variable key ""
        variable headers {}
        variable payload ""
        variable age 0
        variable hits 0
        variable fresh 0
        variable disabled 0
        variable forced 0
        variable expired 0
        variable priority 0
        variable statskey ""
        variable stored 0
        variable hit 0
    }

    foreach tls_side {client server} {
        namespace eval ::state::tls::$tls_side {
            variable sni ""
            variable sni_required 0
            variable cipher_name ""
            variable cipher_bits 0
            variable cipher_version ""
            variable cipher_clientlist ""
            variable clientrandom ""
            variable cert_subject ""
            variable cert_issuer ""
            variable cert_serial ""
            variable cert_hash ""
            variable cert_extensions ""
            variable cert_not_valid_after ""
            variable cert_not_valid_before ""
            variable cert_signature_algorithm ""
            variable cert_public_key ""
            variable cert_public_key_type "unknown"
            variable cert_public_key_bits 0
            variable cert_public_key_curve ""
            variable cert_version 3
            variable cert_pem ""
            variable cert_der ""
            variable cert_count 0
            variable cert_mode "ignore"
            variable verify_result 0
            variable disabled 0
            variable extensions ""
            variable alpn ""
            variable handshake_done 0
            variable session_id ""
            variable initial_session_id ""
            variable sessionticket ""
            variable nextproto ""
            variable session_secret ""
            variable tls13_client_app_secret ""
            variable tls13_client_hs_secret ""
            variable tls13_client_early_secret ""
            variable tls13_server_app_secret ""
            variable tls13_server_hs_secret ""
            variable c3d_cert ""
            variable c3d_subject_cn ""
            variable c3d_extensions [dict create]
            variable cert_constraints [list]
            variable collect_requested 0
            variable collect_length 0
            variable payload ""
            variable payload_length 0
            variable release_requested 0
            variable released_length 0
            variable forward_proxy_policy bypass
            variable forward_proxy_cert ""
            variable forward_proxy_extensions [dict create]
            variable forward_proxy_verified_handshake 0
            variable forward_proxy_response_control ignore
            variable forward_proxy_cert_status ""
            variable handshake_held 0
            variable renegotiation_enabled 1
            variable renegotiation_requested 0
            variable renegotiation_secure 0
            variable secure_renegotiation 0
            variable allow_nonssl 0
            variable dynamic_record_sizing 0
            variable maximum_record_size 16384
            variable profile ""
            variable session_invalidated 0
            variable session_drop 1
            variable unclean_shutdown 0
            variable authenticate_frequency ""
            variable authenticate_depth 0
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
            variable push_count 0
            variable pushes {}
            variable pseudo_headers {}
    }

    namespace eval ::state::stream {
        variable match ""
        variable encoding ascii
        variable expression ""
        variable max_matchsize 4096
        variable enabled 1
        variable disabled 0
        variable replacement ""
        variable replacement_requested 0
        variable replaced 0
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
        variable username_flag 0
        variable password_flag 0
        variable will_topic ""
        variable will_message ""
        variable will_qos 0
        variable will_retain 0
        variable will_flag 0
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

    proc istats_snapshot {} {
        variable istats
        return [array get istats]
    }

    proc oneconnect_snapshot {} {
        variable oneconnect_detach_enabled
        variable oneconnect_reuse_enabled
        variable oneconnect_select_mode
        variable oneconnect_label
        return [list $oneconnect_detach_enabled $oneconnect_reuse_enabled \
            $oneconnect_select_mode $oneconnect_label]
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

    proc http_proxy_prepare_request {} {
        variable http_proxy_default_enabled
        variable http_proxy_default_uri_rewrite
        variable http_proxy_default_resolved
        variable http_proxy_default_addr
        variable http_proxy_default_port
        variable http_proxy_default_rtdom
        variable http_proxy_default_iptuple
        variable http_proxy_default_chain_enabled
        variable http_proxy_default_chain_host
        variable http_proxy_default_chain_port
        variable http_proxy_enabled
        variable http_proxy_uri_rewrite
        variable http_proxy_resolved
        variable http_proxy_addr
        variable http_proxy_port
        variable http_proxy_rtdom
        variable http_proxy_iptuple
        variable http_proxy_chain_enabled
        variable http_proxy_chain_host
        variable http_proxy_chain_port
        variable http_proxy_chain_retry_requested
        set http_proxy_enabled $http_proxy_default_enabled
        set http_proxy_uri_rewrite $http_proxy_default_uri_rewrite
        set http_proxy_resolved $http_proxy_default_resolved
        set http_proxy_addr $http_proxy_default_addr
        set http_proxy_port $http_proxy_default_port
        set http_proxy_rtdom $http_proxy_default_rtdom
        set http_proxy_iptuple $http_proxy_default_iptuple
        if {!$http_proxy_resolved} {
            set http_proxy_addr ""
            set http_proxy_port 0
            set http_proxy_rtdom 0
            set http_proxy_iptuple ""
        } elseif {$http_proxy_iptuple eq ""} {
            set http_proxy_iptuple [list $http_proxy_addr $http_proxy_port $http_proxy_rtdom]
        }
        set http_proxy_chain_enabled $http_proxy_default_chain_enabled
        set http_proxy_chain_host $http_proxy_default_chain_host
        set http_proxy_chain_port $http_proxy_default_chain_port
        set http_proxy_chain_retry_requested 0
    }

    proc http_proxy_reset_connection {} {
        http_proxy_prepare_request
    }

    proc http_proxy_configure {args} {
        if {[llength $args] != 10} {
            error "HTTP proxy configuration requires ten values"
        }
        foreach {
            enabled uri_rewrite resolved addr port rtdom iptuple
            chain_enabled chain_host chain_port
        } $args break
        foreach field {enabled uri_rewrite resolved chain_enabled} value [list \
            $enabled $uri_rewrite $resolved $chain_enabled] {
            if {$value ni {0 1}} {
                error "HTTP proxy $field must be boolean"
            }
        }
        foreach field {port chain_port} value [list $port $chain_port] {
            if {![string is integer -strict $value] || $value < 0 || $value > 65535} {
                error "HTTP proxy $field must be between 0 and 65535"
            }
        }
        if {![string is integer -strict $rtdom] || $rtdom < 0} {
            error "HTTP proxy rtdom must be a non-negative integer"
        }
        foreach field {addr iptuple chain_host} value [list $addr $iptuple $chain_host] {
            if {[string first "\x00" $value] >= 0} {
                error "HTTP proxy $field must not contain NUL"
            }
        }
        variable http_proxy_default_enabled
        variable http_proxy_default_uri_rewrite
        variable http_proxy_default_resolved
        variable http_proxy_default_addr
        variable http_proxy_default_port
        variable http_proxy_default_rtdom
        variable http_proxy_default_iptuple
        variable http_proxy_default_chain_enabled
        variable http_proxy_default_chain_host
        variable http_proxy_default_chain_port
        set http_proxy_default_enabled $enabled
        set http_proxy_default_uri_rewrite $uri_rewrite
        set http_proxy_default_resolved $resolved
        set http_proxy_default_addr $addr
        set http_proxy_default_port $port
        set http_proxy_default_rtdom $rtdom
        set http_proxy_default_iptuple $iptuple
        set http_proxy_default_chain_enabled $chain_enabled
        set http_proxy_default_chain_host $chain_host
        set http_proxy_default_chain_port $chain_port
        http_proxy_prepare_request
    }

    proc http_proxy_snapshot {} {
        variable http_proxy_enabled
        variable http_proxy_uri_rewrite
        variable http_proxy_resolved
        variable http_proxy_addr
        variable http_proxy_port
        variable http_proxy_rtdom
        variable http_proxy_iptuple
        variable http_proxy_chain_enabled
        variable http_proxy_chain_host
        variable http_proxy_chain_port
        variable http_proxy_chain_retry_requested
        return [list \
            enabled $http_proxy_enabled \
            uri_rewrite $http_proxy_uri_rewrite \
            resolved $http_proxy_resolved \
            addr $http_proxy_addr \
            port $http_proxy_port \
            rtdom $http_proxy_rtdom \
            iptuple $http_proxy_iptuple \
            chain_enabled $http_proxy_chain_enabled \
            chain_host $http_proxy_chain_host \
            chain_port $http_proxy_chain_port \
            chain_retry_requested $http_proxy_chain_retry_requested]
    }

    proc _http_proxy_require_event {} {
        if {$::itest::current_event ni {
            HTTP_PROXY_REQUEST HTTP_REQUEST HTTP_REQUEST_DATA HTTP_RESPONSE
            HTTP_RESPONSE_DATA HTTP_PROXY_CONNECT HTTP_PROXY_RESPONSE
        }} {
            error "HTTP::proxy is not valid in $::itest::current_event"
        }
    }

    proc _http_proxy_resolved_value {value} {
        variable http_proxy_resolved
        if {!$http_proxy_resolved} { return "" }
        return $value
    }

    proc http_proxy_command {args} {
        _http_proxy_require_event
        variable http_proxy_enabled
        variable http_proxy_uri_rewrite
        variable http_proxy_resolved
        variable http_proxy_addr
        variable http_proxy_port
        variable http_proxy_rtdom
        variable http_proxy_iptuple
        variable http_proxy_chain_enabled
        variable http_proxy_chain_host
        variable http_proxy_chain_port
        variable http_proxy_chain_retry_requested
        if {[llength $args] == 0} {
            return $http_proxy_enabled
        }
        set command [lindex $args 0]
        switch -exact -- $command {
            enable - disable {
                if {[llength $args] != 1} {
                    error "HTTP::proxy $command takes no arguments"
                }
                set http_proxy_enabled [expr {$command eq "enable"}]
                ::itest::log_decision http_proxy $command
                return ""
            }
            uri-rewrite {
                if {[llength $args] != 2 || [lindex $args 1] ni {enable disable}} {
                    error "HTTP::proxy uri-rewrite requires enable or disable"
                }
                set http_proxy_uri_rewrite [expr {[lindex $args 1] eq "enable"}]
                ::itest::log_decision http_proxy uri-rewrite [lindex $args 1]
                return ""
            }
            addr - port - rtdom - iptuple {
                if {[llength $args] != 1} {
                    error "HTTP::proxy $command takes no arguments"
                }
                return [_http_proxy_resolved_value [set http_proxy_$command]]
            }
            exists {
                if {[llength $args] != 1} {
                    error "HTTP::proxy exists takes no arguments"
                }
                return $http_proxy_resolved
            }
            chain {
                if {[llength $args] == 1} {
                    return $http_proxy_chain_enabled
                }
                set chain_command [lindex $args 1]
                switch -exact -- $chain_command {
                    enable - disable {
                        if {[llength $args] != 2} {
                            error "HTTP::proxy chain $chain_command takes no arguments"
                        }
                        set http_proxy_chain_enabled [expr {$chain_command eq "enable"}]
                        ::itest::log_decision http_proxy chain $chain_command
                        return ""
                    }
                    host {
                        if {[llength $args] == 2} {
                            return $http_proxy_chain_host
                        }
                        if {[llength $args] ni {3 4}} {
                            error "HTTP::proxy chain host requires a hostname and optional port"
                        }
                        set host [lindex $args 2]
                        if {$host eq "" || [string first "\x00" $host] >= 0} {
                            error "HTTP::proxy chain host must be non-empty and contain no NUL"
                        }
                        set http_proxy_chain_host $host
                        if {[llength $args] == 4} {
                            set port [lindex $args 3]
                            if {![string is integer -strict $port] || $port < 1 || $port > 65535} {
                                error "HTTP::proxy chain host port must be between 1 and 65535"
                            }
                            set http_proxy_chain_port $port
                        }
                        ::itest::log_decision http_proxy chain_host [list $http_proxy_chain_host $http_proxy_chain_port]
                        return ""
                    }
                    port {
                        if {[llength $args] == 2} {
                            return $http_proxy_chain_port
                        }
                        if {[llength $args] != 3} {
                            error "HTTP::proxy chain port requires one port"
                        }
                        set port [lindex $args 2]
                        if {![string is integer -strict $port] || $port < 1 || $port > 65535} {
                            error "HTTP::proxy chain port must be between 1 and 65535"
                        }
                        set http_proxy_chain_port $port
                        ::itest::log_decision http_proxy chain_port $port
                        return ""
                    }
                    retry {
                        if {[llength $args] != 2} {
                            error "HTTP::proxy chain retry takes no arguments"
                        }
                        set http_proxy_chain_retry_requested 1
                        ::itest::log_decision http_proxy chain_retry
                        return ""
                    }
                    default {
                        error "unsupported HTTP::proxy chain operation $chain_command"
                    }
                }
            }
            default {
                error "unsupported HTTP::proxy operation $command"
            }
        }
    }

    proc rewrite_reset_connection {} {
        variable rewrite_default_enabled
        variable rewrite_enabled
        variable rewrite_post_process
        variable rewrite_payload_side
        variable rewrite_payload_replaced
        set rewrite_enabled $rewrite_default_enabled
        set rewrite_post_process 0
        set rewrite_payload_side ""
        set rewrite_payload_replaced 0
    }

    proc rewrite_prepare_request {} {
        variable rewrite_post_process
        variable rewrite_payload_side
        variable rewrite_payload_replaced
        set rewrite_post_process 0
        set rewrite_payload_side ""
        set rewrite_payload_replaced 0
    }

    proc rewrite_snapshot {} {
        variable rewrite_enabled
        variable rewrite_post_process
        variable rewrite_payload_side
        variable rewrite_payload_replaced
        set request_length [::itest::cmd::_payload_bytelength $::state::http::request::payload]
        set response_length [::itest::cmd::_payload_bytelength $::state::http::response::payload]
        return [list \
            enabled $rewrite_enabled \
            post_process $rewrite_post_process \
            payload_side $rewrite_payload_side \
            payload_replaced $rewrite_payload_replaced \
            request_payload_length $request_length \
            response_payload_length $response_length]
    }

    proc rewrite_flow_hook {} {
        return ""
    }

    proc rewrite_install_flow_hooks {} {
        set rewrite_events [::itest::registered_events]
        if {[lsearch -exact $rewrite_events REWRITE_REQUEST_DONE] < 0 &&
            [lsearch -exact $rewrite_events REWRITE_RESPONSE_DONE] < 0} {
            return
        }
        foreach event_name {HTTP_REQUEST HTTP_RESPONSE} {
            set handlers {}
            if {[info exists ::itest::event_handlers($event_name)]} {
                set handlers $::itest::event_handlers($event_name)
            }
            set already_installed 0
            foreach handler $handlers {
                if {[lindex $handler 1] eq "::itest::semantic::rewrite_flow_hook"} {
                    set already_installed 1
                    break
                }
            }
            if {!$already_installed} {
                lappend handlers [list 100001 ::itest::semantic::rewrite_flow_hook]
                set ::itest::event_handlers($event_name) $handlers
            }
        }
    }

    proc _rewrite_require_event {allowed command_name} {
        if {$::itest::current_event ni $allowed} {
            error "$command_name is not valid during $::itest::current_event"
        }
    }

    proc _rewrite_payload_var {} {
        if {$::itest::current_event eq "REWRITE_REQUEST_DONE"} {
            return ::state::http::request::payload
        }
        if {$::itest::current_event eq "REWRITE_RESPONSE_DONE"} {
            return ::state::http::response::payload
        }
        error "REWRITE::payload is not valid during $::itest::current_event"
    }

    proc _rewrite_adjust_content_length {var} {
        if {$var eq "::state::http::request::payload"} {
            set header_var ::state::http::request::header
        } else {
            set header_var ::state::http::response::header
        }
        set current [${header_var} get content-length]
        if {$current ne ""} {
            ${header_var} set content-length \
                [::itest::cmd::_payload_bytelength [set $var]]
        }
    }

    proc rewrite_enable_command {args} {
        variable rewrite_enabled
        _rewrite_require_event {
            ACCESS_ACL_ALLOWED HTTP_RESPONSE REWRITE_REQUEST_DONE REWRITE_RESPONSE_DONE
        } REWRITE::enable
        if {[llength $args] != 0} {
            error "REWRITE::enable takes no arguments"
        }
        set rewrite_enabled 1
        ::itest::log_decision rewrite enable
        return ""
    }

    proc rewrite_disable_command {args} {
        variable rewrite_enabled
        _rewrite_require_event {
            ACCESS_ACL_ALLOWED HTTP_RESPONSE REWRITE_REQUEST_DONE REWRITE_RESPONSE_DONE
        } REWRITE::disable
        if {[llength $args] != 0} {
            error "REWRITE::disable takes no arguments"
        }
        set rewrite_enabled 0
        ::itest::log_decision rewrite disable
        return ""
    }

    proc rewrite_post_process_command {args} {
        variable rewrite_post_process
        _rewrite_require_event {REWRITE_REQUEST_DONE} REWRITE::post_process
        if {[llength $args] == 0} {
            return $rewrite_post_process
        }
        if {[llength $args] != 1 || [lindex $args 0] ni {0 1}} {
            error "REWRITE::post_process accepts only 0 or 1"
        }
        set rewrite_post_process [lindex $args 0]
        ::itest::log_decision rewrite post_process $rewrite_post_process
        return $rewrite_post_process
    }

    proc rewrite_payload_command {args} {
        variable rewrite_payload_side
        variable rewrite_payload_replaced
        set var [_rewrite_payload_var]
        set payload [set $var]
        set payload_bytes [::itest::cmd::_payload_bytes $payload]
        if {[llength $args] == 0} {
            return $payload
        }
        if {[llength $args] == 1 && [lindex $args 0] eq "length"} {
            return [::itest::cmd::_payload_bytelength $payload]
        }
        if {[llength $args] in {1 2}} {
            foreach value $args {
                if {![string is integer -strict $value] || $value < 0} {
                    error "REWRITE::payload offsets and lengths must be non-negative integers"
                }
            }
            set offset [expr {[llength $args] == 1 ? 0 : [lindex $args 0]}]
            set length [expr {[llength $args] == 1 ? [lindex $args 0] : [lindex $args 1]}]
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
                error "REWRITE::payload replace offsets and lengths must be non-negative integers"
            }
            set $var [::itest::cmd::_payload_splice $payload $offset $length [lindex $args 3]]
            _rewrite_adjust_content_length $var
            set rewrite_payload_side [expr {$var eq "::state::http::request::payload" ? "request" : "response"}]
            set rewrite_payload_replaced 1
            ::itest::log_decision rewrite payload_replace [list $offset $length [lindex $args 3]]
            return ""
        }
        error "unsupported REWRITE::payload syntax"
    }

    proc html_reset_connection {} {
        html_prepare_request
    }

    proc html_prepare_request {} {
        variable html_enabled
        variable html_processing
        variable html_current_type
        variable html_current_name
        variable html_current_raw
        variable html_current_prepend
        variable html_current_append
        variable html_current_removed
        variable html_token_count
        variable html_mutated
        set html_enabled 0
        set html_processing 0
        set html_current_type ""
        set html_current_name ""
        set html_current_raw ""
        set html_current_prepend ""
        set html_current_append ""
        set html_current_removed 0
        set html_token_count 0
        set html_mutated 0
    }

    proc html_snapshot {} {
        variable html_enabled
        variable html_processing
        variable html_current_type
        variable html_current_name
        variable html_current_removed
        variable html_token_count
        variable html_mutated
        return [list \
            enabled $html_enabled processing $html_processing \
            current_type $html_current_type current_name $html_current_name \
            current_removed $html_current_removed token_count $html_token_count \
            mutated $html_mutated]
    }

    proc _html_require_event {allowed command_name} {
        if {$::itest::current_event ni $allowed} {
            error "$command_name is not valid during $::itest::current_event"
        }
    }

    proc html_enable_command {args} {
        variable html_enabled
        _html_require_event {HTTP_RESPONSE HTML_TAG_MATCHED HTML_COMMENT_MATCHED} HTML::enable
        if {[llength $args] != 0} {
            error "HTML::enable takes no arguments"
        }
        set html_enabled 1
        ::itest::log_decision html enable
        return ""
    }

    proc html_disable_command {args} {
        variable html_enabled
        _html_require_event {HTTP_RESPONSE HTML_TAG_MATCHED HTML_COMMENT_MATCHED} HTML::disable
        if {[llength $args] != 0} {
            error "HTML::disable takes no arguments"
        }
        set html_enabled 0
        ::itest::log_decision html disable
        return ""
    }

    proc html_encode_command {args} {
        if {[llength $args] != 1} {
            error "HTML::encode requires one string"
        }
        set value [lindex $args 0]
        set value [string map [list & {&amp;} < {&lt;} > {&gt;} \" {&quot;} ' {&#39;}] $value]
        ::itest::log_decision html encode $value
        return $value
    }

    proc _html_current_value {} {
        variable html_current_type
        variable html_current_raw
        if {$html_current_type eq "tag" || $html_current_type eq "comment"} {
            return $html_current_raw
        }
        error "HTML command is not active outside an HTML match event"
    }

    proc html_tag_command {args} {
        variable html_current_type
        variable html_current_name
        variable html_current_prepend
        variable html_current_append
        variable html_current_removed
        variable html_mutated
        _html_require_event {HTML_TAG_MATCHED} HTML::tag
        if {$html_current_type ne "tag"} {
            error "HTML::tag has no active tag"
        }
        if {[llength $args] == 0 || ([llength $args] == 1 && [lindex $args 0] eq "name")} {
            if {[llength $args] == 1} { return $html_current_name }
            error "HTML::tag requires append, name, prepend, or remove"
        }
        if {[llength $args] == 1 && [lindex $args 0] eq "remove"} {
            set html_current_removed 1
            set html_mutated 1
            ::itest::log_decision html tag_remove
            return ""
        }
        if {[llength $args] == 2 && [lindex $args 0] in {append prepend}} {
            set operation [lindex $args 0]
            if {$operation eq "append"} {
                append html_current_append [lindex $args 1]
            } else {
                append html_current_prepend [lindex $args 1]
            }
            set html_mutated 1
            ::itest::log_decision html tag_$operation [lindex $args 1]
            return ""
        }
        error "unsupported HTML::tag syntax"
    }

    proc html_comment_command {args} {
        variable html_current_type
        variable html_current_prepend
        variable html_current_append
        variable html_current_removed
        variable html_mutated
        _html_require_event {HTML_COMMENT_MATCHED} HTML::comment
        if {$html_current_type ne "comment"} {
            error "HTML::comment has no active comment"
        }
        if {[llength $args] == 0} {
            return [_html_current_value]
        }
        if {[llength $args] == 1 && [lindex $args 0] eq "remove"} {
            set html_current_removed 1
            set html_mutated 1
            ::itest::log_decision html comment_remove
            return ""
        }
        if {[llength $args] == 2 && [lindex $args 0] in {append prepend}} {
            set operation [lindex $args 0]
            if {$operation eq "append"} {
                append html_current_append [lindex $args 1]
            } else {
                append html_current_prepend [lindex $args 1]
            }
            set html_mutated 1
            ::itest::log_decision html comment_$operation [lindex $args 1]
            return ""
        }
        error "unsupported HTML::comment syntax"
    }

    proc _html_token_name {raw} {
        set content [string trim [string range $raw 1 end-1]]
        if {[string index $content 0] eq "/"} {
            set content [string range $content 1 end]
            return "/[lindex [split $content] 0]"
        }
        return [string trimright [lindex [split $content] 0] /]
    }

    proc _html_render_current {} {
        variable html_current_type
        variable html_current_raw
        variable html_current_prepend
        variable html_current_append
        variable html_current_removed
        if {$html_current_removed} { return "" }
        return "${html_current_prepend}${html_current_raw}${html_current_append}"
    }

    proc _html_fire_if_registered {event_name} {
        if {[lsearch -exact [::itest::registered_events] $event_name] < 0} {
            return ""
        }
        set result [::itest::_testcl_fire_event_orig $event_name]
        ::itest::semantic::event_errors_record $event_name $result
        return $result
    }

    proc html_process_response {} {
        variable html_enabled
        variable html_processing
        variable html_current_type
        variable html_current_name
        variable html_current_raw
        variable html_current_prepend
        variable html_current_append
        variable html_current_removed
        variable html_token_count
        if {!$html_enabled || $html_processing} { return }
        set body $::state::http::response::payload
        set cursor 0
        set output [list]
        set body_length [string length $body]
        set html_processing 1
        while {$cursor < $body_length} {
            set comment_start [string first "<!--" $body $cursor]
            set comment_end -1
            if {$comment_start >= 0} {
                set comment_end [string first "-->" $body [expr {$comment_start + 4}]]
                if {$comment_end >= 0} { set comment_end [expr {$comment_end + 3}] }
            }
            set tag_match {}
            set tag_start -1
            set tag_end -1
            if {[regexp -indices -start $cursor {<[^>]*>} $body tag_match]} {
                set tag_start [lindex $tag_match 0]
                set tag_end [expr {[lindex $tag_match 1] + 1}]
            }
            if {$comment_start >= 0 && $comment_end >= 0 &&
                ($tag_start < 0 || $comment_start <= $tag_start)} {
                set token_start $comment_start
                set token_end $comment_end
                set token_type comment
                set event_name HTML_COMMENT_MATCHED
            } elseif {$tag_start >= 0} {
                set token_start $tag_start
                set token_end $tag_end
                set token_type tag
                set event_name HTML_TAG_MATCHED
            } else {
                append output [string range $body $cursor end]
                break
            }
            append output [string range $body $cursor [expr {$token_start - 1}]]
            set html_current_type $token_type
            set html_current_raw [string range $body $token_start [expr {$token_end - 1}]]
            if {$token_type eq "tag"} {
                set html_current_name [_html_token_name $html_current_raw]
            } else {
                set html_current_name ""
            }
            set html_current_prepend ""
            set html_current_append ""
            set html_current_removed 0
            incr html_token_count
            _html_fire_if_registered $event_name
            append output [_html_render_current]
            set cursor $token_end
            if {!$html_enabled} {
                append output [string range $body $cursor end]
                break
            }
        }
        set ::state::http::response::payload $output
        set html_current_type ""
        set html_current_name ""
        set html_current_raw ""
        set html_current_prepend ""
        set html_current_append ""
        set html_current_removed 0
        set html_processing 0
        set header_value [::state::http::response::header get content-length]
        if {$header_value ne ""} {
            ::state::http::response::header set content-length \
                [::itest::cmd::_payload_bytelength $::state::http::response::payload]
        }
    }

    proc compression_reset_connection {} {
        compression_prepare_request
    }

    proc compression_prepare_request {} {
        foreach side {request response} {
            set ::itest::semantic::compress_${side}_enabled 0
            set ::itest::semantic::compress_${side}_method gzip
            set ::itest::semantic::compress_${side}_buffer_size 0
            set ::itest::semantic::compress_${side}_gzip_level 6
            set ::itest::semantic::compress_${side}_gzip_memory_level 8
            set ::itest::semantic::compress_${side}_gzip_window_size 15
            set ::itest::semantic::compress_${side}_nodelay 0
            set ::itest::semantic::decompress_${side}_enabled 0
        }
        variable compress_applied
        variable compress_applied_side
        variable compress_input_length
        variable compress_output_length
        variable decompress_applied
        variable decompress_applied_side
        variable decompress_input_length
        variable decompress_output_length
        variable compression_codec_error
        set compress_applied 0
        set compress_applied_side ""
        set compress_input_length 0
        set compress_output_length 0
        set decompress_applied 0
        set decompress_applied_side ""
        set decompress_input_length 0
        set decompress_output_length 0
        set compression_codec_error ""
    }

    proc compression_snapshot {} {
        variable compress_applied
        variable compress_applied_side
        variable compress_input_length
        variable compress_output_length
        variable decompress_applied
        variable decompress_applied_side
        variable decompress_input_length
        variable decompress_output_length
        variable compression_codec_error
        return [list \
            compress_request_enabled $::itest::semantic::compress_request_enabled \
            compress_response_enabled $::itest::semantic::compress_response_enabled \
            compress_request_method $::itest::semantic::compress_request_method \
            compress_response_method $::itest::semantic::compress_response_method \
            compress_request_buffer_size $::itest::semantic::compress_request_buffer_size \
            compress_response_buffer_size $::itest::semantic::compress_response_buffer_size \
            compress_request_gzip_level $::itest::semantic::compress_request_gzip_level \
            compress_response_gzip_level $::itest::semantic::compress_response_gzip_level \
            compress_request_gzip_memory_level $::itest::semantic::compress_request_gzip_memory_level \
            compress_response_gzip_memory_level $::itest::semantic::compress_response_gzip_memory_level \
            compress_request_gzip_window_size $::itest::semantic::compress_request_gzip_window_size \
            compress_response_gzip_window_size $::itest::semantic::compress_response_gzip_window_size \
            compress_request_nodelay $::itest::semantic::compress_request_nodelay \
            compress_response_nodelay $::itest::semantic::compress_response_nodelay \
            decompress_request_enabled $::itest::semantic::decompress_request_enabled \
            decompress_response_enabled $::itest::semantic::decompress_response_enabled \
            compress_applied $compress_applied compress_applied_side $compress_applied_side \
            compress_input_length $compress_input_length compress_output_length $compress_output_length \
            decompress_applied $decompress_applied decompress_applied_side $decompress_applied_side \
            decompress_input_length $decompress_input_length decompress_output_length $decompress_output_length \
            codec_error $compression_codec_error]
    }

    proc _compression_parse_side {args command_name} {
        set side ""
        if {[llength $args] > 0 && [lindex $args 0] in {request response}} {
            set side [lindex $args 0]
            set args [lrange $args 1 end]
        }
        if {$side eq ""} {
            set event_name $::itest::current_event
            if {[string match "*RESPONSE*" $event_name]} {
                set side response
            } elseif {[string match "*REQUEST*" $event_name] || $event_name eq "CLIENT_ACCEPTED"} {
                set side request
            } else {
                error "$command_name requires request or response outside an HTTP event"
            }
        }
        return [list $side $args]
    }

    proc _compression_require_integer {value field minimum maximum} {
        if {![string is integer -strict $value] || $value < $minimum || $value > $maximum} {
            error "$field must be an integer between $minimum and $maximum"
        }
    }

    proc compression_enable_command {args} {
        lassign [_compression_parse_side $args COMPRESS::enable] side remaining
        if {[llength $remaining] != 0} {
            error "COMPRESS::enable takes only an optional request or response side"
        }
        set ::itest::semantic::compress_${side}_enabled 1
        ::itest::log_decision compression enable $side
        return ""
    }

    proc compression_disable_command {args} {
        lassign [_compression_parse_side $args COMPRESS::disable] side remaining
        if {[llength $remaining] != 0} {
            error "COMPRESS::disable takes only an optional request or response side"
        }
        set ::itest::semantic::compress_${side}_enabled 0
        ::itest::log_decision compression disable $side
        return ""
    }

    proc decompression_enable_command {args} {
        lassign [_compression_parse_side $args DECOMPRESS::enable] side remaining
        if {[llength $remaining] != 0} {
            error "DECOMPRESS::enable takes only an optional request or response side"
        }
        set ::itest::semantic::decompress_${side}_enabled 1
        ::itest::log_decision decompression enable $side
        return ""
    }

    proc decompression_disable_command {args} {
        lassign [_compression_parse_side $args DECOMPRESS::disable] side remaining
        if {[llength $remaining] != 0} {
            error "DECOMPRESS::disable takes only an optional request or response side"
        }
        set ::itest::semantic::decompress_${side}_enabled 0
        ::itest::log_decision decompression disable $side
        return ""
    }

    proc compression_method_command {args} {
        lassign [_compression_parse_side $args COMPRESS::method] side remaining
        if {[llength $remaining] != 2 || [lindex $remaining 0] ne "prefer" ||
            [lindex $remaining 1] ni {gzip deflate}} {
            error "COMPRESS::method requires prefer gzip or prefer deflate"
        }
        set ::itest::semantic::compress_${side}_method [lindex $remaining 1]
        ::itest::log_decision compression method [list $side [lindex $remaining 1]]
        return ""
    }

    proc compression_buffer_size_command {args} {
        lassign [_compression_parse_side $args COMPRESS::buffer_size] side remaining
        if {[llength $remaining] != 1} {
            error "COMPRESS::buffer_size requires one size"
        }
        set size [lindex $remaining 0]
        _compression_require_integer $size COMPRESS::buffer_size 0 16777216
        set ::itest::semantic::compress_${side}_buffer_size $size
        ::itest::log_decision compression buffer_size [list $side $size]
        return ""
    }

    proc compression_gzip_command {args} {
        lassign [_compression_parse_side $args COMPRESS::gzip] side remaining
        if {[llength $remaining] != 2 || [lindex $remaining 0] ni {level memory_level window_size}} {
            error "COMPRESS::gzip requires level, memory_level, or window_size and a value"
        }
        set option [lindex $remaining 0]
        set value [lindex $remaining 1]
        switch -exact -- $option {
            level { _compression_require_integer $value COMPRESS::gzip_level 0 9 }
            memory_level { _compression_require_integer $value COMPRESS::gzip_memory_level 1 9 }
            window_size { _compression_require_integer $value COMPRESS::gzip_window_size 8 15 }
        }
        set ::itest::semantic::compress_${side}_gzip_${option} $value
        ::itest::log_decision compression gzip [list $side $option $value]
        return ""
    }

    proc compression_nodelay_command {args} {
        lassign [_compression_parse_side $args COMPRESS::nodelay] side remaining
        if {[llength $remaining] != 0} {
            error "COMPRESS::nodelay takes only an optional request or response side"
        }
        set ::itest::semantic::compress_${side}_nodelay 1
        ::itest::log_decision compression nodelay $side
        return ""
    }

    proc _compression_payload_var {side} {
        return ::state::http::${side}::payload
    }

    proc _compression_header_var {side} {
        return ::state::http::${side}::header
    }

    proc _compression_adjust_content_length {side} {
        set header_var [_compression_header_var $side]
        if {[${header_var} get content-length] ne ""} {
            set payload_var [_compression_payload_var $side]
            ${header_var} set content-length \
                [::itest::cmd::_payload_bytelength [set $payload_var]]
        }
    }

    proc _compression_encoding {side} {
        set header_var [_compression_header_var $side]
        set value [string tolower [string trim [${header_var} get content-encoding]]]
        if {$value eq ""} { return "" }
        return [string trim [lindex [split $value ,] 0]]
    }

    proc compression_process_decompress {side} {
        variable decompress_applied
        variable decompress_applied_side
        variable decompress_input_length
        variable decompress_output_length
        variable compression_codec_error
        if {![set ::itest::semantic::decompress_${side}_enabled]} { return }
        set encoding [_compression_encoding $side]
        if {$encoding ni {gzip x-gzip deflate}} { return }
        set method [expr {$encoding eq "deflate" ? "deflate" : "gzip"}]
        set payload_var [_compression_payload_var $side]
        set payload [set $payload_var]
        set input_length [::itest::cmd::_payload_bytelength $payload]
        if {$input_length == 0} { return }
        set encoded [binary encode base64 [::itest::cmd::_payload_bytes $payload]]
        if {[catch {
            set result [::itest::semantic::py_codec decompress $method 6 8 15 $encoded]
            set $payload_var [binary decode base64 $result]
        } error]} {
            set compression_codec_error "${side} decompression failed: $error"
            ::itest::log_decision compression error $compression_codec_error
            return
        }
        set header_var [_compression_header_var $side]
        ${header_var} remove content-encoding
        _compression_adjust_content_length $side
        set decompress_applied 1
        set decompress_applied_side $side
        set decompress_input_length $input_length
        set decompress_output_length [::itest::cmd::_payload_bytelength [set $payload_var]]
        ::itest::log_decision decompression applied [list $side $method]
    }

    proc compression_process_compress {side} {
        variable compress_applied
        variable compress_applied_side
        variable compress_input_length
        variable compress_output_length
        variable compression_codec_error
        if {![set ::itest::semantic::compress_${side}_enabled]} { return }
        if {$side eq "response" && [info exists ::state::http::response::status]} {
            set status $::state::http::response::status
            if {[string is integer -strict $status] &&
                ($status < 200 || $status in {204 304})} { return }
        }
        if {[_compression_encoding $side] ne ""} { return }
        set payload_var [_compression_payload_var $side]
        set payload [set $payload_var]
        set input_length [::itest::cmd::_payload_bytelength $payload]
        if {$input_length == 0} { return }
        set method [set ::itest::semantic::compress_${side}_method]
        set level [set ::itest::semantic::compress_${side}_gzip_level]
        set memory_level [set ::itest::semantic::compress_${side}_gzip_memory_level]
        set window_size [set ::itest::semantic::compress_${side}_gzip_window_size]
        set encoded [binary encode base64 [::itest::cmd::_payload_bytes $payload]]
        if {[catch {
            set result [::itest::semantic::py_codec compress $method $level $memory_level $window_size $encoded]
            set $payload_var [binary decode base64 $result]
        } error]} {
            set compression_codec_error "${side} compression failed: $error"
            ::itest::log_decision compression error $compression_codec_error
            return
        }
        set header_var [_compression_header_var $side]
        ${header_var} set content-encoding $method
        _compression_adjust_content_length $side
        set compress_applied 1
        set compress_applied_side $side
        set compress_input_length $input_length
        set compress_output_length [::itest::cmd::_payload_bytelength [set $payload_var]]
        ::itest::log_decision compression applied [list $side $method]
    }

    proc compression_process_request {} {
        compression_process_decompress request
        compression_process_compress request
    }

    proc compression_process_response {} {
        compression_process_decompress response
        compression_process_compress response
    }

    proc httplog_reset_connection {} {
        variable httplog_enabled
        set httplog_enabled 0
        httplog_prepare_request
    }

    proc httplog_prepare_request {} {
        variable httplog_records
        set httplog_records {}
    }

    proc httplog_enable_command {args} {
        variable httplog_enabled
        if {[llength $args] != 0} {
            error "HTTPLOG::enable takes no arguments"
        }
        set httplog_enabled 1
        ::itest::log_decision httplog enable
        return ""
    }

    proc httplog_disable_command {args} {
        variable httplog_enabled
        if {[llength $args] != 0} {
            error "HTTPLOG::disable takes no arguments"
        }
        set httplog_enabled 0
        ::itest::log_decision httplog disable
        return ""
    }

    proc httplog_record {phase} {
        variable httplog_enabled
        variable httplog_records
        if {!$httplog_enabled || $phase ni {request response}} { return }
        if {$phase eq "request"} {
            set method $::state::http::request::method
            set uri $::state::http::request::uri
            set host $::state::http::request::host
            set status ""
            set bytes [::itest::cmd::_payload_bytelength $::state::http::request::payload]
            set headers $::state::http::request::headers
        } else {
            set method $::state::http::request::method
            set uri $::state::http::request::uri
            set host $::state::http::request::host
            set status $::state::http::response::status
            set bytes [::itest::cmd::_payload_bytelength $::state::http::response::payload]
            set headers $::state::http::response::headers
        }
        lappend httplog_records [list \
            phase $phase method $method uri $uri host $host status $status \
            bytes $bytes headers $headers]
    }

    proc httplog_record_if_missing {phase} {
        variable httplog_records
        if {$phase ni {request response}} {
            error "invalid HTTPLOG record phase"
        }
        foreach record $httplog_records {
            if {[lindex $record 1] eq $phase} {
                return
            }
        }
        httplog_record $phase
    }

    proc httplog_snapshot {} {
        variable httplog_enabled
        variable httplog_records
        return [list enabled $httplog_enabled records $httplog_records]
    }

    proc psm_reset_connection {} {
        variable psm_enabled
        foreach protocol {FTP HTTP SMTP} {
            set psm_enabled($protocol) 1
        }
    }

    proc psm_snapshot {} {
        variable psm_enabled
        return [list FTP $psm_enabled(FTP) HTTP $psm_enabled(HTTP) SMTP $psm_enabled(SMTP)]
    }

    proc psm_control_command {protocol enabled args} {
        variable psm_enabled
        if {[llength $args] != 0} {
            error "PSM::$protocol takes no arguments"
        }
        if {![info exists psm_enabled($protocol)]} {
            error "unsupported PSM protocol $protocol"
        }
        set psm_enabled($protocol) $enabled
        set action [expr {$enabled ? "enable" : "disable"}]
        ::itest::log_decision psm [string tolower $protocol] $action
        return ""
    }

    proc psm_ftp_disable {args} { return [psm_control_command FTP 0 {*}$args] }
    proc psm_ftp_enable {args} { return [psm_control_command FTP 1 {*}$args] }
    proc psm_http_disable {args} { return [psm_control_command HTTP 0 {*}$args] }
    proc psm_http_enable {args} { return [psm_control_command HTTP 1 {*}$args] }
    proc psm_smtp_disable {args} { return [psm_control_command SMTP 0 {*}$args] }
    proc psm_smtp_enable {args} { return [psm_control_command SMTP 1 {*}$args] }

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
            variable payload_ivs ""
            variable payload_processing enable
        }
    }

    proc mqtt_reset_connection {} {
        variable mqtt_enabled
        variable mqtt_collection_requested
        variable mqtt_collection_length
        variable mqtt_release_requested
        variable mqtt_dropped
        variable mqtt_disconnect_requested
        variable mqtt_response_requested
        variable mqtt_response_message
        variable mqtt_insertions
        variable mqtt_operations
        variable mqtt_message_replaced
        set mqtt_enabled 1
        set mqtt_collection_requested 0
        set mqtt_collection_length 0
        set mqtt_release_requested 0
        set mqtt_dropped 0
        set mqtt_disconnect_requested 0
        set mqtt_response_requested 0
        set mqtt_response_message {}
        set mqtt_insertions {}
        set mqtt_operations {}
        set mqtt_message_replaced 0
        namespace eval ::state::mqtt {
            variable type ""
            variable protocol_name "MQTT"
            variable protocol_version 4
            variable client_id ""
            variable clean_session 1
            variable keep_alive 60
            variable username ""
            variable password ""
            variable username_flag 0
            variable password_flag 0
            variable will_topic ""
            variable will_message ""
            variable will_qos 0
            variable will_retain 0
            variable will_flag 0
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
        variable mqtt_response_requested
        variable mqtt_response_message
        variable mqtt_insertions
        variable mqtt_operations
        variable mqtt_message_replaced
        set mqtt_release_requested 0
        set mqtt_dropped 0
        set mqtt_disconnect_requested 0
        set mqtt_response_requested 0
        set mqtt_response_message {}
        set mqtt_insertions {}
        set mqtt_operations {}
        set mqtt_message_replaced 0
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
        variable mqtt_response_requested
        variable mqtt_message_replaced
        return [list dropped $mqtt_dropped disconnect $mqtt_disconnect_requested responded $mqtt_response_requested replaced $mqtt_message_replaced]
    }

    proc mqtt_emissions_snapshot {} {
        variable mqtt_operations
        return [list operations $mqtt_operations]
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

    proc ws_payload_ivs_command {args} {
        if {[llength $args] != 1 || [lindex $args 0] eq "" ||
            [string first "\x00" [lindex $args 0]] >= 0} {
            error "WS::payload_ivs requires one non-empty IVS name without NUL bytes"
        }
        set ::state::websocket::payload_ivs [lindex $args 0]
        ::itest::log_decision ws payload_ivs $::state::websocket::payload_ivs
        return ""
    }

    proc ws_payload_processing_command {args} {
        if {[llength $args] != 1 || [lindex $args 0] ni {enable disable}} {
            error "WS::payload_processing requires enable or disable"
        }
        set ::state::websocket::payload_processing [lindex $args 0]
        ::itest::log_decision ws payload_processing $::state::websocket::payload_processing
        return ""
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

    proc mqtt_validate_integer {value field minimum maximum} {
        if {![string is integer -strict $value] || $value < $minimum || $value > $maximum} {
            error "$field must be between $minimum and $maximum"
        }
        return $value
    }

    proc mqtt_validate_boolean {value field} {
        if {$value ni {0 1 true false}} {
            error "$field must be 0 or 1"
        }
        return [expr {$value in {1 true}}]
    }

    proc mqtt_dict_get_default {mapping key default} {
        if {[dict exists $mapping $key]} {
            return [dict get $mapping $key]
        }
        return $default
    }

    proc mqtt_validate_topic_list {value type} {
        if {[catch {llength $value}]} {
            error "MQTT $type topic_list must be a Tcl list"
        }
        if {[llength $value] == 0} {
            error "MQTT $type topic_list must not be empty"
        }
        set result {}
        foreach item $value {
            set item_length [llength $item]
            if {$item_length < 1 || ($type eq "SUBSCRIBE" && $item_length != 2) || ($type eq "UNSUBSCRIBE" && $item_length > 2)} {
                error "MQTT $type topic_list entries have an invalid format"
            }
            set topic [lindex $item 0]
            if {$topic eq ""} {
                error "MQTT $type topic_list topics must not be empty"
            }
            if {$type eq "SUBSCRIBE"} {
                set qos [mqtt_validate_integer [lindex $item 1] "MQTT $type topic QoS" 0 2]
                lappend result [list $topic $qos]
            } else {
                lappend result [list $topic]
            }
        }
        return $result
    }

    proc mqtt_parse_message {args} {
        if {[llength $args] < 2 || [lindex $args 0] ne "type"} {
            error "MQTT message requires type and its value"
        }
        set type [string toupper [lindex $args 1]]
        set valid_types {CONNECT CONNACK PUBLISH PUBACK PUBREC PUBREL PUBCOMP SUBSCRIBE SUBACK UNSUBSCRIBE UNSUBACK PINGREQ PINGRESP DISCONNECT}
        if {$type ni $valid_types} {
            error "unsupported MQTT message type $type"
        }
        set rest [lrange $args 2 end]
        if {[llength $rest] % 2} {
            error "MQTT $type arguments must be field/value pairs"
        }
        set parsed [dict create type $type]
        foreach {field value} $rest {
            if {[dict exists $parsed $field]} {
                error "MQTT $type field $field was specified more than once"
            }
            dict set parsed $field $value
        }
        set supplied_fields [dict keys $parsed]
        switch -exact -- $type {
            CONNECT {
                set allowed {client_id keep_alive clean_session protocol_name protocol_version username password will_topic will_message will_qos will_retain}
                if {![dict exists $parsed client_id]} { error "MQTT CONNECT requires client_id" }
                set has_will [expr {
                    [lsearch -exact $supplied_fields will_topic] >= 0 ||
                    [lsearch -exact $supplied_fields will_message] >= 0 ||
                    [lsearch -exact $supplied_fields will_qos] >= 0 ||
                    [lsearch -exact $supplied_fields will_retain] >= 0
                }]
                dict set parsed keep_alive [mqtt_validate_integer [mqtt_dict_get_default $parsed keep_alive 60] "MQTT CONNECT keep_alive" 0 65535]
                dict set parsed clean_session [mqtt_validate_boolean [mqtt_dict_get_default $parsed clean_session 1] "MQTT CONNECT clean_session"]
                dict set parsed protocol_name [mqtt_dict_get_default $parsed protocol_name MQTT]
                dict set parsed protocol_version [mqtt_validate_integer [mqtt_dict_get_default $parsed protocol_version 4] "MQTT CONNECT protocol_version" 0 255]
                dict set parsed username [mqtt_dict_get_default $parsed username ""]
                dict set parsed password [mqtt_dict_get_default $parsed password ""]
                dict set parsed username_flag [expr {[lsearch -exact $supplied_fields username] >= 0}]
                dict set parsed password_flag [expr {[lsearch -exact $supplied_fields password] >= 0}]
                if {[dict get $parsed password_flag] && ![dict get $parsed username_flag]} {
                    error "MQTT CONNECT password requires username"
                }
                dict set parsed will_topic [mqtt_dict_get_default $parsed will_topic ""]
                dict set parsed will_message [mqtt_dict_get_default $parsed will_message ""]
                dict set parsed will_qos [mqtt_validate_integer [mqtt_dict_get_default $parsed will_qos 0] "MQTT CONNECT will_qos" 0 2]
                dict set parsed will_retain [mqtt_validate_boolean [mqtt_dict_get_default $parsed will_retain 0] "MQTT CONNECT will_retain"]
                dict set parsed will_flag $has_will
            }
            CONNACK {
                set allowed {return_code session_present}
                if {![dict exists $parsed return_code]} { error "MQTT CONNACK requires return_code" }
                dict set parsed return_code [mqtt_validate_integer [dict get $parsed return_code] "MQTT CONNACK return_code" 0 5]
                dict set parsed session_present [mqtt_validate_boolean [mqtt_dict_get_default $parsed session_present 0] "MQTT CONNACK session_present"]
            }
            PUBLISH {
                set allowed {topic payload qos packet_id dup retain}
                foreach required {topic payload} { if {![dict exists $parsed $required]} { error "MQTT PUBLISH requires $required" } }
                if {[dict get $parsed topic] eq ""} { error "MQTT PUBLISH topic must not be empty" }
                dict set parsed qos [mqtt_validate_integer [mqtt_dict_get_default $parsed qos 0] "MQTT PUBLISH qos" 0 2]
                dict set parsed dup [mqtt_validate_boolean [mqtt_dict_get_default $parsed dup 0] "MQTT PUBLISH dup"]
                dict set parsed retain [mqtt_validate_boolean [mqtt_dict_get_default $parsed retain 0] "MQTT PUBLISH retain"]
                if {[dict get $parsed qos] > 0} {
                    if {![dict exists $parsed packet_id]} { error "MQTT PUBLISH QoS 1 or 2 requires packet_id" }
                    dict set parsed packet_id [mqtt_validate_integer [dict get $parsed packet_id] "MQTT PUBLISH packet_id" 1 65535]
                } elseif {[dict exists $parsed packet_id]} {
                    error "MQTT PUBLISH QoS 0 must not specify packet_id"
                }
            }
            PUBACK - PUBREC - PUBREL - PUBCOMP - UNSUBACK {
                set allowed {packet_id}
                if {[llength $rest] != 2 || ![dict exists $parsed packet_id]} { error "MQTT $type requires packet_id" }
                dict set parsed packet_id [mqtt_validate_integer [dict get $parsed packet_id] "MQTT $type packet_id" 1 65535]
            }
            SUBSCRIBE - UNSUBSCRIBE {
                set allowed {packet_id topic_list}
                foreach required {packet_id topic_list} { if {![dict exists $parsed $required]} { error "MQTT $type requires $required" } }
                dict set parsed packet_id [mqtt_validate_integer [dict get $parsed packet_id] "MQTT $type packet_id" 1 65535]
                dict set parsed topic_list [mqtt_validate_topic_list [dict get $parsed topic_list] $type]
            }
            SUBACK {
                set allowed {packet_id return_code_list}
                foreach required {packet_id return_code_list} { if {![dict exists $parsed $required]} { error "MQTT SUBACK requires $required" } }
                dict set parsed packet_id [mqtt_validate_integer [dict get $parsed packet_id] "MQTT SUBACK packet_id" 1 65535]
                set codes [dict get $parsed return_code_list]
                if {[catch {llength $codes}] || [llength $codes] == 0} { error "MQTT SUBACK return_code_list must not be empty" }
                set normalized_codes {}
                foreach code $codes {
                    if {$code ni {0 1 2 128}} { error "MQTT SUBACK return codes must be 0, 1, 2, or 128" }
                    lappend normalized_codes $code
                }
                dict set parsed return_code_list $normalized_codes
            }
            PINGREQ - PINGRESP - DISCONNECT {
                set allowed {}
            }
        }
        foreach field $supplied_fields {
            if {$field ni [concat {type} $allowed]} {
                error "MQTT $type does not accept field $field"
            }
        }
        return $parsed
    }

    proc mqtt_apply_message {parsed} {
        foreach {field value} {
            type "" protocol_name MQTT protocol_version 4 client_id "" clean_session 1 keep_alive 60 username "" password ""
            will_topic "" will_message "" will_qos 0 will_retain 0 will_flag 0 username_flag 0 password_flag 0 packet_id 0 qos 0 dup 0 retain 0 topic ""
            payload "" payload_length 0 message "" message_length 0 return_code 0 return_code_list {} session_present 0 topic_list {}
        } {
            set ::state::mqtt::$field $value
        }
        foreach {field value} $parsed {
            set ::state::mqtt::$field $value
        }
        set ::state::mqtt::payload_length [string bytelength $::state::mqtt::payload]
        set ::itest::semantic::mqtt_message_replaced 1
        ::itest::log_decision mqtt replace $::state::mqtt::type
        return ""
    }

    proc mqtt_will_command {args} {
        _mqtt_require_event {MQTT_CLIENT_INGRESS MQTT_SERVER_INGRESS MQTT_CLIENT_DATA MQTT_SERVER_DATA} MQTT::will
        if {$::state::mqtt::type ne "CONNECT"} { error "MQTT::will is valid only for CONNECT messages" }
        if {[llength $args] < 1 || [llength $args] > 2} { error "MQTT::will requires a field and optional value" }
        set field [lindex $args 0]
        if {$field ni {topic message qos retain}} { error "unsupported MQTT::will field $field" }
        set state_field will_$field
        if {[llength $args] == 1} { return [set ::state::mqtt::$state_field] }
        set value [lindex $args 1]
        switch -exact -- $field {
            qos { set value [mqtt_validate_integer $value "MQTT::will qos" 0 2] }
            retain { set value [mqtt_validate_boolean $value "MQTT::will retain"] }
        }
        set ::state::mqtt::$state_field $value
        set ::state::mqtt::will_flag 1
        ::itest::log_decision mqtt will_$field $value
        return $value
    }

    proc mqtt_insert_command {args} {
        variable mqtt_insertions
        variable mqtt_operations
        _mqtt_require_event {MQTT_CLIENT_INGRESS MQTT_SERVER_INGRESS MQTT_CLIENT_DATA MQTT_SERVER_DATA} MQTT::insert
        if {[llength $args] < 3} { error "MQTT::insert requires before/after and a message" }
        set position [lindex $args 0]
        if {$position ni {before after}} { error "MQTT::insert position must be before or after" }
        set parsed [mqtt_parse_message {*}[lrange $args 1 end]]
        lappend mqtt_insertions [list $position $parsed]
        lappend mqtt_operations [list insert $position $parsed]
        ::itest::log_decision mqtt insert [list $position [dict get $parsed type]]
        return ""
    }

    proc mqtt_replace_command {args} {
        _mqtt_require_event {MQTT_CLIENT_INGRESS MQTT_SERVER_INGRESS MQTT_CLIENT_DATA MQTT_SERVER_DATA} MQTT::replace
        mqtt_apply_message [mqtt_parse_message {*}$args]
        return ""
    }

    proc mqtt_respond_command {args} {
        variable mqtt_response_requested
        variable mqtt_response_message
        variable mqtt_operations
        _mqtt_require_event {MQTT_CLIENT_INGRESS MQTT_SERVER_INGRESS MQTT_CLIENT_DATA MQTT_SERVER_DATA} MQTT::respond
        set mqtt_response_message [mqtt_parse_message {*}$args]
        set mqtt_response_requested 1
        lappend mqtt_operations [list response $mqtt_response_message]
        ::itest::log_decision mqtt respond [dict get $mqtt_response_message type]
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

    proc lb_reset_connection {} {
        variable lb_bias
        variable lb_class
        variable lb_command
        variable lb_context_id
        variable lb_dst_tag
        variable lb_src_tag
        variable lb_decisionlog_enabled
        variable lb_connect_requested
        variable lb_prime_requested
        variable lb_connlimits
        variable lb_queue_on
        variable lb_queue_queued
        variable lb_queue_depth
        variable lb_queue_limit_depth
        variable lb_queue_limit_time
        variable lb_queue_age_head
        variable lb_queue_age_max
        variable lb_queue_age_edm
        variable lb_queue_age_ema
        set lb_bias 0
        set lb_class ""
        set lb_command ""
        set lb_context_id ""
        set lb_dst_tag ""
        set lb_src_tag ""
        set lb_decisionlog_enabled 0
        set lb_connect_requested 0
        set lb_prime_requested 0
        set lb_connlimits [dict create]
        set lb_queue_on 0
        set lb_queue_queued 0
        set lb_queue_depth 0
        set lb_queue_limit_depth 0
        set lb_queue_limit_time 0
        set lb_queue_age_head 0
        set lb_queue_age_max 0
        set lb_queue_age_edm 0
        set lb_queue_age_ema 0
    }

    proc lb_control_snapshot {} {
        variable lb_bias
        variable lb_class
        variable lb_command
        variable lb_context_id
        variable lb_dst_tag
        variable lb_src_tag
        variable lb_decisionlog_enabled
        variable lb_connect_requested
        variable lb_prime_requested
        variable lb_connlimits
        variable lb_queue_on
        variable lb_queue_queued
        variable lb_queue_depth
        variable lb_queue_limit_depth
        variable lb_queue_limit_time
        variable lb_queue_age_head
        variable lb_queue_age_max
        variable lb_queue_age_edm
        variable lb_queue_age_ema
        return [list \
            bias $lb_bias class $lb_class command $lb_command \
            context_id $lb_context_id dst_tag $lb_dst_tag src_tag $lb_src_tag \
            decisionlog_enabled $lb_decisionlog_enabled \
            connect_requested $lb_connect_requested prime_requested $lb_prime_requested \
            connlimits $lb_connlimits queue_on $lb_queue_on \
            queue_queued $lb_queue_queued queue_depth $lb_queue_depth \
            queue_limit_depth $lb_queue_limit_depth queue_limit_time $lb_queue_limit_time \
            queue_age_head $lb_queue_age_head queue_age_max $lb_queue_age_max \
            queue_age_edm $lb_queue_age_edm queue_age_ema $lb_queue_age_ema]
    }

    proc lb_bias_command {args} {
        variable lb_bias
        if {[llength $args] == 0} { return $lb_bias }
        if {[llength $args] != 1 || ![string is integer -strict [lindex $args 0]]} {
            error "LB::bias accepts an optional integer"
        }
        set lb_bias [lindex $args 0]
        ::itest::log_decision lb bias $lb_bias
        return ""
    }

    proc lb_class_command {args} {
        variable lb_class
        if {[llength $args] != 0} { error "LB::class takes no arguments" }
        if {[info exists ::state::lb::traffic_class]} {
            return $::state::lb::traffic_class
        }
        return $lb_class
    }

    proc lb_command_command {args} {
        variable lb_command
        if {[llength $args] == 0} { return $lb_command }
        if {[llength $args] != 1 || [lindex $args 0] ne "transparent_port"} {
            error "LB::command accepts transparent_port"
        }
        set lb_command transparent_port
        ::itest::log_decision lb command $args
        return ""
    }

    proc lb_connect_command {args} {
        variable lb_connect_requested
        if {[llength $args] != 0} { error "LB::connect takes no arguments" }
        set lb_connect_requested 1
        if {$::state::lb::pool ne "" && !$::state::lb::selected} {
            _select_available_member $::state::lb::pool
        }
        ::itest::log_decision lb connect
        return ""
    }

    proc lb_connlimit_command {args} {
        variable lb_connlimits
        if {[llength $args] < 1} {
            error "LB::connlimit requires virtual, node, or poolmember"
        }
        set target [string tolower [lindex $args 0]]
        if {$target ni {virtual node poolmember}} {
            error "LB::connlimit target must be virtual, node, or poolmember"
        }
        if {![dict exists $lb_connlimits $target]} {
            dict set lb_connlimits $target [list limit unlimited key ""]
        }
        if {[llength $args] == 1} {
            return [dict get $lb_connlimits $target]
        }
        set record [dict get $lb_connlimits $target]
        set remaining [lrange $args 1 end]
        if {[llength $remaining] % 2} {
            error "LB::connlimit options require limit/key pairs"
        }
        foreach {option value} $remaining {
            switch -exact -- [string tolower $option] {
                limit {
                    if {$value ne "unlimited" &&
                        (![string is integer -strict $value] || $value < 0)} {
                        error "LB::connlimit limit must be unlimited or non-negative"
                    }
                    dict set record limit $value
                }
                key { dict set record key $value }
                default { error "unsupported LB::connlimit option $option" }
            }
        }
        dict set lb_connlimits $target $record
        ::itest::log_decision lb connlimit [list $target $record]
        return ""
    }

    proc lb_context_id_command {args} {
        variable lb_context_id
        if {[llength $args] != 1} { error "LB::context_id requires an id" }
        set lb_context_id [lindex $args 0]
        ::itest::log_decision lb context_id $lb_context_id
        return ""
    }

    proc lb_dst_tag_command {args} {
        variable lb_dst_tag
        if {[llength $args] != 1} { error "LB::dst_tag requires a tag" }
        set lb_dst_tag [lindex $args 0]
        ::itest::log_decision lb dst_tag $lb_dst_tag
        return ""
    }

    proc lb_enable_decisionlog_command {args} {
        variable lb_decisionlog_enabled
        if {[llength $args] != 0} { error "LB::enable_decisionlog takes no arguments" }
        set lb_decisionlog_enabled 1
        ::itest::log_decision lb enable_decisionlog
        return ""
    }

    proc lb_mode_command {args} {
        if {[llength $args] == 0} { return $::state::lb::lb_mode }
        if {[llength $args] != 1} { error "LB::mode requires a mode" }
        set mode [string tolower [lindex $args 0]]
        if {$mode ni {
            default rr roundrobin leastconns nodeleastconns fastest predictive
            observed ratio noderatio dynratio dynratiombr
        }} {
            error "unsupported LB::mode $mode"
        }
        set ::state::lb::lb_mode $mode
        ::itest::log_decision lb mode $mode
        return ""
    }

    proc lb_prime_command {args} {
        variable lb_prime_requested
        if {[llength $args] > 1} { error "LB::prime accepts an optional pool" }
        if {[llength $args] == 1} {
            set ::state::lb::pool [lindex $args 0]
        }
        set lb_prime_requested 1
        if {$::state::lb::pool ne "" && !$::state::lb::selected} {
            _select_available_member $::state::lb::pool
        }
        ::itest::log_decision lb prime $args
        return ""
    }

    proc lb_queue_command {args} {
        variable lb_queue_on
        variable lb_queue_queued
        variable lb_queue_depth
        variable lb_queue_limit_depth
        variable lb_queue_limit_time
        variable lb_queue_age_head
        variable lb_queue_age_max
        variable lb_queue_age_edm
        variable lb_queue_age_ema
        if {[llength $args] == 1 && [lindex $args 0] eq "queued"} {
            return $lb_queue_queued
        }
        if {[llength $args] >= 2 && [lindex $args 0] eq "on" &&
            [lindex $args 1] eq "connlimit"} {
            if {[llength $args] > 3} {
                error "LB::queue on connlimit accepts an optional pool"
            }
            return [expr {$lb_queue_on ? "enabled" : "disabled"}]
        }
        if {[llength $args] >= 2 && [lindex $args 0] eq "limit"} {
            if {[llength $args] < 2 || [llength $args] > 3} {
                error "LB::queue limit accepts depth/time and an optional pool"
            }
            set kind [string tolower [lindex $args 1]]
            if {$kind eq "depth"} { return $lb_queue_limit_depth }
            if {$kind eq "time"} { return $lb_queue_limit_time }
            error "LB::queue limit requires depth or time"
        }
        if {[llength $args] >= 2 && [lindex $args 0] eq "depth"} {
            if {[llength $args] < 2 || [llength $args] > 5} {
                error "LB::queue depth accepts a kind, pool, and optional member"
            }
            set kind [string tolower [lindex $args 1]]
            if {$kind in {all one}} { return $lb_queue_depth }
            error "LB::queue depth requires all or one"
        }
        if {[llength $args] >= 2 && [lindex $args 0] eq "age"} {
            if {[llength $args] < 2 || [llength $args] > 5} {
                error "LB::queue age accepts a kind, pool, and optional member"
            }
            switch -exact -- [string tolower [lindex $args 1]] {
                head { return $lb_queue_age_head }
                max { return $lb_queue_age_max }
                edm { return $lb_queue_age_edm }
                ema { return $lb_queue_age_ema }
                default { error "LB::queue age requires head, max, edm, or ema" }
            }
        }
        error "unsupported LB::queue query"
    }

    proc lb_snat_command {args} {
        if {[llength $args] != 0} { error "LB::snat takes no arguments" }
        set kind $::state::lb::snat_type
        if {$kind eq "" || $kind eq "none"} { return "none" }
        if {$kind eq "automap"} { return "automap" }
        if {$kind eq "snatpool"} { return [list snatpool] }
        if {$kind eq "explicit"} {
            set result [list snat $::state::lb::snat_addr]
            if {$::state::lb::snat_port ne "" && $::state::lb::snat_port != 0} {
                lappend result $::state::lb::snat_port
            }
            return $result
        }
        return $kind
    }

    proc lb_src_tag_command {args} {
        variable lb_src_tag
        if {[llength $args] != 1} { error "LB::src_tag requires a tag" }
        set lb_src_tag [lindex $args 0]
        ::itest::log_decision lb src_tag $lb_src_tag
        return ""
    }

    proc _flow_require_profile {command} {
        if {![_profile_enabled FLOW]} {
            error "$command requires the FLOW profile"
        }
    }

    proc _flow_require_event {command {priority_only 0}} {
        set allowed {
            FLOW_INIT CLIENT_ACCEPTED SA_PICKED LB_SELECTED CLIENT_DATA
            SERVER_DATA SERVER_CONNECTED
        }
        if {$priority_only} {
            set allowed {FLOW_INIT CLIENT_ACCEPTED SERVER_CONNECTED}
        }
        if {$::itest::current_event ni $allowed} {
            error "$command is not valid in $::itest::current_event"
        }
    }

    proc _flow_current_handle {} {
        variable flow_current_side
        if {$flow_current_side eq "server"} {
            return flow-server-0
        }
        return flow-client-0
    }

    proc _flow_get {handle command} {
        variable flow_handles
        if {$handle eq "" || ![dict exists $flow_handles $handle]} {
            error "$command received an unknown flow handle"
        }
        set flow [dict get $flow_handles $handle]
        if {![dict get $flow active]} {
            error "$command received an inactive flow handle"
        }
        return $flow
    }

    proc flow_reset_connection {} {
        variable flow_clock
        variable flow_current_side
        variable flow_next_related
        variable flow_handles
        set flow_clock 0
        set flow_current_side client
        set flow_next_related 0
        set flow_handles [dict create \
            flow-client-0 [dict create side client peer flow-server-0 \
                timeout 300 priority 0 last_used 0 active 1 related 0 \
                protocol 6 local_addr "" local_port "" remote_addr "" \
                remote_port "" vlan "" translation_loose 0 hairpin 0 inherit_vs ""] \
            flow-server-0 [dict create side server peer flow-client-0 \
                timeout 300 priority 0 last_used 0 active 1 related 0 \
                protocol 6 local_addr "" local_port "" remote_addr "" \
                remote_port "" vlan "" translation_loose 0 hairpin 0 inherit_vs ""]]
    }

    proc flow_begin_event {event} {
        variable flow_clock
        variable flow_current_side
        variable flow_handles
        if {$event in {SERVER_DATA SERVER_CONNECTED}} {
            set flow_current_side server
        } elseif {$event in {
            FLOW_INIT CLIENT_ACCEPTED SA_PICKED LB_SELECTED CLIENT_DATA
        }} {
            set flow_current_side client
        } else {
            return
        }
        incr flow_clock
        set handle [_flow_current_handle]
        if {[dict exists $flow_handles $handle]} {
            set flow [dict get $flow_handles $handle]
            dict set flow last_used $flow_clock
            dict set flow_handles $handle $flow
        }
    }

    proc _flow_parse_spec {tokens label} {
        set local_addr ""
        set local_port ""
        set positional [list]
        set seen_options [dict create]
        set index 0
        while {$index < [llength $tokens]} {
            set token [lindex $tokens $index]
            if {$token eq "-local-ip" || $token eq "-local-port"} {
                if {$index + 1 >= [llength $tokens]} {
                    error "$label $token requires a value"
                }
                if {[dict exists $seen_options $token]} {
                    error "$label received duplicate option $token"
                }
                dict set seen_options $token 1
                incr index
                set value [lindex $tokens $index]
                if {$value eq ""} { error "$label $token cannot be empty" }
                if {$token eq "-local-ip"} {
                    set local_addr $value
                } else {
                    if {![string is integer -strict $value] || $value < 0 || $value > 65535} {
                        error "$label -local-port must be an integer from 0 to 65535"
                    }
                    set local_port $value
                }
            } elseif {[string match -* $token]} {
                error "$label received unsupported option $token"
            } else {
                lappend positional $token
            }
            incr index
        }
        if {[llength $positional] != 3} {
            error "$label requires REMOTE_ADDR REMOTE_PORT VLAN"
        }
        if {[lindex $positional 0] eq "" || [lindex $positional 2] eq ""} {
            error "$label REMOTE_ADDR and VLAN cannot be empty"
        }
        set remote_port [lindex $positional 1]
        if {![string is integer -strict $remote_port] || $remote_port < 0 || $remote_port > 65535} {
            error "$label REMOTE_PORT must be an integer from 0 to 65535"
        }
        return [dict create local_addr $local_addr local_port $local_port \
            remote_addr [lindex $positional 0] remote_port $remote_port \
            vlan [lindex $positional 2]]
    }

    proc flow_create_related {args} {
        variable flow_handles
        variable flow_next_related
        variable flow_clock
        _flow_require_profile FLOW::create_related
        _flow_require_event FLOW::create_related
        if {[llength $args] < 1} {
            error "FLOW::create_related requires a flow specification"
        }
        set translation_loose 0
        set hairpin 0
        set raw ""
        foreach argument $args {
            if {$argument eq "-translation-loose"} {
                set translation_loose 1
            } elseif {$argument eq "-hairpin"} {
                set hairpin 1
            } elseif {$raw eq ""} {
                set raw $argument
            } else {
                error "FLOW::create_related accepts one flow specification"
            }
        }
        if {$raw eq ""} { error "FLOW::create_related requires a flow specification" }
        set tokens $raw
        set protocol 6
        set inherit_vs ""
        set client_spec ""
        set server_spec ""
        set seen [dict create]
        set index 0
        set flow_keys {proto clientflow serverflow inherit-vs}
        while {$index < [llength $tokens]} {
            set key [lindex $tokens $index]
            if {$key eq "proto"} {
                if {[dict exists $seen proto] || $index + 1 >= [llength $tokens]} {
                    error "FLOW::create_related requires one proto value"
                }
                incr index
                set protocol [lindex $tokens $index]
                if {![string is integer -strict $protocol] || $protocol < 0 || $protocol > 255} {
                    error "FLOW::create_related proto must be an integer from 0 to 255"
                }
                dict set seen proto 1
            } elseif {$key in {clientflow serverflow}} {
                if {[dict exists $seen $key]} { error "FLOW::create_related received duplicate $key" }
                set start [expr {$index + 1}]
                set cursor $start
                set positional_count 0
                while {$cursor < [llength $tokens]} {
                    set token [lindex $tokens $cursor]
                    if {$token in {-local-ip -local-port}} {
                        incr cursor 2
                        continue
                    }
                    if {$positional_count >= 3 && $token in $flow_keys} {
                        break
                    }
                    incr positional_count
                    incr cursor
                }
                set spec [_flow_parse_spec [lrange $tokens $start [expr {$cursor - 1}]] $key]
                if {$key eq "clientflow"} { set client_spec $spec } else { set server_spec $spec }
                dict set seen $key 1
                set index [expr {$cursor - 1}]
            } elseif {$key eq "inherit-vs"} {
                if {[dict exists $seen $key] || $index + 1 >= [llength $tokens]} {
                    error "FLOW::create_related inherit-vs requires a virtual server name"
                }
                incr index
                set inherit_vs [lindex $tokens $index]
                if {$inherit_vs eq ""} { error "FLOW::create_related inherit-vs cannot be empty" }
                dict set seen $key 1
            } else {
                error "FLOW::create_related received unsupported subcommand $key"
            }
            incr index
        }
        if {$client_spec eq "" || $server_spec eq ""} {
            error "FLOW::create_related requires clientflow and serverflow"
        }
        incr flow_next_related
        set client_handle "flow-related-${flow_next_related}-client"
        set server_handle "flow-related-${flow_next_related}-server"
        foreach {handle side peer spec} [list \
            $client_handle client $server_handle $client_spec \
            $server_handle server $client_handle $server_spec] {
            set flow [dict create side $side peer $peer timeout 300 priority 0 \
                last_used $flow_clock active 1 related 1 protocol $protocol \
                local_addr [dict get $spec local_addr] local_port [dict get $spec local_port] \
                remote_addr [dict get $spec remote_addr] remote_port [dict get $spec remote_port] \
                vlan [dict get $spec vlan] translation_loose $translation_loose \
                hairpin $hairpin inherit_vs $inherit_vs]
            dict set flow_handles $handle $flow
        }
        ::itest::log_decision flow create_related [list $client_handle $server_handle $protocol]
        return $client_handle
    }

    proc flow_this {args} {
        _flow_require_profile FLOW::this
        _flow_require_event FLOW::this
        if {[llength $args] != 0} { error "FLOW::this takes no arguments" }
        return [_flow_current_handle]
    }

    proc flow_peer {args} {
        variable flow_handles
        _flow_require_profile FLOW::peer
        _flow_require_event FLOW::peer
        if {[llength $args] != 1} { error "FLOW::peer requires a flow handle" }
        set flow [_flow_get [lindex $args 0] FLOW::peer]
        set peer [dict get $flow peer]
        if {![dict exists $flow_handles $peer]} {
            error "FLOW::peer resolved an unknown peer handle"
        }
        if {![dict get [dict get $flow_handles $peer] active]} {
            error "FLOW::peer resolved an inactive peer handle"
        }
        return $peer
    }

    proc flow_idle_duration {args} {
        variable flow_clock
        _flow_require_profile FLOW::idle_duration
        _flow_require_event FLOW::idle_duration
        if {[llength $args] != 1} { error "FLOW::idle_duration requires a flow handle" }
        set flow [_flow_get [lindex $args 0] FLOW::idle_duration]
        return [expr {$flow_clock - [dict get $flow last_used]}]
    }

    proc flow_refresh {args} {
        variable flow_clock
        variable flow_handles
        _flow_require_profile FLOW::refresh
        _flow_require_event FLOW::refresh
        if {[llength $args] != 1} { error "FLOW::refresh requires a flow handle" }
        set handle [lindex $args 0]
        set flow [_flow_get $handle FLOW::refresh]
        dict set flow last_used $flow_clock
        dict set flow_handles $handle $flow
        ::itest::log_decision flow refresh $handle
        return ""
    }

    proc flow_idle_timeout {args} {
        variable flow_handles
        _flow_require_profile FLOW::idle_timeout
        _flow_require_event FLOW::idle_timeout
        if {[llength $args] ni {1 2}} {
            error "FLOW::idle_timeout requires HANDLE and optional TIMEOUT"
        }
        set handle [lindex $args 0]
        set flow [_flow_get $handle FLOW::idle_timeout]
        if {[llength $args] == 1} { return [dict get $flow timeout] }
        set timeout [lindex $args 1]
        if {![string is integer -strict $timeout] || $timeout < 0} {
            error "FLOW::idle_timeout requires a non-negative integer timeout"
        }
        dict set flow timeout $timeout
        dict set flow_handles $handle $flow
        ::itest::log_decision flow idle_timeout [list $handle $timeout]
        return ""
    }

    proc flow_priority {args} {
        variable flow_handles
        _flow_require_profile FLOW::priority
        _flow_require_event FLOW::priority 1
        set handle [_flow_current_handle]
        set set_value 0
        set priority ""
        if {[llength $args] == 0} {
            # Getter for the current flow.
        } elseif {[llength $args] == 1} {
            set argument [lindex $args 0]
            if {$argument in {clientside serverside}} {
                set handle [expr {$argument eq "clientside" ? "flow-client-0" : "flow-server-0"}]
            } elseif {[string is integer -strict $argument]} {
                set priority $argument
                set set_value 1
            } else {
                set handle $argument
            }
        } elseif {[llength $args] == 2} {
            set selector [lindex $args 0]
            if {$selector in {clientside serverside}} {
                set handle [expr {$selector eq "clientside" ? "flow-client-0" : "flow-server-0"}]
            } else {
                set handle $selector
            }
            set priority [lindex $args 1]
            set set_value 1
        } else {
            error "FLOW::priority accepts at most a handle and priority"
        }
        set flow [_flow_get $handle FLOW::priority]
        if {!$set_value} { return [dict get $flow priority] }
        if {![string is integer -strict $priority] || $priority < 0 || $priority > 7} {
            error "FLOW::priority must be an integer from 0 to 7"
        }
        dict set flow priority $priority
        dict set flow_handles $handle $flow
        ::itest::log_decision flow priority [list $handle $priority]
        return ""
    }

    proc flow_snapshot {} {
        variable flow_clock
        variable flow_current_side
        variable flow_handles
        set result [list clock $flow_clock current_side $flow_current_side \
            current_handle [_flow_current_handle] flow_count [dict size $flow_handles]]
        set flows [list]
        foreach handle [lsort -dictionary [dict keys $flow_handles]] {
            set flow [dict get $flow_handles $handle]
            lappend flows [list $handle [dict get $flow side] [dict get $flow peer] \
                [dict get $flow timeout] [dict get $flow priority] \
                [dict get $flow last_used] [dict get $flow active] \
                [dict get $flow related] [dict get $flow protocol] \
                [dict get $flow local_addr] [dict get $flow local_port] \
                [dict get $flow remote_addr] [dict get $flow remote_port] \
                [dict get $flow vlan] [dict get $flow translation_loose] \
                [dict get $flow hairpin] [dict get $flow inherit_vs]]
        }
        lappend result flows $flows
        return $result
    }

    proc event_errors_reset {} {
        variable event_errors
        set event_errors {}
    }

    proc event_errors_record {event result} {
        variable event_errors
        set handlers_index [lsearch -exact $result handlers]
        if {$handlers_index < 0 || $handlers_index + 1 >= [llength $result]} {
            return
        }
        foreach handler [lindex $result [expr {$handlers_index + 1}]] {
            set code_index [lsearch -exact $handler code]
            if {$code_index < 0 || $code_index + 1 >= [llength $handler]} {
                continue
            }
            if {[lindex $handler [expr {$code_index + 1}]] ne "1"} {
                continue
            }
            set priority_index [lsearch -exact $handler priority]
            set error_index [lsearch -exact $handler error]
            set priority [expr {$priority_index >= 0 && $priority_index + 1 < [llength $handler] ? [lindex $handler [expr {$priority_index + 1}]] : ""}]
            set message [expr {$error_index >= 0 && $error_index + 1 < [llength $handler] ? [lindex $handler [expr {$error_index + 1}]] : "unknown iRule handler error"}]
            lappend event_errors [list $event $priority $message]
        }
    }

    proc event_errors_snapshot {} {
        variable event_errors
        return $event_errors
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

    proc profile_settings_clear {} {
        variable profile_settings
        set profile_settings [dict create]
    }

    proc profile_settings_set {profile raw_settings} {
        variable profile_settings
        if {[llength $raw_settings] % 2} {
            error "profile settings require attribute/value pairs"
        }
        set attributes [dict create]
        foreach {attribute value} $raw_settings {
            if {$attribute eq ""} { error "profile attribute name cannot be empty" }
            dict set attributes $attribute $value
        }
        dict set profile_settings [string toupper $profile] $attributes
    }

    proc _profile_setting {profile args} {
        variable profile_settings
        if {[llength $args] != 1} {
            error "PROFILE::$profile requires one attribute"
        }
        if {![_profile_enabled $profile] ||
            ![dict exists $profile_settings [string toupper $profile]]} {
            return ""
        }
        set wanted [lindex $args 0]
        set attributes [dict get $profile_settings [string toupper $profile]]
        if {[dict exists $attributes $wanted]} {
            return [dict get $attributes $wanted]
        }
        dict for {attribute value} $attributes {
            if {[string equal -nocase $attribute $wanted]} { return $value }
        }
        return ""
    }

    proc profile_access_command {args} { return [_profile_setting ACCESS {*}$args] }
    proc profile_antifraud_command {args} { return [_profile_setting ANTIFRAUD {*}$args] }
    proc profile_auth_command {args} {
        if {[llength $args] != 2} {
            error "PROFILE::auth requires a profile instance and attribute"
        }
        return [_profile_setting AUTH [lindex $args 1]]
    }
    proc profile_avr_command {args} { return [_profile_setting AVR {*}$args] }
    proc profile_diameter_command {args} { return [_profile_setting DIAMETER {*}$args] }
    proc profile_exchange_command {args} { return [_profile_setting EXCHANGE {*}$args] }
    proc profile_ftp_command {args} { return [_profile_setting FTP {*}$args] }
    proc profile_httpclass_command {args} { return [_profile_setting HTTPCLASS {*}$args] }
    proc profile_httpcompression_command {args} {
        return [_profile_setting HTTPCOMPRESSION {*}$args]
    }
    proc profile_oneconnect_command {args} {
        return [_profile_setting ONECONNECT {*}$args]
    }
    proc profile_persist_command {args} {
        if {[llength $args] != 3 || [lindex $args 0] ni {instance mode}} {
            error "PROFILE::persist requires instance/mode, profile, and attribute"
        }
        return [_profile_setting PERSIST [lindex $args 2]]
    }
    proc profile_stream_command {args} { return [_profile_setting STREAM {*}$args] }
    proc profile_tftp_command {args} { return [_profile_setting TFTP {*}$args] }
    proc profile_vdi_command {args} { return [_profile_setting VDI {*}$args] }
    proc profile_webacceleration_command {args} {
        return [_profile_setting WEBACCELERATION {*}$args]
    }
    proc profile_xml_command {args} { return [_profile_setting XML {*}$args] }

    proc profile_settings_snapshot {} {
        variable profile_settings
        set result [list]
        dict for {profile attributes} $profile_settings {
            dict for {attribute value} $attributes {
                lappend result [list $profile $attribute $value]
            }
        }
        return $result
    }

    proc dosl7_configure {enabled health profile mitigated raw_greylist} {
        variable dosl7_default_enabled
        variable dosl7_enabled
        variable dosl7_health
        variable dosl7_profile
        variable dosl7_default_mitigated
        variable dosl7_mitigated
        variable dosl7_profile_object
        variable dosl7_greylist
        if {$enabled ni {0 1} || $mitigated ni {0 1}} {
            error "DOSL7 enabled and mitigated state must be boolean"
        }
        if {![string is integer -strict $health] || $health < 0} {
            error "DOSL7 health must be a non-negative integer"
        }
        if {[llength $raw_greylist] % 3} {
            error "DOSL7 greylist requires address, rate, and timeout triples"
        }
        set greylist [dict create]
        foreach {address rate timeout} $raw_greylist {
            if {$address eq ""} {
                error "DOSL7 greylist address cannot be empty"
            }
            if {![string is integer -strict $rate] || $rate < 0 || $rate > 100} {
                error "DOSL7 slowdown rate must be an integer from 0 to 100"
            }
            if {![string is integer -strict $timeout] || $timeout < 0} {
                error "DOSL7 slowdown timeout must be a non-negative integer"
            }
            dict set greylist $address [list $rate $timeout]
        }
        set dosl7_default_enabled $enabled
        set dosl7_enabled $enabled
        set dosl7_health $health
        set dosl7_profile $profile
        set dosl7_default_mitigated $mitigated
        set dosl7_mitigated $mitigated
        set dosl7_profile_object ""
        set dosl7_greylist $greylist
    }

    proc dosl7_reset_connection {} {
        variable dosl7_default_enabled
        variable dosl7_enabled
        variable dosl7_default_mitigated
        variable dosl7_mitigated
        variable dosl7_profile_object
        set dosl7_enabled $dosl7_default_enabled
        set dosl7_profile_object ""
        set dosl7_mitigated $dosl7_default_mitigated
    }

    proc dosl7_prepare_request {has_override mitigated} {
        variable dosl7_default_mitigated
        variable dosl7_mitigated
        if {$has_override ni {0 1} || $mitigated ni {0 1}} {
            error "DOSL7 request mitigation state must be boolean"
        }
        if {$has_override} {
            set dosl7_mitigated $mitigated
        } else {
            set dosl7_mitigated $dosl7_default_mitigated
        }
    }

    proc dosl7_enable {args} {
        variable dosl7_enabled
        variable dosl7_profile_object
        if {[llength $args] > 1} {
            error "DOSL7::enable accepts an optional profile object"
        }
        set dosl7_enabled 1
        set dosl7_profile_object ""
        if {[llength $args] == 1} {
            set dosl7_profile_object [lindex $args 0]
        }
        ::itest::log_decision dosl7 enable $dosl7_profile_object
        return ""
    }

    proc dosl7_disable {args} {
        variable dosl7_enabled
        variable dosl7_profile_object
        if {[llength $args] != 0} {
            error "DOSL7::disable takes no arguments"
        }
        set dosl7_enabled 0
        set dosl7_profile_object ""
        ::itest::log_decision dosl7 disable
        return ""
    }

    proc dosl7_health {args} {
        variable dosl7_health
        if {[llength $args] != 0} {
            error "DOSL7::health takes no arguments"
        }
        return $dosl7_health
    }

    proc dosl7_profile {args} {
        variable dosl7_enabled
        variable dosl7_profile
        if {[llength $args] != 0} {
            error "DOSL7::profile takes no arguments"
        }
        if {!$dosl7_enabled || ![_profile_enabled FASTHTTP]} {
            return ""
        }
        return $dosl7_profile
    }

    proc dosl7_is_ip_slowdown {args} {
        variable dosl7_greylist
        if {[llength $args] != 0} {
            error "DOSL7::is_ip_slowdown takes no arguments"
        }
        return [dict exists $dosl7_greylist $::state::connection::client_addr]
    }

    proc dosl7_is_mitigated {args} {
        variable dosl7_mitigated
        if {[llength $args] != 0} {
            error "DOSL7::is_mitigated takes no arguments"
        }
        return $dosl7_mitigated
    }

    proc dosl7_slowdown {args} {
        variable dosl7_greylist
        if {[llength $args] != 2} {
            error "DOSL7::slowdown requires rate and timeout"
        }
        set rate [lindex $args 0]
        set timeout [lindex $args 1]
        if {![string is integer -strict $rate] || $rate < 0 || $rate > 100} {
            error "DOSL7::slowdown rate must be an integer from 0 to 100"
        }
        if {![string is integer -strict $timeout] || $timeout < 0} {
            error "DOSL7::slowdown timeout must be a non-negative integer"
        }
        set address $::state::connection::client_addr
        dict set dosl7_greylist $address [list $rate $timeout]
        ::itest::log_decision dosl7 slowdown [list $address $rate $timeout]
        return ""
    }

    proc dosl7_snapshot {} {
        variable dosl7_enabled
        variable dosl7_health
        variable dosl7_profile
        variable dosl7_mitigated
        variable dosl7_profile_object
        variable dosl7_greylist
        set greylist [list]
        foreach address [lsort -dictionary [dict keys $dosl7_greylist]] {
            set values [dict get $dosl7_greylist $address]
            lappend greylist [list $address [lindex $values 0] [lindex $values 1]]
        }
        return [list \
            enabled $dosl7_enabled \
            health $dosl7_health \
            profile $dosl7_profile \
            mitigated $dosl7_mitigated \
            profile_object $dosl7_profile_object \
            greylist $greylist]
    }

    proc asm_configure {enabled policy client_ip fingerprint username login_status microservice status severity support_id captcha_status captcha_age payload} {
        variable asm_default_enabled
        variable asm_enabled
        variable asm_default_policy
        variable asm_policy
        variable asm_default_client_ip
        variable asm_client_ip
        variable asm_default_fingerprint
        variable asm_fingerprint
        variable asm_default_username
        variable asm_username
        variable asm_default_login_status
        variable asm_login_status
        variable asm_default_microservice
        variable asm_microservice
        variable asm_default_status
        variable asm_status
        variable asm_default_severity
        variable asm_severity
        variable asm_default_support_id
        variable asm_support_id
        variable asm_default_captcha_status
        variable asm_captcha_status
        variable asm_default_captcha_age
        variable asm_captcha_age
        variable asm_default_payload
        variable asm_payload
        if {$enabled ni {0 1}} { error "ASM enabled state must be boolean" }
        if {$login_status ni {not_logged_in logging_in logged_in failed}} {
            error "invalid ASM login status"
        }
        if {$status ni {Alarm Blocked Clear {}}} { error "invalid ASM status" }
        if {$severity ni {Emergency Alert Critical Error Warning Notice Informational {}}} {
            error "invalid ASM severity"
        }
        if {$captcha_status ni {not_received correct incorrect empty}} {
            error "invalid ASM CAPTCHA status"
        }
        if {![string is integer -strict $captcha_age] || $captcha_age < -1} {
            error "ASM CAPTCHA age must be an integer from -1"
        }
        set asm_default_enabled $enabled
        set asm_enabled $enabled
        set asm_default_policy $policy
        set asm_policy $policy
        set asm_default_client_ip $client_ip
        set asm_client_ip $client_ip
        set asm_default_fingerprint $fingerprint
        set asm_fingerprint $fingerprint
        set asm_default_username $username
        set asm_username $username
        set asm_default_login_status $login_status
        set asm_login_status $login_status
        set asm_default_microservice $microservice
        set asm_microservice $microservice
        set asm_default_status $status
        set asm_status $status
        set asm_default_severity $severity
        set asm_severity $severity
        set asm_default_support_id $support_id
        set asm_support_id $support_id
        set asm_default_captcha_status $captcha_status
        set asm_captcha_status $captcha_status
        set asm_default_captcha_age $captcha_age
        set asm_captcha_age $captcha_age
        set asm_default_payload $payload
        set asm_payload $payload
        set asm_captcha_sent 0
        set asm_uncaptcha 0
        set asm_unblocked 0
        set asm_conviction 0
        set asm_deception 0
    }

    proc asm_set_violations {args} {
        variable asm_default_violations
        variable asm_violations
        set violations [list]
        foreach record $args {
            if {[llength $record] != 4} {
                error "ASM violation records require name, attack type, rating, and details"
            }
            lassign $record name attack_type rating details
            if {$name eq "" || [llength $details] % 2} {
                error "invalid ASM violation record"
            }
            lappend violations [list $name $attack_type $rating $details]
        }
        set asm_default_violations $violations
        set asm_violations $violations
    }

    proc asm_set_signatures {field raw_values} {
        variable asm_default_signatures
        variable asm_signatures
        if {$field ni {ids names set_names staged_ids staged_names staged_set_names}} {
            error "invalid ASM signature field"
        }
        dict set asm_default_signatures $field $raw_values
        dict set asm_signatures $field $raw_values
    }

    proc asm_set_campaigns {field raw_values} {
        variable asm_default_campaigns
        variable asm_campaigns
        if {$field ni {names staged_names}} {
            error "invalid ASM threat campaign field"
        }
        dict set asm_default_campaigns $field $raw_values
        dict set asm_campaigns $field $raw_values
    }

    proc _asm_derived_status {} {
        variable asm_violations
        if {[llength $asm_violations] > 0} { return Alarm }
        return Clear
    }

    proc _asm_derived_severity {} {
        variable asm_violations
        set best -1
        set result ""
        set ranks {Informational 0 Notice 1 Warning 2 Error 3 Critical 4 Alert 5 Emergency 6}
        foreach record $asm_violations {
            set rating [lindex $record 2]
            set index [lsearch -exact $ranks $rating]
            if {$index >= 0 && $index > $best} {
                set best $index
                set result $rating
            }
        }
        return $result
    }

    proc asm_prepare_request {has_body body} {
        variable asm_default_client_ip
        variable asm_client_ip
        variable asm_default_fingerprint
        variable asm_fingerprint
        variable asm_default_username
        variable asm_username
        variable asm_default_login_status
        variable asm_login_status
        variable asm_default_microservice
        variable asm_microservice
        variable asm_default_status
        variable asm_status
        variable asm_default_severity
        variable asm_severity
        variable asm_default_support_id
        variable asm_support_id
        variable asm_default_captcha_status
        variable asm_captcha_status
        variable asm_default_captcha_age
        variable asm_captcha_age
        variable asm_default_payload
        variable asm_payload
        variable asm_default_violations
        variable asm_violations
        variable asm_default_signatures
        variable asm_signatures
        variable asm_default_campaigns
        variable asm_campaigns
        variable asm_captcha_sent
        variable asm_uncaptcha
        variable asm_unblocked
        variable asm_conviction
        variable asm_deception
        if {$has_body ni {0 1}} { error "ASM request body presence must be boolean" }
        set asm_client_ip $asm_default_client_ip
        set asm_fingerprint $asm_default_fingerprint
        set asm_username $asm_default_username
        set asm_login_status $asm_default_login_status
        set asm_microservice $asm_default_microservice
        set asm_status $asm_default_status
        set asm_severity $asm_default_severity
        set asm_support_id $asm_default_support_id
        set asm_captcha_status $asm_default_captcha_status
        set asm_captcha_age $asm_default_captcha_age
        set asm_payload $asm_default_payload
        if {$has_body} { set asm_payload $body }
        set asm_violations $asm_default_violations
        set asm_signatures $asm_default_signatures
        set asm_campaigns $asm_default_campaigns
        if {$asm_status eq ""} { set asm_status [_asm_derived_status] }
        if {$asm_severity eq ""} { set asm_severity [_asm_derived_severity] }
        set asm_captcha_sent 0
        set asm_uncaptcha 0
        set asm_unblocked 0
        set asm_conviction 0
        set asm_deception 0
    }

    proc asm_reset_connection {} {
        variable asm_default_enabled
        variable asm_enabled
        variable asm_default_policy
        variable asm_policy
        set asm_enabled $asm_default_enabled
        set asm_policy $asm_default_policy
    }

    proc asm_client_ip {args} {
        variable asm_client_ip
        if {[llength $args] != 0} { error "ASM::client_ip takes no arguments" }
        if {$asm_client_ip ne ""} { return $asm_client_ip }
        return $::state::connection::client_addr
    }

    proc asm_fingerprint {args} {
        variable asm_fingerprint
        if {[llength $args] != 0} { error "ASM::fingerprint takes no arguments" }
        return $asm_fingerprint
    }

    proc asm_username {args} {
        variable asm_username
        if {[llength $args] != 0} { error "ASM::username takes no arguments" }
        return $asm_username
    }

    proc asm_login_status {args} {
        variable asm_login_status
        if {[llength $args] != 0} { error "ASM::login_status takes no arguments" }
        return $asm_login_status
    }

    proc asm_is_authenticated {args} {
        if {[llength $args] != 0} { error "ASM::is_authenticated takes no arguments" }
        return [expr {[asm_login_status] eq "logged_in"}]
    }

    proc asm_microservice {args} {
        variable asm_microservice
        if {[llength $args] != 0} { error "ASM::microservice takes no arguments" }
        return $asm_microservice
    }

    proc asm_policy {args} {
        variable asm_enabled
        variable asm_policy
        if {[llength $args] != 0} { error "ASM::policy takes no arguments" }
        if {!$asm_enabled} { return "" }
        return $asm_policy
    }

    proc asm_support_id {args} {
        variable asm_support_id
        if {[llength $args] != 0} { error "ASM::support_id takes no arguments" }
        return $asm_support_id
    }

    proc asm_status {args} {
        variable asm_enabled
        variable asm_status
        if {[llength $args] != 0} { error "ASM::status takes no arguments" }
        if {!$asm_enabled} { return "" }
        return $asm_status
    }

    proc asm_severity {args} {
        variable asm_enabled
        variable asm_severity
        if {[llength $args] != 0} { error "ASM::severity takes no arguments" }
        if {!$asm_enabled} { return "" }
        return $asm_severity
    }

    proc asm_violation {args} {
        variable asm_violations
        if {[llength $args] != 1} {
            error "ASM::violation requires count, names, attack_types, details, or rating"
        }
        set option [lindex $args 0]
        if {$option eq "count"} { return [llength $asm_violations] }
        set result [list]
        foreach record $asm_violations {
            switch -exact -- $option {
                names { lappend result [lindex $record 0] }
                attack_types { lappend result [lindex $record 1] }
                details { lappend result [lindex $record 3] }
                rating { lappend result [lindex $record 2] }
                default { error "unsupported ASM::violation selector $option" }
            }
        }
        return $result
    }

    proc asm_signature {args} {
        variable asm_signatures
        if {[llength $args] != 1} { error "ASM::signature requires a selector" }
        set field [lindex $args 0]
        if {$field ni {ids names set_names staged_ids staged_names staged_set_names}} {
            error "unsupported ASM::signature selector $field"
        }
        return [dict get $asm_signatures $field]
    }

    proc asm_threat_campaign {args} {
        variable asm_campaigns
        if {[llength $args] != 1 || [lindex $args 0] ni {names staged_names}} {
            error "ASM::threat_campaign requires names or staged_names"
        }
        return [dict get $asm_campaigns [lindex $args 0]]
    }

    proc asm_captcha_status {args} {
        variable asm_captcha_status
        if {[llength $args] != 0} { error "ASM::captcha_status takes no arguments" }
        return $asm_captcha_status
    }

    proc asm_captcha_age {args} {
        variable asm_captcha_status
        variable asm_captcha_age
        if {[llength $args] != 0} { error "ASM::captcha_age takes no arguments" }
        if {$asm_captcha_status ne "correct"} { return -1 }
        return $asm_captcha_age
    }

    proc asm_captcha {args} {
        variable asm_status
        variable asm_uncaptcha
        variable asm_captcha_sent
        if {[llength $args] != 0} { error "ASM::captcha takes no arguments" }
        if {$asm_uncaptcha} { return "nok asm uncaptcha command was raised" }
        if {$asm_status eq "Blocked"} { return "nok asm blocked request" }
        set asm_captcha_sent 1
        ::itest::log_decision asm captcha
        return ok
    }

    proc asm_uncaptcha {args} {
        variable asm_uncaptcha
        if {[llength $args] != 0} { error "ASM::uncaptcha takes no arguments" }
        set asm_uncaptcha 1
        ::itest::log_decision asm uncaptcha
        return ""
    }

    proc asm_unblock {args} {
        variable asm_status
        variable asm_unblocked
        if {[llength $args] != 0} { error "ASM::unblock takes no arguments" }
        if {$asm_status eq "Blocked"} { set asm_status Alarm }
        set asm_unblocked 1
        ::itest::log_decision asm unblock
        return ""
    }

    proc asm_conviction {args} {
        variable asm_conviction
        if {[llength $args] != 0} { error "ASM::conviction takes no arguments" }
        set asm_conviction 1
        ::itest::log_decision asm conviction
        return ""
    }

    proc asm_deception {args} {
        variable asm_deception
        if {[llength $args] != 0} { error "ASM::deception takes no arguments" }
        set asm_deception 1
        ::itest::log_decision asm deception
        return ""
    }

    proc asm_disable {args} {
        variable asm_enabled
        if {[llength $args] != 0} { error "ASM::disable takes no arguments" }
        set asm_enabled 0
        ::itest::log_decision asm disable
        return ""
    }

    proc asm_enable {args} {
        variable asm_enabled
        variable asm_policy
        if {[llength $args] != 1} { error "ASM::enable requires an ASM policy" }
        set asm_enabled 1
        set asm_policy [lindex $args 0]
        ::itest::log_decision asm enable $asm_policy
        return ""
    }

    proc asm_raise {args} {
        variable asm_violations
        variable asm_status
        variable asm_severity
        if {[llength $args] < 1 || [llength $args] > 2} {
            error "ASM::raise requires a violation name and optional details"
        }
        set name [lindex $args 0]
        set details {}
        if {[llength $args] == 2} { set details [lindex $args 1] }
        if {$name eq "" || [llength $details] % 2} {
            error "ASM::raise requires a non-empty name and even detail pairs"
        }
        lappend asm_violations [list $name "" "" $details]
        if {$asm_status eq "Clear"} { set asm_status Alarm }
        if {$asm_severity eq ""} { set asm_severity [_asm_derived_severity] }
        ::itest::log_decision asm raise [list $name $details]
        return ""
    }

    proc asm_payload {args} {
        variable asm_payload
        if {[llength $args] == 0} { return $asm_payload }
        if {[lindex $args 0] eq "replace"} {
            if {[llength $args] != 4} { error "ASM::payload replace requires offset, length, and payload" }
            set offset [lindex $args 1]
            set length [lindex $args 2]
            if {![string is integer -strict $offset] || $offset < 0 || ![string is integer -strict $length] || $length < 0} {
                error "ASM::payload offsets and lengths must be non-negative integers"
            }
            set offset [expr {min($offset, [string length $asm_payload])}]
            set prefix [string range $asm_payload 0 [expr {$offset - 1}]]
            set suffix [string range $asm_payload [expr {$offset + $length}] end]
            set asm_payload "$prefix[lindex $args 3]$suffix"
            return ""
        }
        if {[llength $args] == 1} {
            set offset 0
            set length [lindex $args 0]
        } elseif {[llength $args] == 2} {
            set offset [lindex $args 0]
            set length [lindex $args 1]
        } else {
            error "ASM::payload accepts length, offset/length, or replace"
        }
        if {![string is integer -strict $offset] || $offset < 0 || ![string is integer -strict $length] || $length < 0} {
            error "ASM::payload offsets and lengths must be non-negative integers"
        }
        return [string range $asm_payload $offset [expr {$offset + $length - 1}]]
    }

    proc asm_violation_data {args} {
        variable asm_violations
        variable asm_support_id
        if {[llength $args] != 0} { error "ASM::violation_data takes no arguments" }
        if {[llength $asm_violations] == 0} { return [list] }
        return [list [lindex [lindex $asm_violations 0] 0] $asm_support_id [asm_client_ip]]
    }

    proc asm_snapshot {} {
        variable asm_enabled
        variable asm_policy
        variable asm_client_ip
        variable asm_fingerprint
        variable asm_username
        variable asm_login_status
        variable asm_microservice
        variable asm_status
        variable asm_severity
        variable asm_support_id
        variable asm_captcha_status
        variable asm_captcha_age
        variable asm_payload
        variable asm_captcha_sent
        variable asm_uncaptcha
        variable asm_unblocked
        variable asm_conviction
        variable asm_deception
        variable asm_violations
        variable asm_signatures
        variable asm_campaigns
        set effective_policy [asm_policy]
        set effective_status [asm_status]
        set effective_severity [asm_severity]
        set violations [list]
        foreach record $asm_violations { lappend violations $record }
        set signatures [list]
        foreach field {ids names set_names staged_ids staged_names staged_set_names} {
            lappend signatures [list $field [dict get $asm_signatures $field]]
        }
        set campaigns [list]
        foreach field {names staged_names} {
            lappend campaigns [list $field [dict get $asm_campaigns $field]]
        }
        return [list \
            enabled $asm_enabled policy $effective_policy client_ip [asm_client_ip] \
            fingerprint $asm_fingerprint username $asm_username \
            login_status $asm_login_status microservice $asm_microservice \
            status $effective_status severity $effective_severity support_id $asm_support_id \
            captcha_status $asm_captcha_status captcha_age $asm_captcha_age \
            payload $asm_payload captcha_sent $asm_captcha_sent \
            uncaptcha $asm_uncaptcha unblocked $asm_unblocked \
            conviction $asm_conviction deception $asm_deception \
            violations $violations signatures $signatures threat_campaigns $campaigns]
    }

    proc botdefense_configure {raw} {
        variable botdefense_default_enabled
        variable botdefense_enabled
        variable botdefense_default_action
        variable botdefense_action
        variable botdefense_default_bot_name
        variable botdefense_bot_name
        variable botdefense_default_bot_signature
        variable botdefense_bot_signature
        variable botdefense_default_bot_signature_category
        variable botdefense_bot_signature_category
        variable botdefense_default_captcha_age
        variable botdefense_captcha_age
        variable botdefense_default_captcha_status
        variable botdefense_captcha_status
        variable botdefense_default_client_class
        variable botdefense_client_class
        variable botdefense_default_client_type
        variable botdefense_client_type
        variable botdefense_default_cookie_age
        variable botdefense_cookie_age
        variable botdefense_default_cookie_status
        variable botdefense_cookie_status
        variable botdefense_default_cs_allowed
        variable botdefense_cs_allowed
        variable botdefense_default_cs_possible
        variable botdefense_cs_possible
        variable botdefense_default_cs_attribute_device_id
        variable botdefense_cs_attribute_device_id
        variable botdefense_default_device_id
        variable botdefense_device_id
        variable botdefense_default_intent
        variable botdefense_intent
        variable botdefense_default_previous_action
        variable botdefense_previous_action
        variable botdefense_default_previous_request_age
        variable botdefense_previous_request_age
        variable botdefense_default_previous_support_id
        variable botdefense_previous_support_id
        variable botdefense_default_reason
        variable botdefense_reason
        variable botdefense_default_support_id
        variable botdefense_support_id
        variable botdefense_action_overridden
        if {[llength $raw] != 21} { error "invalid Bot Defense configuration" }
        lassign $raw enabled action bot_name bot_signature bot_signature_category \
            captcha_age captcha_status client_class client_type cookie_age cookie_status \
            cs_allowed cs_possible cs_attribute_device_id device_id intent \
            previous_action previous_request_age previous_support_id reason support_id
        foreach {name value} [list \
            enabled $enabled cs_allowed $cs_allowed cs_possible $cs_possible \
            cs_attribute_device_id $cs_attribute_device_id] {
            if {$value ni {0 1}} { error "Bot Defense $name state must be boolean" }
        }
        if {![string is integer -strict $captcha_age] || $captcha_age < -1} {
            error "Bot Defense CAPTCHA age must be a non-negative integer or -1"
        }
        if {![string is integer -strict $cookie_age] || $cookie_age < -1} {
            error "Bot Defense cookie age must be a non-negative integer or -1"
        }
        if {![string is integer -strict $device_id] || $device_id < 0} {
            error "Bot Defense device ID must be a non-negative integer"
        }
        if {![string is integer -strict $previous_request_age] || $previous_request_age < 0} {
            error "Bot Defense previous request age must be a non-negative integer"
        }
        if {$action eq ""} { error "Bot Defense action cannot be empty" }
        if {$captcha_status ni {not_received correct incorrect empty expired}} {
            error "invalid Bot Defense CAPTCHA status"
        }
        if {$client_type ni {bot mobile_app browser uncategorized}} {
            error "invalid Bot Defense client type"
        }
        if {$client_class ni {unknown browser mobile_application trusted_bot untrusted_bot malicious_bot suspicious_browser}} {
            error "invalid Bot Defense client class"
        }
        if {$cookie_status ni {{} valid invalid expired valid_redirect_challenge renewal}} {
            error "invalid Bot Defense cookie status"
        }
        set botdefense_default_enabled $enabled
        set botdefense_enabled $enabled
        set botdefense_default_action $action
        set botdefense_action $action
        set botdefense_default_bot_name $bot_name
        set botdefense_bot_name $bot_name
        set botdefense_default_bot_signature $bot_signature
        set botdefense_bot_signature $bot_signature
        set botdefense_default_bot_signature_category $bot_signature_category
        set botdefense_bot_signature_category $bot_signature_category
        set botdefense_default_captcha_age $captcha_age
        set botdefense_captcha_age $captcha_age
        set botdefense_default_captcha_status $captcha_status
        set botdefense_captcha_status $captcha_status
        set botdefense_default_client_class $client_class
        set botdefense_client_class $client_class
        set botdefense_default_client_type $client_type
        set botdefense_client_type $client_type
        set botdefense_default_cookie_age $cookie_age
        set botdefense_cookie_age $cookie_age
        set botdefense_default_cookie_status $cookie_status
        set botdefense_cookie_status $cookie_status
        set botdefense_default_cs_allowed $cs_allowed
        set botdefense_cs_allowed $cs_allowed
        set botdefense_default_cs_possible $cs_possible
        set botdefense_cs_possible $cs_possible
        set botdefense_default_cs_attribute_device_id $cs_attribute_device_id
        set botdefense_cs_attribute_device_id $cs_attribute_device_id
        set botdefense_default_device_id $device_id
        set botdefense_device_id $device_id
        set botdefense_default_intent $intent
        set botdefense_intent $intent
        set botdefense_default_previous_action $previous_action
        set botdefense_previous_action $previous_action
        set botdefense_default_previous_request_age $previous_request_age
        set botdefense_previous_request_age $previous_request_age
        set botdefense_default_previous_support_id $previous_support_id
        set botdefense_previous_support_id $previous_support_id
        set botdefense_default_reason $reason
        set botdefense_reason $reason
        set botdefense_default_support_id $support_id
        set botdefense_support_id $support_id
        set botdefense_action_overridden 0
    }

    proc botdefense_set_lists {anomalies categories} {
        variable botdefense_default_bot_anomalies
        variable botdefense_bot_anomalies
        variable botdefense_default_bot_categories
        variable botdefense_bot_categories
        set botdefense_default_bot_anomalies $anomalies
        set botdefense_bot_anomalies $anomalies
        set botdefense_default_bot_categories $categories
        set botdefense_bot_categories $categories
    }

    proc botdefense_set_micro_service {raw} {
        variable botdefense_default_micro_service
        variable botdefense_micro_service
        if {[llength $raw] != 2} { error "Bot Defense micro-service requires name and type" }
        set botdefense_default_micro_service $raw
        set botdefense_micro_service $raw
    }

    proc botdefense_prepare_request {} {
        variable botdefense_default_action
        variable botdefense_action
        variable botdefense_default_bot_anomalies
        variable botdefense_bot_anomalies
        variable botdefense_default_bot_categories
        variable botdefense_bot_categories
        variable botdefense_default_bot_name
        variable botdefense_bot_name
        variable botdefense_default_bot_signature
        variable botdefense_bot_signature
        variable botdefense_default_bot_signature_category
        variable botdefense_bot_signature_category
        variable botdefense_default_captcha_age
        variable botdefense_captcha_age
        variable botdefense_default_captcha_status
        variable botdefense_captcha_status
        variable botdefense_default_client_class
        variable botdefense_client_class
        variable botdefense_default_client_type
        variable botdefense_client_type
        variable botdefense_default_cookie_age
        variable botdefense_cookie_age
        variable botdefense_default_cookie_status
        variable botdefense_cookie_status
        variable botdefense_default_cs_allowed
        variable botdefense_cs_allowed
        variable botdefense_default_cs_possible
        variable botdefense_cs_possible
        variable botdefense_default_cs_attribute_device_id
        variable botdefense_cs_attribute_device_id
        variable botdefense_default_device_id
        variable botdefense_device_id
        variable botdefense_default_intent
        variable botdefense_intent
        variable botdefense_default_micro_service
        variable botdefense_micro_service
        variable botdefense_default_previous_action
        variable botdefense_previous_action
        variable botdefense_default_previous_request_age
        variable botdefense_previous_request_age
        variable botdefense_default_previous_support_id
        variable botdefense_previous_support_id
        variable botdefense_default_reason
        variable botdefense_reason
        variable botdefense_default_support_id
        variable botdefense_support_id
        variable botdefense_action_overridden
        set botdefense_action $botdefense_default_action
        set botdefense_bot_anomalies $botdefense_default_bot_anomalies
        set botdefense_bot_categories $botdefense_default_bot_categories
        set botdefense_bot_name $botdefense_default_bot_name
        set botdefense_bot_signature $botdefense_default_bot_signature
        set botdefense_bot_signature_category $botdefense_default_bot_signature_category
        set botdefense_captcha_age $botdefense_default_captcha_age
        set botdefense_captcha_status $botdefense_default_captcha_status
        set botdefense_client_class $botdefense_default_client_class
        set botdefense_client_type $botdefense_default_client_type
        set botdefense_cookie_age $botdefense_default_cookie_age
        set botdefense_cookie_status $botdefense_default_cookie_status
        set botdefense_cs_allowed $botdefense_default_cs_allowed
        set botdefense_cs_possible $botdefense_default_cs_possible
        set botdefense_cs_attribute_device_id $botdefense_default_cs_attribute_device_id
        set botdefense_device_id $botdefense_default_device_id
        set botdefense_intent $botdefense_default_intent
        set botdefense_micro_service $botdefense_default_micro_service
        set botdefense_previous_action $botdefense_default_previous_action
        set botdefense_previous_request_age $botdefense_default_previous_request_age
        set botdefense_previous_support_id $botdefense_default_previous_support_id
        set botdefense_reason $botdefense_default_reason
        set botdefense_support_id $botdefense_default_support_id
        set botdefense_action_overridden 0
    }

    proc botdefense_reset_connection {} {
        variable botdefense_default_enabled
        variable botdefense_enabled
        set botdefense_enabled $botdefense_default_enabled
    }

    proc botdefense_action {args} {
        variable botdefense_enabled
        variable botdefense_action
        variable botdefense_action_overridden
        variable botdefense_cs_allowed
        variable botdefense_cs_possible
        if {[llength $args] == 0} { return $botdefense_action }
        if {[llength $args] != 1} { error "BOTDEFENSE::action accepts an optional action" }
        set requested [lindex $args 0]
        if {$requested eq ""} { error "BOTDEFENSE::action cannot set an empty action" }
        if {!$botdefense_enabled} { return "bot defense is disabled" }
        if {$botdefense_action_overridden} { return "action already overridden" }
        if {[string match *challenge* $requested] && (!$botdefense_cs_possible || !$botdefense_cs_allowed)} {
            return "client-side action is not possible"
        }
        set botdefense_action $requested
        set botdefense_action_overridden 1
        ::itest::log_decision botdefense action $requested
        return ok
    }

    proc botdefense_bot_anomalies {args} {
        variable botdefense_bot_anomalies
        if {[llength $args] != 0} { error "BOTDEFENSE::bot_anomalies takes no arguments" }
        return $botdefense_bot_anomalies
    }

    proc botdefense_bot_categories {args} {
        variable botdefense_bot_categories
        if {[llength $args] != 0} { error "BOTDEFENSE::bot_categories takes no arguments" }
        return $botdefense_bot_categories
    }

    proc botdefense_bot_name {args} {
        variable botdefense_bot_name
        if {[llength $args] != 0} { error "BOTDEFENSE::bot_name takes no arguments" }
        return $botdefense_bot_name
    }

    proc botdefense_bot_signature {args} {
        variable botdefense_bot_signature
        if {[llength $args] != 0} { error "BOTDEFENSE::bot_signature takes no arguments" }
        return $botdefense_bot_signature
    }

    proc botdefense_bot_signature_category {args} {
        variable botdefense_bot_signature_category
        if {[llength $args] != 0} { error "BOTDEFENSE::bot_signature_category takes no arguments" }
        return $botdefense_bot_signature_category
    }

    proc botdefense_captcha_age {args} {
        variable botdefense_captcha_age
        variable botdefense_captcha_status
        if {[llength $args] != 0} { error "BOTDEFENSE::captcha_age takes no arguments" }
        if {$botdefense_captcha_status ni {correct renewal expired}} { return -1 }
        return $botdefense_captcha_age
    }

    proc botdefense_captcha_status {args} {
        variable botdefense_captcha_status
        if {[llength $args] != 0} { error "BOTDEFENSE::captcha_status takes no arguments" }
        return $botdefense_captcha_status
    }

    proc botdefense_client_class {args} {
        variable botdefense_client_class
        if {[llength $args] != 0} { error "BOTDEFENSE::client_class takes no arguments" }
        return $botdefense_client_class
    }

    proc botdefense_client_type {args} {
        variable botdefense_client_type
        if {[llength $args] != 0} { error "BOTDEFENSE::client_type takes no arguments" }
        return $botdefense_client_type
    }

    proc botdefense_cookie_age {args} {
        variable botdefense_cookie_age
        variable botdefense_cookie_status
        if {[llength $args] != 0} { error "BOTDEFENSE::cookie_age takes no arguments" }
        if {$botdefense_cookie_status ni {valid expired valid_redirect_challenge renewal}} { return -1 }
        return $botdefense_cookie_age
    }

    proc botdefense_cookie_status {args} {
        variable botdefense_cookie_status
        if {[llength $args] != 0} { error "BOTDEFENSE::cookie_status takes no arguments" }
        return $botdefense_cookie_status
    }

    proc botdefense_cs_allowed {args} {
        variable botdefense_cs_allowed
        if {[llength $args] > 1} { error "BOTDEFENSE::cs_allowed accepts an optional boolean" }
        if {[llength $args] == 0} { return $botdefense_cs_allowed }
        set value [lindex $args 0]
        if {![string is boolean -strict $value]} { error "BOTDEFENSE::cs_allowed requires a boolean" }
        set botdefense_cs_allowed [expr {$value ? 1 : 0}]
        ::itest::log_decision botdefense cs_allowed $botdefense_cs_allowed
        return ""
    }

    proc botdefense_cs_attribute {args} {
        variable botdefense_cs_attribute_device_id
        if {[llength $args] < 1 || [llength $args] > 2 || [lindex $args 0] ne "device_id"} {
            error "BOTDEFENSE::cs_attribute syntax is device_id with optional boolean"
        }
        if {[llength $args] == 1} { return $botdefense_cs_attribute_device_id }
        set value [lindex $args 1]
        if {![string is boolean -strict $value]} { error "BOTDEFENSE::cs_attribute requires a boolean" }
        set botdefense_cs_attribute_device_id [expr {$value ? 1 : 0}]
        ::itest::log_decision botdefense cs_attribute $botdefense_cs_attribute_device_id
        return ""
    }

    proc botdefense_cs_possible {args} {
        variable botdefense_cs_possible
        if {[llength $args] != 0} { error "BOTDEFENSE::cs_possible takes no arguments" }
        return $botdefense_cs_possible
    }

    proc botdefense_device_id {args} {
        variable botdefense_device_id
        if {[llength $args] != 0} { error "BOTDEFENSE::device_id takes no arguments" }
        return $botdefense_device_id
    }

    proc botdefense_disable {args} {
        variable botdefense_enabled
        if {[llength $args] != 0} { error "BOTDEFENSE::disable takes no arguments" }
        set botdefense_enabled 0
        ::itest::log_decision botdefense disable
        return ""
    }

    proc botdefense_enable {args} {
        variable botdefense_enabled
        if {[llength $args] != 0} { error "BOTDEFENSE::enable takes no arguments" }
        set botdefense_enabled 1
        ::itest::log_decision botdefense enable
        return ""
    }

    proc botdefense_intent {args} {
        variable botdefense_intent
        if {[llength $args] != 0} { error "BOTDEFENSE::intent takes no arguments" }
        return $botdefense_intent
    }

    proc botdefense_micro_service {args} {
        variable botdefense_micro_service
        if {[llength $args] != 1 || [lindex $args 0] ni {name type}} {
            error "BOTDEFENSE::micro_service requires name or type"
        }
        return [lindex $botdefense_micro_service [expr {[lindex $args 0] eq "name" ? 0 : 1}]]
    }

    proc botdefense_previous_action {args} {
        variable botdefense_previous_action
        if {[llength $args] != 0} { error "BOTDEFENSE::previous_action takes no arguments" }
        return $botdefense_previous_action
    }

    proc botdefense_previous_request_age {args} {
        variable botdefense_previous_request_age
        if {[llength $args] != 0} { error "BOTDEFENSE::previous_request_age takes no arguments" }
        return $botdefense_previous_request_age
    }

    proc botdefense_previous_support_id {args} {
        variable botdefense_previous_support_id
        if {[llength $args] != 0} { error "BOTDEFENSE::previous_support_id takes no arguments" }
        return $botdefense_previous_support_id
    }

    proc botdefense_reason {args} {
        variable botdefense_reason
        if {[llength $args] != 0} { error "BOTDEFENSE::reason takes no arguments" }
        return $botdefense_reason
    }

    proc botdefense_support_id {args} {
        variable botdefense_support_id
        if {[llength $args] != 0} { error "BOTDEFENSE::support_id takes no arguments" }
        return $botdefense_support_id
    }

    proc botdefense_snapshot {} {
        variable botdefense_enabled
        variable botdefense_action
        variable botdefense_action_overridden
        variable botdefense_bot_anomalies
        variable botdefense_bot_categories
        variable botdefense_bot_name
        variable botdefense_bot_signature
        variable botdefense_bot_signature_category
        variable botdefense_captcha_status
        variable botdefense_client_class
        variable botdefense_client_type
        variable botdefense_cookie_status
        variable botdefense_cs_allowed
        variable botdefense_cs_attribute_device_id
        variable botdefense_cs_possible
        variable botdefense_device_id
        variable botdefense_intent
        variable botdefense_micro_service
        variable botdefense_previous_action
        variable botdefense_previous_request_age
        variable botdefense_previous_support_id
        variable botdefense_reason
        variable botdefense_support_id
        return [list \
            enabled $botdefense_enabled action $botdefense_action \
            action_overridden $botdefense_action_overridden \
            bot_anomalies $botdefense_bot_anomalies bot_categories $botdefense_bot_categories \
            bot_name $botdefense_bot_name bot_signature $botdefense_bot_signature \
            bot_signature_category $botdefense_bot_signature_category \
            captcha_age [botdefense_captcha_age] captcha_status $botdefense_captcha_status \
            client_class $botdefense_client_class client_type $botdefense_client_type \
            cookie_age [botdefense_cookie_age] cookie_status $botdefense_cookie_status \
            cs_allowed $botdefense_cs_allowed \
            cs_attribute_device_id $botdefense_cs_attribute_device_id \
            cs_possible $botdefense_cs_possible device_id $botdefense_device_id \
            intent $botdefense_intent micro_service $botdefense_micro_service \
            previous_action $botdefense_previous_action \
            previous_request_age $botdefense_previous_request_age \
            previous_support_id $botdefense_previous_support_id reason $botdefense_reason \
            support_id $botdefense_support_id]
    }

    proc antifraud_configure {raw} {
        variable antifraud_default_enabled
        variable antifraud_enabled
        variable antifraud_default_profile
        variable antifraud_profile
        variable antifraud_default_login_requested
        variable antifraud_default_alert_requested
        variable antifraud_default_client_id
        variable antifraud_client_id
        variable antifraud_default_device_id
        variable antifraud_device_id
        variable antifraud_default_fingerprint
        variable antifraud_fingerprint
        variable antifraud_default_geo
        variable antifraud_geo
        variable antifraud_default_guid
        variable antifraud_guid
        variable antifraud_default_result
        variable antifraud_result
        variable antifraud_default_username
        variable antifraud_username
        variable antifraud_default_license_id
        variable antifraud_license_id
        if {[llength $raw] != 12} { error "invalid Anti-Fraud configuration" }
        lassign $raw enabled profile login alert client_id device_id fingerprint geo guid result username license_id
        if {$enabled ni {0 1} || $login ni {0 1} || $alert ni {0 1}} {
            error "Anti-Fraud enabled and event triggers must be boolean"
        }
        if {$result ni {passed failed}} { error "Anti-Fraud result must be passed or failed" }
        set antifraud_default_enabled $enabled
        set antifraud_enabled $enabled
        set antifraud_default_profile $profile
        set antifraud_profile $profile
        set antifraud_default_login_requested $login
        set antifraud_default_alert_requested $alert
        set antifraud_default_client_id $client_id
        set antifraud_client_id $client_id
        set antifraud_default_device_id $device_id
        set antifraud_device_id $device_id
        set antifraud_default_fingerprint $fingerprint
        set antifraud_fingerprint $fingerprint
        set antifraud_default_geo $geo
        set antifraud_geo $geo
        set antifraud_default_guid $guid
        set antifraud_guid $guid
        set antifraud_default_result $result
        set antifraud_result $result
        set antifraud_default_username $username
        set antifraud_username $username
        set antifraud_default_license_id $license_id
        set antifraud_license_id $license_id
    }

    proc antifraud_set_alert_fields {raw} {
        variable antifraud_default_alert_fields
        variable antifraud_alert_fields
        set allowed {
            alert_additional_info alert_bait_signatures alert_component
            alert_defined_value alert_details alert_device_id alert_expected_value
            alert_fingerprint alert_forbidden_added_element alert_guid alert_html
            alert_http_referrer alert_id alert_min alert_origin alert_resolved_value
            alert_score alert_transaction_data alert_transaction_id alert_type
            alert_username alert_view_id
        }
        if {[llength $raw] % 2} { error "Anti-Fraud alert fields require key/value pairs" }
        foreach {field value} $raw {
            if {$field ni $allowed} { error "unknown Anti-Fraud alert field $field" }
            dict set antifraud_default_alert_fields $field $value
            dict set antifraud_alert_fields $field $value
        }
    }

    proc antifraud_prepare_request {login alert} {
        variable antifraud_default_client_id
        variable antifraud_client_id
        variable antifraud_default_device_id
        variable antifraud_device_id
        variable antifraud_default_fingerprint
        variable antifraud_fingerprint
        variable antifraud_default_geo
        variable antifraud_geo
        variable antifraud_default_guid
        variable antifraud_guid
        variable antifraud_default_result
        variable antifraud_result
        variable antifraud_default_username
        variable antifraud_username
        variable antifraud_alert_fields
        variable antifraud_default_alert_fields
        variable antifraud_login_requested
        variable antifraud_alert_requested
        variable antifraud_alert_disabled
        variable antifraud_log_enabled
        variable antifraud_log_level
        variable antifraud_disabled_features
        if {$login ni {0 1} || $alert ni {0 1}} {
            error "Anti-Fraud event triggers must be boolean"
        }
        set antifraud_client_id $antifraud_default_client_id
        set antifraud_device_id $antifraud_default_device_id
        set antifraud_fingerprint $antifraud_default_fingerprint
        set antifraud_geo $antifraud_default_geo
        set antifraud_guid $antifraud_default_guid
        set antifraud_result $antifraud_default_result
        set antifraud_username $antifraud_default_username
        set antifraud_alert_fields $antifraud_default_alert_fields
        set antifraud_login_requested $login
        set antifraud_alert_requested $alert
        set antifraud_alert_disabled 0
        set antifraud_log_enabled 0
        set antifraud_log_level Informational
        foreach feature {app_layer_encryption auto_transactions injection malware phishing} {
            dict set antifraud_disabled_features $feature 0
        }
    }

    proc antifraud_reset_connection {} {
        variable antifraud_default_enabled
        variable antifraud_enabled
        variable antifraud_default_profile
        variable antifraud_profile
        variable antifraud_default_login_requested
        variable antifraud_default_alert_requested
        set antifraud_enabled $antifraud_default_enabled
        set antifraud_profile $antifraud_default_profile
        antifraud_prepare_request $antifraud_default_login_requested $antifraud_default_alert_requested
    }

    proc _antifraud_require_event {event command} {
        if {$::itest::current_event ne $event} {
            error "$command is valid only during $event"
        }
    }

    proc _antifraud_alert_field {field args} {
        variable antifraud_alert_fields
        _antifraud_require_event ANTIFRAUD_ALERT "ANTIFRAUD::$field"
        if {[llength $args] > 1} { error "ANTIFRAUD::$field accepts an optional value" }
        if {[llength $args] == 1} {
            dict set antifraud_alert_fields $field [lindex $args 0]
            ::itest::log_decision antifraud $field [lindex $args 0]
            return ""
        }
        return [dict get $antifraud_alert_fields $field]
    }

    proc _antifraud_alert_static {field args} {
        variable antifraud_alert_fields
        _antifraud_require_event ANTIFRAUD_ALERT "ANTIFRAUD::$field"
        if {[llength $args] != 0} { error "ANTIFRAUD::$field takes no arguments" }
        return [dict get $antifraud_alert_fields $field]
    }

    proc _antifraud_license_digest {} {
        variable antifraud_license_id
        if {$antifraud_license_id eq ""} { return "" }
        return [format %08x [zlib crc32 $antifraud_license_id]]
    }

    proc antifraud_alert_additional_info {args} { return [_antifraud_alert_field alert_additional_info {*}$args] }
    proc antifraud_alert_component {args} { return [_antifraud_alert_field alert_component {*}$args] }
    proc antifraud_alert_defined_value {args} { return [_antifraud_alert_field alert_defined_value {*}$args] }
    proc antifraud_alert_details {args} { return [_antifraud_alert_field alert_details {*}$args] }
    proc antifraud_alert_expected_value {args} { return [_antifraud_alert_field alert_expected_value {*}$args] }
    proc antifraud_alert_fingerprint {args} { return [_antifraud_alert_field alert_fingerprint {*}$args] }
    proc antifraud_alert_html {args} { return [_antifraud_alert_field alert_html {*}$args] }
    proc antifraud_alert_http_referrer {args} { return [_antifraud_alert_field alert_http_referrer {*}$args] }
    proc antifraud_alert_id {args} { return [_antifraud_alert_field alert_id {*}$args] }
    proc antifraud_alert_min {args} { return [_antifraud_alert_field alert_min {*}$args] }
    proc antifraud_alert_origin {args} { return [_antifraud_alert_field alert_origin {*}$args] }
    proc antifraud_alert_resolved_value {args} { return [_antifraud_alert_field alert_resolved_value {*}$args] }
    proc antifraud_alert_score {args} { return [_antifraud_alert_field alert_score {*}$args] }
    proc antifraud_alert_transaction_data {args} { return [_antifraud_alert_field alert_transaction_data {*}$args] }
    proc antifraud_alert_transaction_id {args} { return [_antifraud_alert_field alert_transaction_id {*}$args] }
    proc antifraud_alert_type {args} { return [_antifraud_alert_field alert_type {*}$args] }
    proc antifraud_alert_username {args} { return [_antifraud_alert_field alert_username {*}$args] }
    proc antifraud_alert_view_id {args} { return [_antifraud_alert_field alert_view_id {*}$args] }
    proc antifraud_alert_bait_signatures {args} { return [_antifraud_alert_static alert_bait_signatures {*}$args] }
    proc antifraud_alert_device_id {args} { return [_antifraud_alert_static alert_device_id {*}$args] }
    proc antifraud_alert_forbidden_added_element {args} { return [_antifraud_alert_static alert_forbidden_added_element {*}$args] }
    proc antifraud_alert_guid {args} { return [_antifraud_alert_static alert_guid {*}$args] }
    proc antifraud_alert_license_id {args} {
        _antifraud_require_event ANTIFRAUD_ALERT "ANTIFRAUD::alert_license_id"
        if {[llength $args] != 0} { error "ANTIFRAUD::alert_license_id takes no arguments" }
        return [_antifraud_license_digest]
    }

    proc antifraud_client_id {args} {
        variable antifraud_client_id
        if {[llength $args] != 0} { error "ANTIFRAUD::client_id takes no arguments" }
        return $antifraud_client_id
    }
    proc antifraud_device_id {args} {
        variable antifraud_device_id
        if {[llength $args] != 0} { error "ANTIFRAUD::device_id takes no arguments" }
        return $antifraud_device_id
    }
    proc antifraud_fingerprint {args} {
        variable antifraud_fingerprint
        _antifraud_require_event ANTIFRAUD_LOGIN "ANTIFRAUD::fingerprint"
        if {[llength $args] != 0} { error "ANTIFRAUD::fingerprint takes no arguments" }
        return $antifraud_fingerprint
    }
    proc antifraud_geo {args} {
        variable antifraud_geo
        if {[llength $args] != 0} { error "ANTIFRAUD::geo takes no arguments" }
        return $antifraud_geo
    }
    proc antifraud_guid {args} {
        variable antifraud_guid
        _antifraud_require_event ANTIFRAUD_LOGIN "ANTIFRAUD::guid"
        if {[llength $args] != 0} { error "ANTIFRAUD::guid takes no arguments" }
        return $antifraud_guid
    }
    proc antifraud_result {args} {
        variable antifraud_result
        if {[llength $args] != 0} { error "ANTIFRAUD::result takes no arguments" }
        return $antifraud_result
    }
    proc antifraud_username {args} {
        variable antifraud_username
        _antifraud_require_event ANTIFRAUD_LOGIN "ANTIFRAUD::username"
        if {[llength $args] > 1} { error "ANTIFRAUD::username accepts an optional alias" }
        if {[llength $args] == 1} {
            set antifraud_username [lindex $args 0]
            ::itest::log_decision antifraud username $antifraud_username
        }
        return $antifraud_username
    }

    proc antifraud_disable {args} {
        variable antifraud_enabled
        if {[llength $args] != 0} { error "ANTIFRAUD::disable takes no arguments" }
        set antifraud_enabled 0
        ::itest::log_decision antifraud disable
        return ""
    }
    proc antifraud_enable {args} {
        variable antifraud_enabled
        variable antifraud_default_profile
        variable antifraud_profile
        if {[llength $args] > 1} { error "ANTIFRAUD::enable accepts an optional profile" }
        set antifraud_enabled 1
        if {[llength $args] == 1} {
            set antifraud_profile [lindex $args 0]
        } else {
            set antifraud_profile $antifraud_default_profile
        }
        ::itest::log_decision antifraud enable $antifraud_profile
        return ""
    }
    proc antifraud_enable_log {args} {
        variable antifraud_log_enabled
        variable antifraud_log_level
        if {[llength $args] > 1} { error "ANTIFRAUD::enable_log accepts an optional log level" }
        set antifraud_log_level Informational
        if {[llength $args] == 1} { set antifraud_log_level [lindex $args 0] }
        if {$antifraud_log_level ni {Error Warning Notice Informational Debug}} {
            error "ANTIFRAUD::enable_log has an invalid log level"
        }
        set antifraud_log_enabled 1
        ::itest::log_decision antifraud enable_log $antifraud_log_level
        return ""
    }
    proc antifraud_disable_alert {args} {
        variable antifraud_alert_disabled
        if {[llength $args] != 0} { error "ANTIFRAUD::disable_alert takes no arguments" }
        set antifraud_alert_disabled 1
        ::itest::log_decision antifraud disable_alert
        return ""
    }
    proc _antifraud_disable_feature {feature command args} {
        variable antifraud_disabled_features
        if {[llength $args] != 0} { error "$command takes no arguments" }
        if {![_profile_enabled FASTHTTP]} {
            error "$command requires the FASTHTTP profile"
        }
        dict set antifraud_disabled_features $feature 1
        ::itest::log_decision antifraud $feature disabled
        return ""
    }
    proc antifraud_disable_app_layer_encryption {args} {
        return [_antifraud_disable_feature app_layer_encryption ANTIFRAUD::disable_app_layer_encryption {*}$args]
    }
    proc antifraud_disable_auto_transactions {args} {
        return [_antifraud_disable_feature auto_transactions ANTIFRAUD::disable_auto_transactions {*}$args]
    }
    proc antifraud_disable_injection {args} {
        return [_antifraud_disable_feature injection ANTIFRAUD::disable_injection {*}$args]
    }
    proc antifraud_disable_malware {args} {
        return [_antifraud_disable_feature malware ANTIFRAUD::disable_malware {*}$args]
    }
    proc antifraud_disable_phishing {args} {
        return [_antifraud_disable_feature phishing ANTIFRAUD::disable_phishing {*}$args]
    }

    proc antifraud_should_login {} {
        variable antifraud_enabled
        variable antifraud_login_requested
        return [expr {$antifraud_enabled && $antifraud_login_requested}]
    }

    proc antifraud_should_alert {} {
        variable antifraud_enabled
        variable antifraud_alert_requested
        variable antifraud_alert_disabled
        return [expr {$antifraud_enabled && $antifraud_alert_requested && !$antifraud_alert_disabled}]
    }

    proc antifraud_snapshot {} {
        variable antifraud_enabled
        variable antifraud_profile
        variable antifraud_client_id
        variable antifraud_device_id
        variable antifraud_fingerprint
        variable antifraud_geo
        variable antifraud_guid
        variable antifraud_result
        variable antifraud_username
        variable antifraud_license_id
        variable antifraud_alert_fields
        variable antifraud_login_requested
        variable antifraud_alert_requested
        variable antifraud_alert_disabled
        variable antifraud_log_enabled
        variable antifraud_log_level
        variable antifraud_disabled_features
        set result [list \
            enabled $antifraud_enabled profile $antifraud_profile \
            client_id $antifraud_client_id device_id $antifraud_device_id \
            fingerprint $antifraud_fingerprint geo $antifraud_geo guid $antifraud_guid \
            result $antifraud_result username $antifraud_username \
            license_id $antifraud_license_id login_requested $antifraud_login_requested \
            alert_requested $antifraud_alert_requested alert_disabled $antifraud_alert_disabled \
            log_enabled $antifraud_log_enabled log_level $antifraud_log_level]
        foreach field [lsort -dictionary [dict keys $antifraud_alert_fields]] {
            lappend result $field [dict get $antifraud_alert_fields $field]
        }
        lappend result alert_license_id [_antifraud_license_digest]
        foreach feature {app_layer_encryption auto_transactions injection malware phishing} {
            lappend result disable_$feature [dict get $antifraud_disabled_features $feature]
        }
        return $result
    }

    proc auth_configure {raw response_data} {
        variable auth_default_enabled
        variable auth_enabled
        variable auth_default_result
        variable auth_configured_result
        variable auth_default_type
        variable auth_type
        variable auth_default_service
        variable auth_service
        variable auth_default_prompt
        variable auth_prompt
        variable auth_default_prompt_style
        variable auth_prompt_style
        variable auth_default_credential_type
        variable auth_credential_type
        variable auth_default_ldap_status
        variable auth_ldap_status
        variable auth_default_ldap_username
        variable auth_ldap_username
        variable auth_default_response_data
        if {[llength $raw] != 9} { error "invalid AUTH configuration" }
        lassign $raw enabled result type service prompt prompt_style credential_type ldap_status ldap_username
        if {$enabled ni {0 1}} { error "AUTH enabled state must be boolean" }
        if {$result ni {success failure error wantcredential}} {
            error "AUTH result must be success, failure, error, or wantcredential"
        }
        if {$prompt_style ni {echo_on echo_off unknown}} {
            error "AUTH prompt style is invalid"
        }
        if {[llength $response_data] % 2} { error "AUTH response data requires key/value pairs" }
        set normalised_response [dict create]
        foreach {key value} $response_data {
            if {$key eq ""} { error "AUTH response data keys cannot be empty" }
            dict set normalised_response $key $value
        }
        set auth_default_enabled $enabled
        set auth_enabled $enabled
        set auth_default_result $result
        set auth_configured_result $result
        set auth_default_type $type
        set auth_type $type
        set auth_default_service $service
        set auth_service $service
        set auth_default_prompt $prompt
        set auth_prompt $prompt
        set auth_default_prompt_style $prompt_style
        set auth_prompt_style $prompt_style
        set auth_default_credential_type $credential_type
        set auth_credential_type $credential_type
        set auth_default_ldap_status $ldap_status
        set auth_ldap_status $ldap_status
        set auth_default_ldap_username $ldap_username
        set auth_ldap_username $ldap_username
        set auth_default_response_data $normalised_response
    }

    proc auth_reset_connection {} {
        variable auth_default_enabled
        variable auth_enabled
        variable auth_default_type
        variable auth_type
        variable auth_default_service
        variable auth_service
        variable auth_default_prompt
        variable auth_prompt
        variable auth_default_prompt_style
        variable auth_prompt_style
        variable auth_default_credential_type
        variable auth_credential_type
        variable auth_default_ldap_status
        variable auth_ldap_status
        variable auth_default_ldap_username
        variable auth_ldap_username
        variable auth_sessions
        variable auth_next_id
        variable auth_last_event_session_id
        variable auth_last_event
        variable auth_current_session_id
        set auth_enabled $auth_default_enabled
        set auth_type $auth_default_type
        set auth_service $auth_default_service
        set auth_prompt $auth_default_prompt
        set auth_prompt_style $auth_default_prompt_style
        set auth_credential_type $auth_default_credential_type
        set auth_ldap_status $auth_default_ldap_status
        set auth_ldap_username $auth_default_ldap_username
        set auth_sessions [dict create]
        set auth_next_id 0
        set auth_last_event_session_id ""
        set auth_last_event ""
        set auth_current_session_id ""
    }

    proc _auth_require_profile {command} {
        if {![_profile_enabled AUTH]} { error "$command requires the AUTH profile" }
    }

    proc _auth_require_enabled {command} {
        variable auth_enabled
        _auth_require_profile $command
        if {!$auth_enabled} { error "$command is disabled" }
    }

    proc _auth_require_session {auth_id command} {
        variable auth_sessions
        _auth_require_profile $command
        if {$auth_id eq "" || ![dict exists $auth_sessions $auth_id]} {
            error "$command received an unknown AUTH_ID"
        }
        set session [dict get $auth_sessions $auth_id]
        if {![dict get $session valid]} {
            error "$command received an invalid AUTH_ID"
        }
        return $session
    }

    proc _auth_set_session {auth_id session} {
        variable auth_sessions
        dict set auth_sessions $auth_id $session
    }

    proc _auth_event {event auth_id} {
        variable auth_sessions
        variable auth_last_event_session_id
        variable auth_last_event
        variable auth_current_session_id
        if {$auth_id ne "" && [dict exists $auth_sessions $auth_id]} {
            set session [dict get $auth_sessions $auth_id]
            dict set session last_event $event
            dict set auth_sessions $auth_id $session
        }
        set previous_event $::itest::current_event
        set previous_session $auth_current_session_id
        set auth_last_event_session_id $auth_id
        set auth_last_event $event
        set auth_current_session_id $auth_id
        set rc [catch {::itest::fire_event $event} result options]
        set ::itest::current_event $previous_event
        set auth_current_session_id $previous_session
        if {$rc} { return -options $options $result }
        return $result
    }

    proc _auth_status_for_session {auth_id} {
        variable auth_sessions
        if {$auth_id eq "" || ![dict exists $auth_sessions $auth_id]} { return -1 }
        set session [dict get $auth_sessions $auth_id]
        if {![dict get $session valid]} { return -1 }
        return [dict get $session status]
    }

    proc _auth_session_from_args {args command} {
        variable auth_current_session_id
        variable auth_last_event_session_id
        if {[llength $args] > 1} { error "$command accepts an optional AUTH_ID" }
        if {[llength $args] == 1} { return [lindex $args 0] }
        if {$auth_current_session_id ne ""} { return $auth_current_session_id }
        return $auth_last_event_session_id
    }

    proc _auth_complete {auth_id status event} {
        variable auth_sessions
        set session [_auth_require_session $auth_id AUTH::authenticate]
        dict set session status $status
        dict set session in_progress 0
        dict set session last_event AUTH_RESULT
        _auth_set_session $auth_id $session
        if {[dict get $session subscribed]} { _auth_event AUTH_RESULT $auth_id }
        _auth_event $event $auth_id
    }

    proc auth_start {args} {
        variable auth_sessions
        variable auth_next_id
        variable auth_type
        variable auth_service
        variable auth_prompt
        variable auth_prompt_style
        variable auth_credential_type
        variable auth_ldap_status
        variable auth_ldap_username
        _auth_require_enabled AUTH::start
        if {[llength $args] != 2} { error "AUTH::start requires TYPE and SERVICE" }
        incr auth_next_id
        set auth_id "auth-$auth_next_id"
        set session [dict create \
            valid 1 type [lindex $args 0] service [lindex $args 1] status 2 \
            in_progress 0 subscribed 0 username_credential "" password_credential "" \
            cert_credential "" cert_issuer_credential "" response_data {} \
            prompt $auth_prompt prompt_style $auth_prompt_style \
            credential_type $auth_credential_type ldap_status $auth_ldap_status \
            ldap_username $auth_ldap_username last_event ""]
        dict set auth_sessions $auth_id $session
        ::itest::log_decision auth start [list $auth_id [lindex $args 0] [lindex $args 1]]
        return $auth_id
    }

    proc auth_username_credential {args} {
        if {[llength $args] != 2} { error "AUTH::username_credential requires AUTH_ID and credential" }
        set auth_id [lindex $args 0]
        set session [_auth_require_session $auth_id AUTH::username_credential]
        dict set session username_credential [lindex $args 1]
        dict set session last_event ""
        _auth_set_session $auth_id $session
        ::itest::log_decision auth username_credential $auth_id
        return ""
    }

    proc auth_password_credential {args} {
        if {[llength $args] != 2} { error "AUTH::password_credential requires AUTH_ID and credential" }
        if {![_profile_enabled HTTP]} { error "AUTH::password_credential requires the HTTP profile" }
        set auth_id [lindex $args 0]
        set session [_auth_require_session $auth_id AUTH::password_credential]
        dict set session password_credential [lindex $args 1]
        dict set session last_event ""
        _auth_set_session $auth_id $session
        ::itest::log_decision auth password_credential $auth_id
        return ""
    }

    proc auth_cert_credential {args} {
        if {[llength $args] != 2} { error "AUTH::cert_credential requires AUTH_ID and certificate" }
        set auth_id [lindex $args 0]
        set session [_auth_require_session $auth_id AUTH::cert_credential]
        dict set session cert_credential [lindex $args 1]
        dict set session last_event ""
        _auth_set_session $auth_id $session
        ::itest::log_decision auth cert_credential $auth_id
        return ""
    }

    proc auth_cert_issuer_credential {args} {
        if {[llength $args] != 2} { error "AUTH::cert_issuer_credential requires AUTH_ID and certificate" }
        set auth_id [lindex $args 0]
        set session [_auth_require_session $auth_id AUTH::cert_issuer_credential]
        dict set session cert_issuer_credential [lindex $args 1]
        dict set session last_event ""
        _auth_set_session $auth_id $session
        ::itest::log_decision auth cert_issuer_credential $auth_id
        return ""
    }

    proc auth_authenticate {args} {
        variable auth_configured_result
        if {[llength $args] != 1} { error "AUTH::authenticate requires AUTH_ID" }
        if {![_profile_enabled HTTP]} { error "AUTH::authenticate requires the HTTP profile" }
        _auth_require_enabled AUTH::authenticate
        set auth_id [lindex $args 0]
        set session [_auth_require_session $auth_id AUTH::authenticate]
        if {[dict get $session in_progress]} { error "AUTH::authenticate is already in progress" }
        dict set session in_progress 1
        dict set session last_event ""
        dict set session response_data $::itest::semantic::auth_default_response_data
        _auth_set_session $auth_id $session
        switch -- $auth_configured_result {
            success { _auth_complete $auth_id 0 AUTH_SUCCESS }
            failure { _auth_complete $auth_id 1 AUTH_FAILURE }
            error { _auth_complete $auth_id -1 AUTH_ERROR }
            wantcredential {
                dict set session last_event AUTH_WANTCREDENTIAL
                _auth_set_session $auth_id $session
                _auth_event AUTH_WANTCREDENTIAL $auth_id
            }
        }
        ::itest::log_decision auth authenticate $auth_id
        return ""
    }

    proc auth_authenticate_continue {args} {
        if {[llength $args] != 2} { error "AUTH::authenticate_continue requires AUTH_ID and RESPONSE" }
        set auth_id [lindex $args 0]
        set session [_auth_require_session $auth_id AUTH::authenticate_continue]
        if {![dict get $session in_progress] || [dict get $session last_event] ne "AUTH_WANTCREDENTIAL"} {
            error "AUTH::authenticate_continue requires the most recent AUTH_WANTCREDENTIAL event"
        }
        _auth_complete $auth_id 0 AUTH_SUCCESS
        ::itest::log_decision auth authenticate_continue $auth_id
        return ""
    }

    proc auth_abort {args} {
        if {[llength $args] != 1} { error "AUTH::abort requires AUTH_ID" }
        variable auth_sessions
        set auth_id [lindex $args 0]
        set session [_auth_require_session $auth_id AUTH::abort]
        set active [dict get $session in_progress]
        dict set session status 1
        dict set session in_progress 0
        dict set session last_event AUTH_FAILURE
        _auth_set_session $auth_id $session
        if {$active} { _auth_event AUTH_FAILURE $auth_id }
        dict set session valid 0
        _auth_set_session $auth_id $session
        ::itest::log_decision auth abort $auth_id
        return ""
    }

    proc auth_status {args} {
        _auth_require_profile AUTH::status
        set auth_id [_auth_session_from_args $args AUTH::status]
        return [_auth_status_for_session $auth_id]
    }

    proc auth_last_event_session_id {args} {
        variable auth_last_event_session_id
        _auth_require_profile AUTH::last_event_session_id
        if {[llength $args] != 0} { error "AUTH::last_event_session_id takes no arguments" }
        return $auth_last_event_session_id
    }

    proc auth_subscribe {args} {
        if {[llength $args] != 1} { error "AUTH::subscribe requires AUTH_ID" }
        set auth_id [lindex $args 0]
        set session [_auth_require_session $auth_id AUTH::subscribe]
        dict set session subscribed 1
        _auth_set_session $auth_id $session
        ::itest::log_decision auth subscribe $auth_id
        return ""
    }

    proc auth_unsubscribe {args} {
        if {[llength $args] != 1} { error "AUTH::unsubscribe requires AUTH_ID" }
        set auth_id [lindex $args 0]
        set session [_auth_require_session $auth_id AUTH::unsubscribe]
        dict set session subscribed 0
        _auth_set_session $auth_id $session
        ::itest::log_decision auth unsubscribe $auth_id
        return ""
    }

    proc auth_response_data {args} {
        variable auth_current_session_id
        variable auth_last_event_session_id
        set auth_id [_auth_session_from_args $args AUTH::response_data]
        if {$auth_id eq ""} { return "" }
        set session [_auth_require_session $auth_id AUTH::response_data]
        if {![dict get $session subscribed]} { return "" }
        set response [dict get $session response_data]
        set result [list]
        dict for {key value} $response { lappend result $key $value }
        return $result
    }

    proc auth_ssl_cc_ldap_status {args} {
        if {[llength $args] != 1} { error "AUTH::ssl_cc_ldap_status requires AUTH_ID" }
        set session [_auth_require_session [lindex $args 0] AUTH::ssl_cc_ldap_status]
        return [dict get $session ldap_status]
    }

    proc auth_ssl_cc_ldap_username {args} {
        if {[llength $args] != 1} { error "AUTH::ssl_cc_ldap_username requires AUTH_ID" }
        set session [_auth_require_session [lindex $args 0] AUTH::ssl_cc_ldap_username]
        return [dict get $session ldap_username]
    }

    proc _auth_wantcredential_field {field command args} {
        if {[llength $args] != 1} { error "$command requires AUTH_ID" }
        set session [_auth_require_session [lindex $args 0] $command]
        return [dict get $session $field]
    }
    proc auth_wantcredential_prompt {args} {
        return [_auth_wantcredential_field prompt AUTH::wantcredential_prompt {*}$args]
    }
    proc auth_wantcredential_prompt_style {args} {
        return [_auth_wantcredential_field prompt_style AUTH::wantcredential_prompt_style {*}$args]
    }
    proc auth_wantcredential_type {args} {
        return [_auth_wantcredential_field credential_type AUTH::wantcredential_type {*}$args]
    }

    proc auth_snapshot {} {
        variable auth_enabled
        variable auth_configured_result
        variable auth_type
        variable auth_service
        variable auth_prompt
        variable auth_prompt_style
        variable auth_credential_type
        variable auth_ldap_status
        variable auth_ldap_username
        variable auth_sessions
        variable auth_last_event_session_id
        variable auth_last_event
        set result [list enabled $auth_enabled result $auth_configured_result \
            type $auth_type service $auth_service prompt $auth_prompt \
            prompt_style $auth_prompt_style credential_type $auth_credential_type \
            ldap_status $auth_ldap_status ldap_username $auth_ldap_username \
            last_event_session_id $auth_last_event_session_id last_event $auth_last_event \
            session_count [dict size $auth_sessions]]
        set sessions [list]
        foreach auth_id [lsort -dictionary [dict keys $auth_sessions]] {
            set session [dict get $auth_sessions $auth_id]
            lappend sessions [list $auth_id [dict get $session valid] [dict get $session status] \
                [dict get $session in_progress] [dict get $session subscribed] [dict get $session last_event]]
        }
        lappend result sessions $sessions
        return $result
    }

    proc aaa_configure {raw} {
        variable aaa_default_enabled
        variable aaa_enabled
        variable aaa_default_auth_result
        variable aaa_auth_result
        variable aaa_default_acct_result
        variable aaa_acct_result
        if {[llength $raw] != 3} { error "invalid AAA configuration" }
        lassign $raw enabled auth_result acct_result
        if {$enabled ni {0 1}} { error "AAA enabled state must be boolean" }
        foreach {name value} [list auth_result $auth_result acct_result $acct_result] {
            if {$value ni {OK FAIL INPROGRESS ERROR}} {
                error "AAA result must be OK, FAIL, INPROGRESS, or ERROR"
            }
        }
        set aaa_default_enabled $enabled
        set aaa_enabled $enabled
        set aaa_default_auth_result $auth_result
        set aaa_auth_result $auth_result
        set aaa_default_acct_result $acct_result
        set aaa_acct_result $acct_result
    }

    proc aaa_reset_connection {} {
        variable aaa_default_enabled
        variable aaa_enabled
        variable aaa_default_auth_result
        variable aaa_auth_result
        variable aaa_default_acct_result
        variable aaa_acct_result
        variable aaa_requests
        variable aaa_next_id
        set aaa_enabled $aaa_default_enabled
        set aaa_auth_result $aaa_default_auth_result
        set aaa_acct_result $aaa_default_acct_result
        set aaa_requests [dict create]
        set aaa_next_id 0
    }

    proc _aaa_require_enabled {command} {
        variable aaa_enabled
        if {!$aaa_enabled} { error "$command is disabled" }
    }

    proc _aaa_new_request {kind result virtual_server username} {
        variable aaa_requests
        variable aaa_next_id
        incr aaa_next_id
        set request_id "aaa-$aaa_next_id"
        set request [dict create \
            kind $kind result $result valid 1 virtual_server $virtual_server \
            username $username]
        dict set aaa_requests $request_id $request
        return $request_id
    }

    proc _aaa_result {request_id kind command} {
        variable aaa_requests
        if {$request_id eq "" || ![dict exists $aaa_requests $request_id]} {
            return ERROR
        }
        set request [dict get $aaa_requests $request_id]
        if {![dict get $request valid] || [dict get $request kind] ne $kind} {
            return ERROR
        }
        return [dict get $request result]
    }

    proc aaa_auth_send {args} {
        variable aaa_auth_result
        _aaa_require_enabled AAA::auth_send
        if {[llength $args] ni {2 3}} {
            error "AAA::auth_send requires VIRTUAL_SERVER USERNAME and optional PASSWORD"
        }
        set username [lindex $args 1]
        set password_present [expr {[llength $args] == 3}]
        set request_id [_aaa_new_request auth $aaa_auth_result [lindex $args 0] $username]
        ::itest::log_decision aaa auth_send [list $request_id [lindex $args 0] $username $password_present]
        return $request_id
    }

    proc aaa_acct_send {args} {
        variable aaa_acct_result
        _aaa_require_enabled AAA::acct_send
        if {[llength $args] < 1 || ([llength $args] - 1) % 2} {
            error "AAA::acct_send requires VIRTUAL_SERVER and key/value attributes"
        }
        set username ""
        set allowed_attributes {
            user-name framed-ip-address framed-ipv6-prefix event-timestamp
            acct-status-type acct-session-id acct-input-octets acct-output-octets
            3gpp-imsi 3gpp-imeisv 3gpp-user-location-info
        }
        foreach {key value} [lrange $args 1 end] {
            if {$key ni $allowed_attributes} {
                error "AAA::acct_send received unsupported attribute $key"
            }
            if {$key eq "user-name"} { set username $value }
        }
        set request_id [_aaa_new_request acct $aaa_acct_result [lindex $args 0] $username]
        ::itest::log_decision aaa acct_send [list $request_id [lindex $args 0]]
        return $request_id
    }

    proc aaa_auth_result {args} {
        if {[llength $args] != 1} { error "AAA::auth_result requires AAA_REQUEST_ID" }
        return [_aaa_result [lindex $args 0] auth AAA::auth_result]
    }

    proc aaa_acct_result {args} {
        if {[llength $args] != 1} { error "AAA::acct_result requires AAA_REQUEST_ID" }
        return [_aaa_result [lindex $args 0] acct AAA::acct_result]
    }

    proc aaa_snapshot {} {
        variable aaa_enabled
        variable aaa_auth_result
        variable aaa_acct_result
        variable aaa_requests
        set result [list enabled $aaa_enabled auth_result $aaa_auth_result \
            acct_result $aaa_acct_result request_count [dict size $aaa_requests]]
        set requests [list]
        foreach request_id [lsort -dictionary [dict keys $aaa_requests]] {
            set request [dict get $aaa_requests $request_id]
            lappend requests [list $request_id [dict get $request kind] \
                [dict get $request result] [dict get $request valid] \
                [dict get $request virtual_server] [dict get $request username]]
        }
        lappend result requests $requests
        return $result
    }

    proc access_configure {raw acl_lookup acl_matched session_data perflow} {
        variable access_default_enabled
        variable access_enabled
        variable access_default_acl_result
        variable access_acl_result
        variable access_default_acl_lookup
        variable access_acl_lookup
        variable access_default_acl_matched
        variable access_acl_matched
        variable access_default_policy_result
        variable access_policy_result
        variable access_default_policy_agent_id
        variable access_policy_agent_id
        variable access_default_policy_uri
        variable access_policy_uri
        variable access_default_flow_id
        variable access_flow_id
        variable access_ephemeral_auth_password
        variable access_default_session_data
        variable access_session_data
        variable access_default_perflow
        variable access_perflow
        if {[llength $raw] != 7} { error "invalid ACCESS configuration" }
        lassign $raw enabled acl_result policy_result policy_agent_id policy_uri flow_id ephemeral_password
        if {$enabled ni {0 1}} { error "ACCESS enabled state must be boolean" }
        if {$acl_result ni {Allow Reject}} { error "ACCESS ACL result is invalid" }
        if {$policy_result ni {allow deny redirect}} { error "ACCESS policy result is invalid" }
        if {$policy_uri ni {0 1}} { error "ACCESS policy URI state must be boolean" }
        if {$ephemeral_password eq ""} { error "ACCESS ephemeral auth password cannot be empty" }
        if {[llength $session_data] % 2 || [llength $perflow] % 2} {
            error "ACCESS data requires key/value pairs"
        }
        set access_default_enabled $enabled
        set access_enabled $enabled
        set access_default_acl_result $acl_result
        set access_acl_result $acl_result
        set access_default_acl_lookup $acl_lookup
        set access_acl_lookup $acl_lookup
        set access_default_acl_matched $acl_matched
        set access_acl_matched $acl_matched
        set access_default_policy_result $policy_result
        set access_policy_result $policy_result
        set access_default_policy_agent_id $policy_agent_id
        set access_policy_agent_id $policy_agent_id
        set access_default_policy_uri $policy_uri
        set access_policy_uri $policy_uri
        set access_default_flow_id $flow_id
        set access_flow_id $flow_id
        set access_ephemeral_auth_password $ephemeral_password
        set access_default_session_data [dict create {*}$session_data]
        set access_session_data $access_default_session_data
        set access_default_perflow [dict create {*}$perflow]
        set access_perflow $access_default_perflow
    }

    proc access_reset_connection {} {
        variable access_default_enabled
        variable access_enabled
        variable access_default_acl_result
        variable access_acl_result
        variable access_default_acl_lookup
        variable access_acl_lookup
        variable access_default_acl_matched
        variable access_acl_matched
        variable access_acl_evaluated
        variable access_default_policy_result
        variable access_policy_result
        variable access_default_policy_agent_id
        variable access_policy_agent_id
        variable access_default_policy_uri
        variable access_policy_uri
        variable access_default_flow_id
        variable access_flow_id
        variable access_request_enabled
        variable access_restrict_irule_events
        variable access_default_session_data
        variable access_session_data
        variable access_default_perflow
        variable access_perflow
        variable access_sessions
        variable access_current_sid
        variable access_next_sid
        variable access_ephemeral
        variable access_ephemeral_next
        variable access_oauth_next
        variable access_user_keys
        variable access_saml
        set access_enabled $access_default_enabled
        set access_acl_result $access_default_acl_result
        set access_acl_lookup $access_default_acl_lookup
        set access_acl_matched $access_default_acl_matched
        set access_acl_evaluated {}
        set access_policy_result $access_default_policy_result
        set access_policy_agent_id $access_default_policy_agent_id
        set access_policy_uri $access_default_policy_uri
        set access_flow_id $access_default_flow_id
        set access_request_enabled 1
        set access_restrict_irule_events 1
        set access_session_data $access_default_session_data
        set access_perflow $access_default_perflow
        set access_sessions [dict create]
        set access_current_sid ""
        set access_next_sid 0
        set access_ephemeral [dict create]
        set access_ephemeral_next 0
        set access_oauth_next 0
        set access_user_keys [dict create]
        set access_saml [dict create authn "" assertion "" slo_req "" slo_resp ""]
    }

    proc access_prepare_request {} {
        variable access_request_enabled
        variable access_acl_evaluated
        set access_request_enabled 1
        set access_acl_evaluated {}
    }

    proc _access_current_sid {command args} {
        variable access_current_sid
        if {[llength $args] > 0} {
            if {[llength $args] != 2 || [lindex $args 0] ne "-sid"} {
                error "$command accepts optional -sid SESSION_ID"
            }
            return [lindex $args 1]
        }
        return $access_current_sid
    }

    proc _access_require_enabled {command} {
        variable access_enabled
        if {![_profile_enabled ACCESS]} { error "$command requires the ACCESS profile" }
        if {!$access_enabled} { error "$command is disabled" }
    }

    proc _access_require_session {sid command} {
        variable access_sessions
        if {$sid eq "" || ![dict exists $access_sessions $sid]} {
            error "$command received an unknown ACCESS session"
        }
        set session [dict get $access_sessions $sid]
        if {![dict get $session valid]} { error "$command received an invalid ACCESS session" }
        return $session
    }

    proc _access_set_session {sid session} {
        variable access_sessions
        dict set access_sessions $sid $session
    }

    proc _access_event {event sid} {
        variable access_current_sid
        set previous_sid $access_current_sid
        set access_current_sid $sid
        set rc [catch {::itest::fire_event $event} result options]
        set access_current_sid $previous_sid
        if {$rc} { return -options $options $result }
        return $result
    }

    proc _access_safe_data {data} {
        set result [dict create]
        dict for {key value} $data {
            if {[regexp -nocase {(password|passwd|secret|token)} $key]} {
                set value "<redacted>"
            }
            dict set result $key $value
        }
        return $result
    }

    proc access_acl {args} {
        variable access_acl_result
        variable access_acl_lookup
        variable access_acl_matched
        variable access_acl_evaluated
        _access_require_enabled ACCESS::acl
        if {[llength $args] < 1} { error "ACCESS::acl requires result, lookup, matched, or eval" }
        switch -exact -- [lindex $args 0] {
            result { return $access_acl_result }
            lookup { return $access_acl_lookup }
            matched { return $access_acl_matched }
            eval {
                if {[llength $args] != 2 || [lindex $args 1] eq ""} {
                    error "ACCESS::acl eval requires ACL_NAME"
                }
                lappend access_acl_evaluated [lindex $args 1]
                ::itest::log_decision access acl_eval [lindex $args 1]
                return $access_acl_result
            }
            default { error "ACCESS::acl requires result, lookup, matched, or eval ACL_NAME" }
        }
    }

    proc access_disable {args} {
        variable access_request_enabled
        _access_require_enabled ACCESS::disable
        if {[llength $args] != 0} { error "ACCESS::disable takes no arguments" }
        set access_request_enabled 0
        ::itest::log_decision access disable
        return ""
    }

    proc access_enable {args} {
        variable access_request_enabled
        _access_require_enabled ACCESS::enable
        if {[llength $args] != 0} { error "ACCESS::enable takes no arguments" }
        set access_request_enabled 1
        ::itest::log_decision access enable
        return ""
    }

    proc access_flowid {args} {
        variable access_flow_id
        _access_require_enabled ACCESS::flowid
        if {[llength $args] > 1} { error "ACCESS::flowid accepts an optional flow ID" }
        if {[llength $args] == 1} { set access_flow_id [lindex $args 0] }
        if {$access_flow_id eq ""} { set access_flow_id flow-1 }
        ::itest::log_decision access flowid $access_flow_id
        return $access_flow_id
    }

    proc access_log {args} {
        _access_require_enabled ACCESS::log
        if {[llength $args] ni {1 2}} { error "ACCESS::log requires a message and optional component/level" }
        set message [lindex $args end]
        ::state::log_capture::add "access" "notice" $message
        ::itest::log_decision access log [lindex $args 0]
        return ""
    }

    proc access_perflow {args} {
        variable access_perflow
        _access_require_enabled ACCESS::perflow
        if {[llength $args] < 2} { error "ACCESS::perflow requires get/set and a key" }
        set operation [lindex $args 0]
        set key [lindex $args 1]
        switch -exact -- $operation {
            get {
                if {[llength $args] != 2} { error "ACCESS::perflow get requires KEY" }
                if {[dict exists $access_perflow $key]} { return [dict get $access_perflow $key] }
                return ""
            }
            set {
                if {[llength $args] != 3 || $key ni {perflow.custom perflow.scratchpad}} {
                    error "ACCESS::perflow set supports perflow.custom or perflow.scratchpad"
                }
                dict set access_perflow $key [lindex $args 2]
                ::itest::log_decision access perflow_set [list $key [lindex $args 2]]
                return ""
            }
            default { error "ACCESS::perflow requires get or set" }
        }
    }

    proc access_policy {args} {
        variable access_policy_agent_id
        variable access_policy_result
        variable access_policy_uri
        variable access_sessions
        _access_require_enabled ACCESS::policy
        switch -exact -- [lindex $args 0] {
            agent_id {
                if {[llength $args] != 1} { error "ACCESS::policy agent_id takes no arguments" }
                return $access_policy_agent_id
            }
            uri {
                if {[llength $args] != 1} { error "ACCESS::policy uri takes no arguments" }
                return $access_policy_uri
            }
            result {
                set sid [_access_current_sid ACCESS::policy {*}[lrange $args 1 end]]
                if {$sid ne "" && [dict exists $access_sessions $sid]} {
                    return [dict get [dict get $access_sessions $sid] policy_result]
                }
                return $access_policy_result
            }
            evaluate {
                set rest [lrange $args 1 end]
                set sid ""
                set profile ""
                set index 0
                while {$index < [llength $rest]} {
                    set option [lindex $rest $index]
                    if {$option eq "-sid" && $index + 1 < [llength $rest]} {
                        incr index
                        set sid [lindex $rest $index]
                    } elseif {$option eq "-profile" && $index + 1 < [llength $rest]} {
                        incr index
                        set profile [lindex $rest $index]
                    } else { break }
                    incr index
                }
                if {$sid eq "" || $profile eq "" || ![dict exists $access_sessions $sid]} {
                    error "ACCESS::policy evaluate requires -sid SESSION_ID and -profile PROFILE"
                }
                set pairs [lrange $rest $index end]
                if {[llength $pairs] % 2} { error "ACCESS::policy evaluate requires key/value variables" }
                set session [dict get $access_sessions $sid]
                foreach {key value} $pairs { dict set session data $key $value }
                dict set session policy_profile $profile
                dict set session policy_result $access_policy_result
                dict set session state $access_policy_result
                _access_set_session $sid $session
                _access_event ACCESS_POLICY_COMPLETED $sid
                ::itest::log_decision access policy_evaluate [list $sid $profile]
                return ""
            }
            default { error "ACCESS::policy requires agent_id, result, uri, or evaluate" }
        }
    }

    proc access_respond {args} {
        _access_require_enabled ACCESS::respond
        if {[llength $args] < 1 || ![string is integer -strict [lindex $args 0]]} {
            error "ACCESS::respond requires a numeric status code"
        }
        set status [lindex $args 0]
        if {$status < 100 || $status > 599} {
            error "ACCESS::respond status code must be between 100 and 599"
        }
        set content_index [lsearch -exact $args content]
        if {$content_index < 0} { set content_index [lsearch -exact $args -content] }
        set payload ""
        if {$content_index >= 0 && $content_index + 1 < [llength $args]} {
            set payload [lindex $args [expr {$content_index + 1}]]
        }
        set ::state::http::response::status $status
        set ::state::http::response::payload $payload
        set ::state::http::response_committed 1
        ::itest::log_decision access respond [list $status $payload]
        return ""
    }

    proc access_restrict_irule_events {args} {
        variable access_restrict_irule_events
        _access_require_enabled ACCESS::restrict_irule_events
        if {[llength $args] != 1 || [lindex $args 0] ni {enable disable}} {
            error "ACCESS::restrict_irule_events requires enable or disable"
        }
        set access_restrict_irule_events [expr {[lindex $args 0] eq "enable"}]
        ::itest::log_decision access restrict_irule_events $access_restrict_irule_events
        return ""
    }

    proc access_saml {args} {
        variable access_saml
        _access_require_enabled ACCESS::saml
        if {[llength $args] ni {1 2} || [lindex $args 0] ni {authn assertion slo_req slo_resp}} {
            error "ACCESS::saml requires authn, assertion, slo_req, or slo_resp"
        }
        set field [lindex $args 0]
        if {[llength $args] == 2} { dict set access_saml $field [lindex $args 1] }
        return [dict get $access_saml $field]
    }

    proc access_ephemeral_auth {args} {
        variable access_ephemeral_auth_password
        variable access_ephemeral
        variable access_ephemeral_next
        variable access_current_sid
        _access_require_enabled ACCESS::ephemeral-auth
        if {[llength $args] < 1 || [lindex $args 0] ni {create verify}} {
            error "ACCESS::ephemeral-auth requires create or verify"
        }
        set operation [lindex $args 0]
        set rest [lrange $args 1 end]
        if {[llength $rest] % 2} {
            error "ACCESS::ephemeral-auth requires option/value pairs"
        }
        set values [dict create]
        foreach {option value} $rest {
            if {$option ni {-user -auth_cfg -sid -password -protocol}} {
                error "ACCESS::ephemeral-auth received unsupported option $option"
            }
            dict set values [string range $option 1 end] $value
        }
        if {$operation eq "create"} {
            if {![dict exists $values user]} { error "ACCESS::ephemeral-auth create requires -user USER" }
            incr access_ephemeral_next
            set password "${access_ephemeral_auth_password}-${access_ephemeral_next}"
            set sid [expr {[dict exists $values sid] ? [dict get $values sid] : ($access_current_sid ne "" ? $access_current_sid : "sid-ephemeral-$access_ephemeral_next")}]
            dict set access_ephemeral [dict get $values user] [list $password $sid]
            ::itest::log_decision access ephemeral_create [dict get $values user]
            return $password
        }
        if {![dict exists $values user] || ![dict exists $values password] || ![dict exists $values protocol]} {
            error "ACCESS::ephemeral-auth verify requires -user, -password, and -protocol"
        }
        set user [dict get $values user]
        if {[dict exists $access_ephemeral $user]} {
            lassign [dict get $access_ephemeral $user] password sid
            if {$password eq [dict get $values password]} { return $sid }
        }
        return ""
    }

    proc access_oauth {args} {
        variable access_oauth_next
        _access_require_enabled ACCESS::oauth
        if {[llength $args] < 1 || [lindex $args 0] ne "sign"} {
            error "ACCESS::oauth supports sign"
        }
        incr access_oauth_next
        ::itest::log_decision access oauth_sign $access_oauth_next
        return "mock-jws-$access_oauth_next"
    }

    proc access_user {args} {
        variable access_user_keys
        _access_require_enabled ACCESS::user
        if {[llength $args] < 1} { error "ACCESS::user requires a subcommand" }
        switch -exact -- [lindex $args 0] {
            getkey {
                if {[llength $args] != 2} { error "ACCESS::user getkey requires SID_HASH" }
                set key "userkey-[lindex $args 1]"
                dict set access_user_keys $key [lindex $args 1]
                return $key
            }
            getsid {
                if {[llength $args] != 2} { error "ACCESS::user getsid requires KEY" }
                if {[dict exists $access_user_keys [lindex $args 1]]} {
                    return [dict get $access_user_keys [lindex $args 1]]
                }
                return ""
            }
            default { return "" }
        }
    }

    proc access_uuid {args} {
        _access_require_enabled ACCESS::uuid
        if {[llength $args] < 1 || [lindex $args 0] ne "getsid"} {
            error "ACCESS::uuid supports getsid SESSION_ID"
        }
        if {[llength $args] != 2} { error "ACCESS::uuid getsid requires SESSION_ID" }
        return [lindex $args 1]
    }

    proc access_session {args} {
        variable access_sessions
        variable access_current_sid
        variable access_next_sid
        variable access_session_data
        _access_require_enabled ACCESS::session
        if {[llength $args] < 1} { error "ACCESS::session requires a subcommand" }
        set operation [lindex $args 0]
        set rest [lrange $args 1 end]
        switch -exact -- $operation {
            sid {
                if {[llength $rest] != 0} { error "ACCESS::session sid takes no arguments" }
                return $access_current_sid
            }
            create {
                set flow 0
                set timeout 0
                set lifetime 0
                set index 0
                while {$index < [llength $rest]} {
                    set option [lindex $rest $index]
                    if {$option eq "-flow"} { set flow 1
                    } elseif {$option in {-timeout -lifetime} && $index + 1 < [llength $rest]} {
                        incr index
                        set value [lindex $rest $index]
                        if {![string is integer -strict $value] || $value < 0} { error "ACCESS::session create timeout values must be non-negative integers" }
                        if {$option eq "-timeout"} { set timeout $value } else { set lifetime $value }
                    } else { error "ACCESS::session create received an invalid option" }
                    incr index
                }
                incr access_next_sid
                set sid "sid-$access_next_sid"
                set session [dict create valid 1 state allow timeout $timeout lifetime $lifetime remaining $timeout data $access_session_data policy_result allow policy_profile ""]
                dict set access_sessions $sid $session
                if {$flow} { set access_current_sid $sid }
                _access_event ACCESS_SESSION_STARTED $sid
                ::itest::log_decision access session_create [list $sid $flow]
                return $sid
            }
            exists {
                set sid ""
                set state ""
                set index 0
                while {$index < [llength $rest]} {
                    set option [lindex $rest $index]
                    if {$option eq "-sid"} {
                        if {$index + 1 >= [llength $rest]} { error "ACCESS::session exists requires a value after -sid" }
                        incr index
                        set sid [lindex $rest $index]
                    } elseif {$option in {-state_allow -state_deny -state_redirect -state_inprogress}} { set state [string range $option 7 end]
                    } elseif {$sid eq ""} { set sid $option
                    } else { error "ACCESS::session exists received an invalid option" }
                    incr index
                }
                if {$sid eq ""} { set sid $access_current_sid }
                if {![dict exists $access_sessions $sid]} { return FALSE }
                set session [dict get $access_sessions $sid]
                if {![dict get $session valid]} { return FALSE }
                if {$state ne "" && [dict get $session state] ne $state} { return FALSE }
                return TRUE
            }
            remove {
                set sid [_access_current_sid ACCESS::session {*}$rest]
                set session [_access_require_session $sid ACCESS::session]
                _access_event ACCESS_SESSION_CLOSED $sid
                dict unset access_sessions $sid
                if {$access_current_sid eq $sid} { set access_current_sid "" }
                ::itest::log_decision access session_remove $sid
                return ""
            }
            modify {
                set sid ""
                set timeout ""
                set lifetime ""
                set remaining ""
                set index 0
                while {$index < [llength $rest]} {
                    set option [lindex $rest $index]
                    if {$option in {-sid -timeout -lifetime -remaining} && $index + 1 < [llength $rest]} {
                        incr index
                        set value [lindex $rest $index]
                        if {$option ne "-sid" && (![string is integer -strict $value] || $value < 0)} {
                            error "ACCESS::session modify timing values must be non-negative integers"
                        }
                        if {$option eq "-sid"} { set sid $value } elseif {$option eq "-timeout"} { set timeout $value } elseif {$option eq "-lifetime"} { set lifetime $value } else { set remaining $value }
                    } else { error "ACCESS::session modify received an invalid option" }
                    incr index
                }
                if {$sid eq ""} { set sid $access_current_sid }
                if {$lifetime ne "" && $remaining ne ""} { error "ACCESS::session modify cannot use lifetime and remaining together" }
                set session [_access_require_session $sid ACCESS::session]
                if {$timeout ne ""} { dict set session timeout $timeout }
                if {$lifetime ne ""} { dict set session lifetime $lifetime }
                if {$remaining ne ""} { dict set session remaining $remaining }
                _access_set_session $sid $session
                return ""
            }
            data {
                if {[llength $rest] < 1 || [lindex $rest 0] ni {get set}} { error "ACCESS::session data requires get or set" }
                set data_operation [lindex $rest 0]
                set options [lrange $rest 1 end]
                set sid ""
                set key ""
                set value ""
                set value_set 0
                set index 0
                while {$index < [llength $options]} {
                    set option [lindex $options $index]
                    if {$option eq "-sid"} {
                        if {$index + 1 >= [llength $options]} { error "ACCESS::session data requires a value after -sid" }
                        incr index
                        set sid [lindex $options $index]
                    } elseif {$option in {-secure -config} || $option eq "-ssid"} {
                        if {$option eq "-ssid"} {
                            if {$index + 1 >= [llength $options]} { error "ACCESS::session data requires a value after -ssid" }
                            incr index
                        }
                    } elseif {$key eq ""} { set key $option
                    } elseif {$data_operation eq "set" && !$value_set} {
                        set value $option
                        set value_set 1
                    } else { error "ACCESS::session data received an invalid argument" }
                    incr index
                }
                if {$sid eq ""} { set sid $access_current_sid }
                set session [_access_require_session $sid ACCESS::session]
                if {$key eq ""} { error "ACCESS::session data requires KEY" }
                if {$data_operation eq "get"} {
                    if {[dict exists [dict get $session data] $key]} { return [dict get [dict get $session data] $key] }
                    return ""
                }
                if {!$value_set} { error "ACCESS::session data set requires KEY and VALUE" }
                dict set session data $key $value
                _access_set_session $sid $session
                return ""
            }
            default { error "ACCESS::session requires create, data, exists, modify, remove, or sid" }
        }
    }

    proc access_snapshot {} {
        variable access_enabled
        variable access_acl_result
        variable access_acl_lookup
        variable access_acl_matched
        variable access_acl_evaluated
        variable access_policy_result
        variable access_policy_agent_id
        variable access_policy_uri
        variable access_flow_id
        variable access_request_enabled
        variable access_restrict_irule_events
        variable access_current_sid
        variable access_sessions
        variable access_perflow
        variable access_saml
        set result [list enabled $access_enabled acl_result $access_acl_result \
            acl_lookup $access_acl_lookup acl_matched $access_acl_matched \
            acl_evaluated $access_acl_evaluated \
            policy_result $access_policy_result policy_agent_id $access_policy_agent_id \
            policy_uri $access_policy_uri flow_id $access_flow_id \
            request_enabled $access_request_enabled restrict_irule_events $access_restrict_irule_events \
            current_sid $access_current_sid session_count [dict size $access_sessions]]
        set sessions [list]
        foreach sid [lsort -dictionary [dict keys $access_sessions]] {
            set session [dict get $access_sessions $sid]
            lappend sessions [list $sid [dict get $session valid] [dict get $session state] \
                [dict get $session timeout] [dict get $session lifetime] \
                [dict get $session remaining] [_access_safe_data [dict get $session data]]]
        }
        lappend result sessions $sessions perflow $access_perflow saml $access_saml
        return $result
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

    proc _istats_key {key command_name} {
        if {$key eq ""} {
            error "$command_name requires a non-empty key"
        }
        return $key
    }

    proc _istats_measure_type {key} {
        set tokens [regexp -all -inline {\S+} $key]
        foreach index {2 1} {
            if {$index >= [llength $tokens]} {
                continue
            }
            set token [lindex $tokens $index]
            switch -nocase -- $token {
                counter - c - r { return counter }
                gauge - g { return gauge }
                string - text - s { return string }
            }
        }
        return ""
    }

    proc istats_get {args} {
        if {[llength $args] != 1} {
            error "ISTATS::get requires exactly one key"
        }
        variable istats
        set key [_istats_key [lindex $args 0] ISTATS::get]
        if {[info exists istats($key)]} {
            return $istats($key)
        }
        if {[_istats_measure_type $key] eq "string"} {
            return ""
        }
        return 0
    }

    proc istats_set {args} {
        if {[llength $args] != 2} {
            error "ISTATS::set requires key and value"
        }
        variable istats
        set key [_istats_key [lindex $args 0] ISTATS::set]
        set istats($key) [lindex $args 1]
        ::itest::log_decision istats set [list $key $istats($key)]
        return ""
    }

    proc istats_incr {args} {
        if {[llength $args] != 2} {
            error "ISTATS::incr requires key and value"
        }
        variable istats
        set key [_istats_key [lindex $args 0] ISTATS::incr]
        set amount [lindex $args 1]
        if {![string is integer -strict $amount]} {
            error "ISTATS::incr value must be an integer"
        }
        set measure_type [_istats_measure_type $key]
        if {$measure_type eq "string"} {
            error "ISTATS::incr cannot increment a string value"
        }
        if {$amount < 0 && $measure_type ne "gauge"} {
            error "ISTATS::incr counter value must be non-negative"
        }
        if {[info exists istats($key)]} {
            set current $istats($key)
            if {![string is integer -strict $current]} {
                error "ISTATS::incr cannot increment a non-numeric value"
            }
        } else {
            set current 0
        }
        set value [expr {$current + $amount}]
        set istats($key) $value
        ::itest::log_decision istats incr [list $key $amount $value]
        return $value
    }

    proc istats_remove {args} {
        if {[llength $args] != 1} {
            error "ISTATS::remove requires exactly one key"
        }
        variable istats
        set key [_istats_key [lindex $args 0] ISTATS::remove]
        unset -nocomplain istats($key)
        ::itest::log_decision istats remove $key
        return ""
    }

    proc oneconnect_reset_connection {} {
        variable oneconnect_detach_enabled
        variable oneconnect_reuse_enabled
        variable oneconnect_select_mode
        variable oneconnect_label
        set oneconnect_detach_enabled 1
        set oneconnect_reuse_enabled 1
        set oneconnect_select_mode none
        set oneconnect_label ""
    }

    proc crypto_reset_connection {} {
        variable crypto_contexts
        set crypto_contexts {}
    }

    proc _adapt_default_record {side} {
        return [dict create \
            handle "static:$side" \
            side $side \
            name [string toupper "${side}ADAPT"] \
            dynamic 0 \
            enabled 1 \
            allow_http_v1 1 \
            preview_size 0 \
            result unknown \
            select "" \
            service_down_action ignore \
            timeout 30000 \
            order 0]
    }

    proc adapt_reset_connection {} {
        variable adapt_contexts
        variable adapt_context_counter
        variable adapt_current_handle
        variable adapt_current_side
        set adapt_contexts [dict create \
            static:request [_adapt_default_record request] \
            static:response [_adapt_default_record response]]
        set adapt_context_counter 0
        set adapt_current_side request
        set adapt_current_handle static:request
    }

    proc adapt_snapshot {} {
        variable adapt_contexts
        variable adapt_current_handle
        variable adapt_current_side
        set contexts {}
        dict for {handle record} $adapt_contexts {
            lappend contexts [list \
                [dict get $record handle] \
                [dict get $record side] \
                [dict get $record name] \
                [dict get $record dynamic] \
                [dict get $record enabled] \
                [dict get $record allow_http_v1] \
                [dict get $record preview_size] \
                [dict get $record result] \
                [dict get $record select] \
                [dict get $record service_down_action] \
                [dict get $record timeout] \
                [dict get $record order]]
        }
        return [list \
            current_handle $adapt_current_handle \
            current_side $adapt_current_side \
            contexts $contexts]
    }

    proc _adapt_require_profile {side command_name} {
        if {![_profile_enabled [string toupper "${side}ADAPT"]]} {
            error "$command_name requires the [string toupper "${side}ADAPT"] profile"
        }
    }

    proc _adapt_event_side {} {
        if {[info exists ::itest::current_event] &&
            [string match {ADAPT_RESPONSE_*} $::itest::current_event]} {
            return response
        }
        if {[info exists ::itest::current_event] &&
            $::itest::current_event eq "HTTP_RESPONSE"} {
            return response
        }
        return request
    }

    proc _adapt_extract_handle {args command_name} {
        variable adapt_contexts
        set handle ""
        set explicit 0
        if {[llength $args] > 0 &&
            [dict exists $adapt_contexts [lindex $args 0]]} {
            set handle [lindex $args 0]
            set explicit 1
            set args [lrange $args 1 end]
        }
        return [list $handle $explicit $args]
    }

    proc _adapt_resolve_handle {handle explicit side side_explicit command_name} {
        variable adapt_contexts
        variable adapt_current_handle
        if {$explicit} {
            if {![dict exists $adapt_contexts $handle]} {
                error "$command_name references an unknown context"
            }
            set record [dict get $adapt_contexts $handle]
            if {[info exists ::itest::current_event] &&
                [string match {ADAPT_*} $::itest::current_event] &&
                [dict get $record side] ne [_adapt_event_side]} {
                error "$command_name context belongs to the [dict get $record side] side"
            }
            if {$side_explicit && [dict get $record side] ne $side} {
                error "$command_name context belongs to the [dict get $record side] side"
            }
            set side [dict get $record side]
        } elseif {!$side_explicit &&
                  [dict exists $adapt_contexts $adapt_current_handle] &&
                  [dict get [dict get $adapt_contexts $adapt_current_handle] side] eq $side &&
                  [info exists ::itest::current_event] &&
                  [string match {ADAPT_*} $::itest::current_event]} {
            set handle $adapt_current_handle
        } else {
            set handle "static:$side"
        }
        _adapt_require_profile $side $command_name
        if {![dict exists $adapt_contexts $handle]} {
            error "$command_name references an unknown context"
        }
        return $handle
    }

    proc _adapt_parse_side_target {args command_name} {
        variable adapt_current_side
        set extracted [_adapt_extract_handle $args $command_name]
        set handle [lindex $extracted 0]
        set explicit [lindex $extracted 1]
        set remaining [lindex $extracted 2]
        set side $adapt_current_side
        set side_explicit 0
        if {[llength $remaining] > 0 && [lindex $remaining 0] in {request response}} {
            set side [lindex $remaining 0]
            set side_explicit 1
            set remaining [lrange $remaining 1 end]
        }
        set target [_adapt_resolve_handle $handle $explicit $side $side_explicit $command_name]
        return [list $target $side $remaining]
    }

    proc _adapt_parse_property_target {args command_name} {
        variable adapt_current_side
        set extracted [_adapt_extract_handle $args $command_name]
        set handle [lindex $extracted 0]
        set explicit [lindex $extracted 1]
        set remaining [lindex $extracted 2]
        if {[llength $remaining] == 0} {
            error "$command_name requires a property"
        }
        set property [lindex $remaining 0]
        set remaining [lrange $remaining 1 end]
        set side $adapt_current_side
        set side_explicit 0
        if {[llength $remaining] > 0 && [lindex $remaining 0] in {request response}} {
            set side [lindex $remaining 0]
            set side_explicit 1
            set remaining [lrange $remaining 1 end]
        }
        set target [_adapt_resolve_handle $handle $explicit $side $side_explicit $command_name]
        return [list $target $side $property $remaining]
    }

    proc _adapt_bool {value command_name} {
        switch -exact -- [string tolower $value] {
            0 - false - disable - no { return 0 }
            1 - true - enable - yes { return 1 }
            default { error "$command_name boolean must be 0/1, false/true, or disable/enable" }
        }
    }

    proc _adapt_store {handle record} {
        variable adapt_contexts
        dict set adapt_contexts $handle $record
    }

    proc adapt_allow {args} {
        set parsed [_adapt_parse_property_target $args ADAPT::allow]
        set handle [lindex $parsed 0]
        set property [lindex $parsed 2]
        set remaining [lindex $parsed 3]
        if {$property ne "http_v1.0"} {
            error "ADAPT::allow only supports the http_v1.0 property"
        }
        variable adapt_contexts
        set record [dict get $adapt_contexts $handle]
        if {[llength $remaining] == 0} {
            return [dict get $record allow_http_v1]
        }
        if {[llength $remaining] != 1} {
            error "ADAPT::allow accepts one optional boolean"
        }
        dict set record allow_http_v1 [_adapt_bool [lindex $remaining 0] ADAPT::allow]
        _adapt_store $handle $record
        ::itest::log_decision adapt allow [list $handle [dict get $record allow_http_v1]]
        return ""
    }

    proc adapt_enable {args} {
        set parsed [_adapt_parse_side_target $args ADAPT::enable]
        set handle [lindex $parsed 0]
        set remaining [lindex $parsed 2]
        variable adapt_contexts
        set record [dict get $adapt_contexts $handle]
        if {[llength $remaining] == 0} {
            return [dict get $record enabled]
        }
        if {[llength $remaining] != 1} {
            error "ADAPT::enable accepts one optional boolean"
        }
        dict set record enabled [_adapt_bool [lindex $remaining 0] ADAPT::enable]
        _adapt_store $handle $record
        ::itest::log_decision adapt enable [list $handle [dict get $record enabled]]
        return ""
    }

    proc adapt_select {args} {
        set parsed [_adapt_parse_side_target $args ADAPT::select]
        set handle [lindex $parsed 0]
        set remaining [lindex $parsed 2]
        variable adapt_contexts
        set record [dict get $adapt_contexts $handle]
        if {[llength $remaining] == 0} {
            return [dict get $record select]
        }
        if {[llength $remaining] != 1 || [string first "\x00" [lindex $remaining 0]] >= 0} {
            error "ADAPT::select accepts one internal virtual name without NUL bytes"
        }
        dict set record select [lindex $remaining 0]
        _adapt_store $handle $record
        ::itest::log_decision adapt select [list $handle [dict get $record select]]
        return ""
    }

    proc adapt_preview_size {args} {
        set parsed [_adapt_parse_side_target $args ADAPT::preview_size]
        set handle [lindex $parsed 0]
        set remaining [lindex $parsed 2]
        variable adapt_contexts
        set record [dict get $adapt_contexts $handle]
        if {[llength $remaining] == 0} {
            return [dict get $record preview_size]
        }
        if {[llength $remaining] != 1 ||
            ![string is integer -strict [lindex $remaining 0]] ||
            [lindex $remaining 0] < 0} {
            error "ADAPT::preview_size requires a non-negative integer"
        }
        dict set record preview_size [lindex $remaining 0]
        _adapt_store $handle $record
        ::itest::log_decision adapt preview_size [list $handle [dict get $record preview_size]]
        return ""
    }

    proc adapt_service_down_action {args} {
        set parsed [_adapt_parse_side_target $args ADAPT::service_down_action]
        set handle [lindex $parsed 0]
        set remaining [lindex $parsed 2]
        variable adapt_contexts
        set record [dict get $adapt_contexts $handle]
        if {[llength $remaining] == 0} {
            return [dict get $record service_down_action]
        }
        if {[llength $remaining] != 1 || [lindex $remaining 0] ni {ignore drop reset}} {
            error "ADAPT::service_down_action requires ignore, drop, or reset"
        }
        dict set record service_down_action [lindex $remaining 0]
        _adapt_store $handle $record
        ::itest::log_decision adapt service_down_action [list $handle [dict get $record service_down_action]]
        return ""
    }

    proc adapt_timeout {args} {
        set parsed [_adapt_parse_side_target $args ADAPT::timeout]
        set handle [lindex $parsed 0]
        set remaining [lindex $parsed 2]
        variable adapt_contexts
        set record [dict get $adapt_contexts $handle]
        if {[llength $remaining] == 0} {
            return [dict get $record timeout]
        }
        if {[llength $remaining] != 1 ||
            ![string is integer -strict [lindex $remaining 0]] ||
            [lindex $remaining 0] < 0} {
            error "ADAPT::timeout requires a non-negative integer in milliseconds"
        }
        dict set record timeout [lindex $remaining 0]
        _adapt_store $handle $record
        ::itest::log_decision adapt timeout [list $handle [dict get $record timeout]]
        return ""
    }

    proc adapt_result {args} {
        if {![info exists ::itest::current_event] ||
            ![string match {ADAPT_*} $::itest::current_event]} {
            error "ADAPT::result is valid only in an ADAPT event"
        }
        set parsed [_adapt_parse_side_target $args ADAPT::result]
        set handle [lindex $parsed 0]
        set remaining [lindex $parsed 2]
        variable adapt_contexts
        set record [dict get $adapt_contexts $handle]
        if {[llength $remaining] == 0} {
            return [dict get $record result]
        }
        if {[llength $remaining] != 1 || [lindex $remaining 0] ni {bypass close}} {
            error "ADAPT::result can set only bypass or close"
        }
        dict set record result [lindex $remaining 0]
        _adapt_store $handle $record
        ::itest::log_decision adapt result [list $handle [dict get $record result]]
        return ""
    }

    proc adapt_context_create {args} {
        variable adapt_contexts
        variable adapt_context_counter
        set side [_adapt_event_side]
        if {[llength $args] == 2} {
            set side [lindex $args 0]
            set name [lindex $args 1]
        } elseif {[llength $args] == 1} {
            set name [lindex $args 0]
        } else {
            error "ADAPT::context_create accepts a name or side and name"
        }
        if {$side ni {request response}} {
            error "ADAPT::context_create side must be request or response"
        }
        _adapt_require_profile $side ADAPT::context_create
        if {$name eq "" || [string first "\x00" $name] >= 0 ||
            [string bytelength $name] > 256} {
            error "ADAPT::context_create requires a non-empty name without NUL bytes and no more than 256 bytes"
        }
        set dynamic_count 0
        dict for {existing_handle existing} $adapt_contexts {
            if {[dict get $existing dynamic] && [dict get $existing side] eq $side} {
                incr dynamic_count
                if {[dict get $existing name] eq $name} {
                    error "ADAPT::context_create name already exists on the $side side"
                }
            }
        }
        if {$dynamic_count >= 64} {
            error "ADAPT::context_create exceeds the 64-context limit"
        }
        incr adapt_context_counter
        set handle "dynamic:$side:$adapt_context_counter"
        set record [dict get $adapt_contexts "static:$side"]
        dict set record handle $handle
        dict set record name $name
        dict set record dynamic 1
        dict set record order $adapt_context_counter
        dict set adapt_contexts $handle $record
        ::itest::log_decision adapt context_create [list $handle $side $name]
        return $handle
    }

    proc adapt_context_current {args} {
        variable adapt_current_handle
        if {[llength $args] != 0} {
            error "ADAPT::context_current takes no arguments"
        }
        _adapt_require_profile [_adapt_event_side] ADAPT::context_current
        return $adapt_current_handle
    }

    proc adapt_context_delete_all {args} {
        variable adapt_contexts
        variable adapt_current_handle
        variable adapt_current_side
        if {[llength $args] != 0} {
            error "ADAPT::context_delete_all takes no arguments"
        }
        _adapt_require_profile $adapt_current_side ADAPT::context_delete_all
        set request [dict get $adapt_contexts static:request]
        set response [dict get $adapt_contexts static:response]
        set adapt_contexts [dict create static:request $request static:response $response]
        set adapt_current_handle "static:$adapt_current_side"
        ::itest::log_decision adapt context_delete_all
        return ""
    }

    proc adapt_context_name {args} {
        variable adapt_contexts
        if {[llength $args] != 1 || ![dict exists $adapt_contexts [lindex $args 0]]} {
            error "ADAPT::context_name requires a known context handle"
        }
        return [dict get $adapt_contexts [lindex $args 0] name]
    }

    proc adapt_context_static {args} {
        variable adapt_current_side
        if {[llength $args] > 1 ||
            ([llength $args] == 1 && [lindex $args 0] ni {request response})} {
            error "ADAPT::context_static accepts request or response"
        }
        set side $adapt_current_side
        if {[llength $args] == 1} { set side [lindex $args 0] }
        _adapt_require_profile $side ADAPT::context_static
        return "static:$side"
    }

    proc adapt_prepare_event {event_name} {
        variable adapt_contexts
        variable adapt_current_handle
        variable adapt_current_side
        if {[string match {ADAPT_RESPONSE_*} $event_name] || $event_name eq "HTTP_RESPONSE"} {
        set adapt_current_side response
        } else {
            set adapt_current_side request
        }
        set adapt_current_handle "static:$adapt_current_side"
        dict for {handle record} $adapt_contexts {
            if {[dict get $record dynamic] && [dict get $record enabled] &&
                [dict get $record side] eq $adapt_current_side} {
                set adapt_current_handle $handle
                break
            }
        }
    }

    proc _oneconnect_require_profile {command_name} {
        if {![_profile_enabled ONECONNECT]} {
            error "$command_name requires a OneConnect profile"
        }
    }

    proc oneconnect_detach_command {args} {
        _oneconnect_require_profile ONECONNECT::detach
        if {[llength $args] != 1 || [lindex $args 0] ni {enable disable}} {
            error "ONECONNECT::detach requires enable or disable"
        }
        variable oneconnect_detach_enabled
        set oneconnect_detach_enabled [expr {[lindex $args 0] eq "enable"}]
        ::itest::log_decision oneconnect detach [lindex $args 0]
        return ""
    }

    proc oneconnect_label_command {args} {
        _oneconnect_require_profile ONECONNECT::label
        if {[llength $args] != 2 || [lindex $args 0] ne "update"} {
            error "ONECONNECT::label syntax is update key"
        }
        if {[string first "\x00" [lindex $args 1]] >= 0} {
            error "ONECONNECT::label key cannot contain NUL bytes"
        }
        variable oneconnect_label
        set oneconnect_label [lindex $args 1]
        ::itest::log_decision oneconnect label $oneconnect_label
        return ""
    }

    proc oneconnect_reuse_command {args} {
        _oneconnect_require_profile ONECONNECT::reuse
        if {[llength $args] == 0} {
            variable oneconnect_reuse_enabled
            return $oneconnect_reuse_enabled
        }
        if {[llength $args] != 1 || [lindex $args 0] ni {enable disable}} {
            error "ONECONNECT::reuse requires enable or disable"
        }
        variable oneconnect_reuse_enabled
        set oneconnect_reuse_enabled [expr {[lindex $args 0] eq "enable"}]
        ::itest::log_decision oneconnect reuse [lindex $args 0]
        return ""
    }

    proc oneconnect_select_command {args} {
        _oneconnect_require_profile ONECONNECT::select
        if {[llength $args] == 0} {
            variable oneconnect_select_mode
            return $oneconnect_select_mode
        }
        if {[llength $args] != 1 || [lindex $args 0] ni {none persist}} {
            error "ONECONNECT::select requires none or persist"
        }
        variable oneconnect_select_mode
        set oneconnect_select_mode [lindex $args 0]
        ::itest::log_decision oneconnect select $oneconnect_select_mode
        return ""
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
        if {[llength $args] != 0} {
            error "IP::version takes no arguments"
        }
        set address $::state::connection::client_addr
        return [expr {[string first : $address] >= 0 ? 6 : 4}]
    }

    proc _ipv6_address_valid {address} {
        if {[string first ":::" $address] >= 0} {
            return 0
        }
        set compression [string first "::" $address]
        if {$compression >= 0 && [string last "::" $address] != $compression} {
            return 0
        }
        set pieces [list]
        if {$compression >= 0} {
            set left [string range $address 0 [expr {$compression - 1}]]
            set right [string range $address [expr {$compression + 2}] end]
            set pieces [concat [split $left :] [split $right :]]
        } else {
            set pieces [split $address :]
        }
        set count 0
        foreach piece $pieces {
            if {$piece eq ""} {
                continue
            }
            if {[string length $piece] > 4 || ![regexp {^[0-9A-Fa-f]+$} $piece]} {
                return 0
            }
            incr count
        }
        if {$compression >= 0} {
            return [expr {$count < 8}]
        }
        return [expr {$count == 8}]
    }

    proc ip_address_key {address} {
        if {$address eq "" || [string first "\x00" $address] >= 0} {
            error "invalid IP address \"$address\""
        }
        set original_address $address
        if {[string first . $address] >= 0} {
            set last_colon [string last : $address]
            if {$last_colon < 0} {
                if {[catch {_ipv4_int $address}]} {
                    error "invalid IP address \"$address\""
                }
            } else {
                set ipv4 [string range $address [expr {$last_colon + 1}] end]
                if {[catch {_ipv4_int $ipv4}]} {
                    error "invalid IP address \"$address\""
                }
                set validation_address "[string range $address 0 $last_colon]0:0"
                if {![_ipv6_address_valid $validation_address]} {
                    error "invalid IP address \"$original_address\""
                }
            }
        } elseif {[string first : $address] >= 0} {
            if {![_ipv6_address_valid $address]} {
                error "invalid IP address \"$address\""
            }
        } elseif {[catch {_ipv4_int $address}]} {
            error "invalid IP address \"$address\""
        }
        return [string tolower $original_address]
    }

    proc ip_configure {hops} {
        if {![string is integer -strict $hops] || $hops < 0 || $hops > 255} {
            error "IP hops must be an integer from 0 to 255"
        }
        variable ip_default_hops
        variable ip_hops
        variable ip_intelligence_records
        variable ip_reputation_records
        variable ip_drop_rates
        variable ip_global_gray_list_rate
        variable ip_global_rate
        set ip_default_hops $hops
        set ip_hops $hops
        set ip_intelligence_records [dict create]
        set ip_reputation_records [dict create]
        set ip_drop_rates [dict create]
        set ip_global_gray_list_rate 0
        set ip_global_rate 0
        ip_reset_connection
    }

    proc ip_set_intelligence {address categories} {
        variable ip_intelligence_records
        set key [ip_address_key $address]
        if {[catch {llength $categories}]} {
            error "IP intelligence categories must be a Tcl list"
        }
        foreach category $categories {
            if {$category eq "" || [string first "\x00" $category] >= 0 ||
                [string first "{" $category] >= 0 || [string first "}" $category] >= 0} {
                error "IP intelligence categories must be non-empty strings"
            }
        }
        dict set ip_intelligence_records $key $categories
    }

    proc ip_set_reputation {address categories} {
        variable ip_reputation_records
        set key [ip_address_key $address]
        if {[catch {llength $categories}]} {
            error "IP reputation categories must be a Tcl list"
        }
        foreach category $categories {
            if {$category eq "" || [string first "\x00" $category] >= 0 ||
                [string first "{" $category] >= 0 || [string first "}" $category] >= 0} {
                error "IP reputation categories must be non-empty strings"
            }
        }
        dict set ip_reputation_records $key $categories
    }

    proc ip_reset_connection {} {
        variable ip_default_hops
        variable ip_hops
        variable ip_stats_pkts_in
        variable ip_stats_pkts_out
        variable ip_stats_bytes_in
        variable ip_stats_bytes_out
        variable ip_stats_age_ms
        set ip_hops $ip_default_hops
        set ip_stats_pkts_in 0
        set ip_stats_pkts_out 0
        set ip_stats_bytes_in 0
        set ip_stats_bytes_out 0
        set ip_stats_age_ms 0
    }

    proc ip_record_packet {direction byte_count age_ms {hops ""}} {
        if {$direction ni {client_to_server server_to_client}} {
            error "IP packet direction must be client_to_server or server_to_client"
        }
        if {![string is integer -strict $byte_count] || $byte_count < 0} {
            error "IP packet byte count must be a non-negative integer"
        }
        if {![string is integer -strict $age_ms] || $age_ms < 0} {
            error "IP packet age must be a non-negative integer"
        }
        if {$hops ne "" && (![string is integer -strict $hops] || $hops < 0 || $hops > 255)} {
            error "IP packet hops must be an integer from 0 to 255"
        }
        variable ip_hops
        variable ip_stats_pkts_in
        variable ip_stats_pkts_out
        variable ip_stats_bytes_in
        variable ip_stats_bytes_out
        variable ip_stats_age_ms
        if {$direction eq "client_to_server"} {
            incr ip_stats_pkts_in
            incr ip_stats_bytes_in $byte_count
        } else {
            incr ip_stats_pkts_out
            incr ip_stats_bytes_out $byte_count
        }
        if {$age_ms > $ip_stats_age_ms} {
            set ip_stats_age_ms $age_ms
        }
        if {$hops ne ""} {
            set ip_hops $hops
        }
    }

    proc ip_hops_command {args} {
        if {[llength $args] != 0} {
            error "IP::hops takes no arguments"
        }
        variable ip_hops
        return $ip_hops
    }

    proc ip_idle_timeout_command {args} {
        if {[llength $args] > 1} {
            error "IP::idle_timeout accepts zero or one argument"
        }
        if {[llength $args] == 1} {
            set value [lindex $args 0]
            if {![string is integer -strict $value] || $value < 0} {
                error "IP::idle_timeout requires a non-negative integer"
            }
            set ::state::connection::idle_timeout $value
            ::itest::log_decision ip idle_timeout $value
        }
        if {[info exists ::state::connection::idle_timeout]} {
            return $::state::connection::idle_timeout
        }
        return 0
    }

    proc ip_ingress_drop_rate_command {args} {
        if {[llength $args] != 3} {
            error "IP::ingress_drop_rate requires IP, DROP_RATE, and TIMEOUT"
        }
        lassign $args address rate timeout
        set key [ip_address_key $address]
        if {![string is integer -strict $rate] || $rate < 0 || $rate > 100} {
            error "IP::ingress_drop_rate DROP_RATE must be an integer from 0 to 100"
        }
        if {![string is integer -strict $timeout] || $timeout < 0} {
            error "IP::ingress_drop_rate TIMEOUT must be a non-negative integer"
        }
        variable ip_drop_rates
        dict set ip_drop_rates $key [list $rate $timeout]
        ::itest::log_decision ip ingress_drop_rate [list $key $rate $timeout]
        return ""
    }

    proc ip_ingress_rate_limit_command {args} {
        if {[llength $args] != 2} {
            error "IP::ingress_rate_limit requires GLOBAL_GRAY_LIST_RATE and GLOBAL_RATE"
        }
        lassign $args gray_list_rate global_rate
        foreach value [list $gray_list_rate $global_rate] {
            if {![string is integer -strict $value] || $value < 0} {
                error "IP::ingress_rate_limit rates must be non-negative integers"
            }
        }
        variable ip_global_gray_list_rate
        variable ip_global_rate
        set ip_global_gray_list_rate $gray_list_rate
        set ip_global_rate $global_rate
        ::itest::log_decision ip ingress_rate_limit [list $gray_list_rate $global_rate]
        return ""
    }

    proc ip_intelligence_command {args} {
        if {[llength $args] != 1} {
            error "IP::intelligence requires one IP address"
        }
        variable ip_intelligence_records
        set key [ip_address_key [lindex $args 0]]
        if {[dict exists $ip_intelligence_records $key]} {
            return [dict get $ip_intelligence_records $key]
        }
        return [list]
    }

    proc ip_reputation_command {args} {
        if {[llength $args] < 1} {
            error "IP::reputation requires one or more IP addresses"
        }
        variable ip_reputation_records
        set result [list]
        foreach address $args {
            set key [ip_address_key $address]
            if {![dict exists $ip_reputation_records $key]} {
                continue
            }
            foreach category [dict get $ip_reputation_records $key] {
                if {[lsearch -exact $result $category] < 0} {
                    lappend result $category
                }
            }
        }
        return $result
    }

    proc ip_stats_command {args} {
        if {[llength $args] > 2} {
            error "IP::stats accepts at most two arguments"
        }
        variable ip_stats_pkts_in
        variable ip_stats_pkts_out
        variable ip_stats_bytes_in
        variable ip_stats_bytes_out
        variable ip_stats_age_ms
        if {[llength $args] == 0} {
            return [list $ip_stats_pkts_in $ip_stats_pkts_out $ip_stats_bytes_in $ip_stats_bytes_out $ip_stats_age_ms]
        }
        set metric [string tolower [lindex $args 0]]
        if {[llength $args] == 1} {
            switch -exact -- $metric {
                pkts { return [list $ip_stats_pkts_in $ip_stats_pkts_out] }
                bytes { return [list $ip_stats_bytes_in $ip_stats_bytes_out] }
                in { return [list $ip_stats_pkts_in $ip_stats_bytes_in] }
                out { return [list $ip_stats_pkts_out $ip_stats_bytes_out] }
                age { return $ip_stats_age_ms }
                default { error "unsupported IP::stats selector \"$metric\"" }
            }
        }
        set direction [string tolower [lindex $args 1]]
        if {$direction ni {in out} || $metric ni {pkts bytes}} {
            error "IP::stats requires pkts or bytes followed by in or out"
        }
        if {$metric eq "pkts"} {
            return [expr {$direction eq "in" ? $ip_stats_pkts_in : $ip_stats_pkts_out}]
        }
        return [expr {$direction eq "in" ? $ip_stats_bytes_in : $ip_stats_bytes_out}]
    }

    proc ip_snapshot {} {
        variable ip_hops
        variable ip_intelligence_records
        variable ip_reputation_records
        variable ip_drop_rates
        variable ip_global_gray_list_rate
        variable ip_global_rate
        variable ip_stats_pkts_in
        variable ip_stats_pkts_out
        variable ip_stats_bytes_in
        variable ip_stats_bytes_out
        variable ip_stats_age_ms
        set idle_timeout 0
        if {[info exists ::state::connection::idle_timeout]} {
            set idle_timeout $::state::connection::idle_timeout
        }
        return [list hops $ip_hops idle_timeout $idle_timeout \
            pkts_in $ip_stats_pkts_in pkts_out $ip_stats_pkts_out \
            bytes_in $ip_stats_bytes_in bytes_out $ip_stats_bytes_out \
            age_ms $ip_stats_age_ms intelligence $ip_intelligence_records \
            reputation $ip_reputation_records drop_rates $ip_drop_rates \
            global_gray_list_rate $ip_global_gray_list_rate global_rate $ip_global_rate]
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

    proc rtsp_reset_connection {} {
        variable rtsp_collection_requested
        variable rtsp_collection_length
        variable rtsp_release_requested
        set rtsp_collection_requested 0
        set rtsp_collection_length 0
        set rtsp_release_requested 0
        foreach {name value} {
            type request
            method ""
            uri ""
            version RTSP/1.0
            status 200
            phrase OK
            msg_source client
            headers {}
            payload ""
            payload_length 0
            dropped 0
            responded 0
            response_status 0
            response_phrase ""
            response_headers {}
            response_body ""
        } {
            set ::state::rtsp::$name $value
        }
    }

    proc rtsp_prepare_event {} {
        variable rtsp_release_requested
        set rtsp_release_requested 0
        foreach {name value} {
            dropped 0
            responded 0
            response_status 0
            response_phrase ""
            response_headers {}
            response_body ""
        } {
            set ::state::rtsp::$name $value
        }
    }

    proc _rtsp_require_event {allowed command_name} {
        if {$::itest::current_event ni $allowed} {
            error "$command_name is not valid during $::itest::current_event"
        }
    }

    proc _rtsp_is_response_event {} {
        return [expr {$::itest::current_event in {RTSP_RESPONSE RTSP_RESPONSE_DATA}}]
    }

    proc _rtsp_header_matches {actual wanted} {
        return [string equal -nocase $actual $wanted]
    }

    proc _rtsp_set_headers {headers} {
        set ::state::rtsp::headers $headers
        if {[_rtsp_is_response_event]} {
            set ::state::rtsp::response_headers $headers
        }
    }

    proc _rtsp_header_indices {headers wanted} {
        set indices {}
        set index 0
        foreach {name value} $headers {
            if {[_rtsp_header_matches $name $wanted]} {
                lappend indices $index
            }
            incr index 2
        }
        return $indices
    }

    proc rtsp_header_command {args} {
        _rtsp_require_event {
            RTSP_REQUEST RTSP_REQUEST_DATA RTSP_RESPONSE RTSP_RESPONSE_DATA
        } RTSP::header
        if {[llength $args] == 0} {
            error "RTSP::header requires a subcommand"
        }
        set subcommand [string tolower [lindex $args 0]]
        set headers $::state::rtsp::headers
        switch -exact -- $subcommand {
            value {
                if {[llength $args] != 2} { error "RTSP::header value requires a name" }
                foreach {name value} $headers {
                    if {[_rtsp_header_matches $name [lindex $args 1]]} {
                        return $value
                    }
                }
                return ""
            }
            exists {
                if {[llength $args] != 2} { error "RTSP::header exists requires a name" }
                return [expr {[llength [_rtsp_header_indices $headers [lindex $args 1]]] > 0}]
            }
            insert {
                if {[llength $args] == 2} {
                    set additions [lindex $args 1]
                } elseif {[llength $args] >= 3 && ([llength $args] - 1) % 2 == 0} {
                    set additions [lrange $args 1 end]
                } else {
                    error "RTSP::header insert requires name/value pairs"
                }
                if {[llength $additions] % 2} {
                    error "RTSP::header insert requires name/value pairs"
                }
                foreach {name value} $additions {
                    if {$name eq ""} { error "RTSP header name cannot be empty" }
                    lappend headers $name $value
                }
                _rtsp_set_headers $headers
            }
            remove {
                if {[llength $args] != 2} { error "RTSP::header remove requires a name" }
                set wanted [lindex $args 1]
                set updated {}
                foreach {name value} $headers {
                    if {![_rtsp_header_matches $name $wanted]} {
                        lappend updated $name $value
                    }
                }
                _rtsp_set_headers $updated
            }
            replace {
                if {[llength $args] == 3} {
                    set old_name [lindex $args 1]
                    set new_name $old_name
                    set new_value [lindex $args 2]
                } elseif {[llength $args] == 5} {
                    set old_name [lindex $args 1]
                    set new_name [lindex $args 3]
                    set new_value [lindex $args 4]
                } else {
                    error "RTSP::header replace requires name/value or old-name/value/new-name/value"
                }
                set updated {}
                set replaced 0
                foreach {name value} $headers {
                    if {[_rtsp_header_matches $name $old_name]} {
                        if {!$replaced} {
                            lappend updated $new_name $new_value
                            set replaced 1
                        }
                    } else {
                        lappend updated $name $value
                    }
                }
                if {!$replaced} { lappend updated $new_name $new_value }
                _rtsp_set_headers $updated
            }
            default { error "unsupported RTSP::header subcommand $subcommand" }
        }
        return ""
    }

    proc rtsp_payload_command {args} {
        _rtsp_require_event {RTSP_REQUEST_DATA RTSP_RESPONSE_DATA} RTSP::payload
        if {[llength $args] == 0} { return $::state::rtsp::payload }
        set subcommand [lindex $args 0]
        switch -exact -- $subcommand {
            length {
                if {[llength $args] != 1} { error "RTSP::payload length takes no arguments" }
                return [::itest::cmd::_payload_bytelength $::state::rtsp::payload]
            }
            replace {
                if {[llength $args] != 4} {
                    error "RTSP::payload replace requires offset, length, and data"
                }
                set offset [lindex $args 1]
                set length [lindex $args 2]
                if {![string is integer -strict $offset] || $offset < 0 ||
                    ![string is integer -strict $length] || $length < 0} {
                    error "RTSP::payload offsets must be non-negative integers"
                }
                set ::state::rtsp::payload [::itest::cmd::_payload_splice \
                    $::state::rtsp::payload $offset $length [lindex $args 3]]
                set ::state::rtsp::payload_length \
                    [::itest::cmd::_payload_bytelength $::state::rtsp::payload]
                ::itest::log_decision rtsp payload_replace [list $offset $length]
                return ""
            }
            default {
                if {![string is integer -strict $subcommand] || $subcommand < 0 ||
                    [llength $args] != 1} {
                    error "RTSP::payload accepts length, replace, or an optional non-negative size"
                }
                return [::itest::cmd::_payload_first $::state::rtsp::payload $subcommand]
            }
        }
    }

    proc rtsp_collect_command {args} {
        _rtsp_require_event {RTSP_REQUEST RTSP_RESPONSE} RTSP::collect
        variable rtsp_collection_requested
        variable rtsp_collection_length
        if {[llength $args] > 1} { error "RTSP::collect accepts an optional length" }
        set length 0
        if {[llength $args] == 1} {
            set length [lindex $args 0]
            if {![string is integer -strict $length] || $length <= 0} {
                error "RTSP::collect length must be a positive integer"
            }
        }
        set rtsp_collection_requested 1
        set rtsp_collection_length $length
        ::itest::log_decision rtsp collect $length
        return ""
    }

    proc rtsp_release_command {args} {
        _rtsp_require_event {RTSP_REQUEST_DATA RTSP_RESPONSE_DATA} RTSP::release
        variable rtsp_release_requested
        if {[llength $args] != 0} { error "RTSP::release takes no arguments" }
        set rtsp_release_requested 1
        variable rtsp_collection_requested
        set rtsp_collection_requested 0
        ::itest::log_decision rtsp release ""
        return ""
    }

    proc _rtsp_getter {field command_name} {
        _rtsp_require_event {
            RTSP_REQUEST RTSP_REQUEST_DATA RTSP_RESPONSE RTSP_RESPONSE_DATA
        } $command_name
        return [set ::state::rtsp::$field]
    }

    proc rtsp_method_command {args} {
        if {[llength $args] != 0} { error "RTSP::method takes no arguments" }
        return [_rtsp_getter method RTSP::method]
    }

    proc rtsp_msg_source_command {args} {
        if {[llength $args] != 0} { error "RTSP::msg_source takes no arguments" }
        return [_rtsp_getter msg_source RTSP::msg_source]
    }

    proc rtsp_status_command {args} {
        if {[llength $args] != 0} { error "RTSP::status takes no arguments" }
        return [_rtsp_getter status RTSP::status]
    }

    proc rtsp_uri_command {args} {
        if {[llength $args] != 0} { error "RTSP::uri takes no arguments" }
        return [_rtsp_getter uri RTSP::uri]
    }

    proc rtsp_version_command {args} {
        if {[llength $args] != 0} { error "RTSP::version takes no arguments" }
        return [_rtsp_getter version RTSP::version]
    }

    proc rtsp_respond_command {args} {
        _rtsp_require_event {RTSP_REQUEST} RTSP::respond
        if {$::state::rtsp::responded} {
            error "only one RTSP response is allowed per request"
        }
        if {[llength $args] < 2 || [llength $args] > 3} {
            error "RTSP::respond requires status, phrase, and an optional response"
        }
        set status [lindex $args 0]
        if {![string is integer -strict $status] || $status < 100 || $status > 999} {
            error "RTSP response status must be between 100 and 999"
        }
        set phrase [lindex $args 1]
        if {$phrase eq ""} { error "RTSP response phrase cannot be empty" }
        set headers {}
        set body ""
        if {[llength $args] == 3} {
            set response [lindex $args 2]
            set separator [string first "\r\n\r\n" $response]
            set separator_length 4
            if {$separator < 0} {
                set separator [string first "\n\n" $response]
                set separator_length 2
            }
            if {$separator >= 0} {
                set header_text [string range $response 0 [expr {$separator - 1}]]
                set body [string range $response [expr {$separator + $separator_length}] end]
            } else {
                set header_text $response
            }
            set header_text [string map {\r\n \n \r \n} $header_text]
            set non_header 0
            foreach line [split $header_text \n] {
                if {$line eq ""} { continue }
                set colon [string first : $line]
                if {$colon <= 0} {
                    set non_header 1
                    break
                }
                lappend headers [string trim [string range $line 0 [expr {$colon - 1}]]] \
                    [string trim [string range $line [expr {$colon + 1}] end]]
            }
            if {$separator < 0 && $non_header} {
                set headers {}
                set body $response
            }
        }
        set has_cseq 0
        foreach {name value} $headers {
            if {[_rtsp_header_matches $name CSeq]} { set has_cseq 1; break }
        }
        if {!$has_cseq} {
            foreach {name value} $::state::rtsp::headers {
                if {[_rtsp_header_matches $name CSeq]} {
                    lappend headers CSeq $value
                    break
                }
            }
        }
        set ::state::rtsp::responded 1
        set ::state::rtsp::response_status $status
        set ::state::rtsp::response_phrase $phrase
        set ::state::rtsp::response_headers $headers
        set ::state::rtsp::response_body $body
        ::itest::log_decision rtsp respond [list $status $phrase]
        return ""
    }

    proc _cache_profile_enabled {} {
        foreach profile $::orch::config(profiles) {
            if {[string toupper $profile] in {CACHE WEBACCELERATION}} {
                return 1
            }
        }
        return 0
    }

    proc _cache_header_matches {actual wanted} {
        return [string equal -nocase $actual $wanted]
    }

    proc _cache_require_event {allowed command_name} {
        if {$::itest::current_event ni $allowed} {
            error "$command_name is not valid during $::itest::current_event"
        }
    }

    proc _cache_key {} {
        set host $::state::http::request::host
        if {$host eq ""} {
            set host [::state::http::request::header get host]
        }
        set key [list $::state::cache::userkey $host \
            $::state::cache::uri $::state::cache::accept_encoding \
            $::state::cache::useragent]
        set ::state::cache::key $key
        set ::state::cache::statskey $key
        return $key
    }

    proc _cache_response_headers {} {
        set headers {}
        dict for {name values} $::state::http::response::headers {
            lappend headers $name [lindex $values 0]
        }
        return $headers
    }

    proc _cache_load_object {object} {
        foreach field {uri useragent userkey accept_encoding key headers payload \
                       age hits fresh priority statskey stored hit} {
            if {[dict exists $object $field]} {
                set ::state::cache::$field [dict get $object $field]
            }
        }
        set ::state::cache::status [dict get $object status]
        set ::state::cache::reason [dict get $object reason]
    }

    proc _cache_sync_http_response {} {
        set ::state::http::response::status $::state::cache::status
        set ::state::http::response::reason $::state::cache::reason
        set ::state::http::response::headers {}
        foreach {name value} $::state::cache::headers {
            ::state::http::response::header set $name $value
        }
        set ::state::http::response::payload $::state::cache::payload
    }

    proc _cache_fire {event_name} {
        if {[lsearch -exact [::itest::registered_events] $event_name] < 0} {
            return ""
        }
        return [::itest::_testcl_fire_event_orig $event_name]
    }

    proc cache_flow_hook {} {
        return ""
    }

    proc cache_install_flow_hooks {} {
        foreach event_name {HTTP_REQUEST HTTP_RESPONSE} {
            set handlers {}
            if {[info exists ::itest::event_handlers($event_name)]} {
                set handlers $::itest::event_handlers($event_name)
            }
            set already_installed 0
            foreach handler $handlers {
                if {[lindex $handler 1] eq "::itest::semantic::cache_flow_hook"} {
                    set already_installed 1
                    break
                }
            }
            if {!$already_installed} {
                lappend handlers [list 100000 ::itest::semantic::cache_flow_hook]
                set ::itest::event_handlers($event_name) $handlers
            }
        }
    }

    proc cache_prepare_request {} {
        variable cache_tick
        variable cache_update_tick
        incr cache_tick
        set cache_update_tick -1
        foreach {name value} {
            uri ""
            useragent ""
            userkey ""
            accept_encoding ""
            key ""
            headers {}
            payload ""
            age 0
            hits 0
            fresh 0
            disabled 0
            forced 0
            expired 0
            priority 0
            statskey ""
            stored 0
            hit 0
            status 200
            reason OK
        } {
            set ::state::cache::$name $value
        }
        set ::state::cache::uri $::state::http::request::uri
        set ::state::cache::useragent [::state::http::request::header get user-agent]
        set ::state::cache::accept_encoding [::state::http::request::header get accept-encoding]
        set ::state::cache::headers {}
        set ::state::cache::statskey ""
        set ::state::cache::key [_cache_key]
    }

    proc cache_request_event {} {
        variable cache_objects
        variable cache_tick
        if {![_cache_profile_enabled]} { return 0 }
        set key [_cache_key]
        set found [info exists cache_objects($key)]
        if {$found} {
            set object $cache_objects($key)
            set hits [expr {[dict get $object hits] + 1}]
            dict set object hits $hits
            set age [expr {$cache_tick - [dict get $object stored_tick]}]
            dict set object age $age
            set cache_objects($key) $object
            _cache_load_object $object
            set ::state::cache::age $age
            set ::state::cache::hits $hits
            set ::state::cache::fresh 1
            set ::state::cache::hit 1
            set ::state::cache::stored 1
        }
        _cache_fire CACHE_REQUEST
        if {$found && !$::state::cache::disabled && !$::state::cache::expired} {
            _cache_load_object $cache_objects($key)
            _cache_fire CACHE_RESPONSE
            _cache_sync_http_response
            set ::state::http::response_committed 1
            if {$::state::cache::expired} {
                unset -nocomplain cache_objects($key)
            }
            return 1
        }
        if {$found && $::state::cache::expired} {
            unset -nocomplain cache_objects($key)
        }
        return 0
    }

    proc cache_update_event {} {
        variable cache_objects
        variable cache_tick
        variable cache_update_tick
        if {![_cache_profile_enabled]} { return 0 }
        if {$cache_update_tick == $cache_tick} { return 0 }
        set cache_update_tick $cache_tick
        set method [string toupper $::state::http::request::method]
        if {$method ni {GET HEAD} && !$::state::cache::forced} { return 0 }
        set key [_cache_key]
        set ::state::cache::key $key
        set ::state::cache::headers [_cache_response_headers]
        set ::state::cache::payload $::state::http::response::payload
        set ::state::cache::status $::state::http::response::status
        set ::state::cache::reason $::state::http::response::reason
        set ::state::cache::age 0
        set ::state::cache::hits 0
        set ::state::cache::fresh 1
        set ::state::cache::hit 0
        set ::state::cache::stored 0
        set ::state::cache::expired 0
        _cache_fire CACHE_UPDATE
        if {$::state::cache::disabled || $::state::cache::expired} { return 0 }
        set cache_objects($key) [dict create \
            uri $::state::cache::uri \
            useragent $::state::cache::useragent \
            userkey $::state::cache::userkey \
            accept_encoding $::state::cache::accept_encoding \
            key $key headers $::state::cache::headers \
            payload $::state::cache::payload \
            status $::state::cache::status reason $::state::cache::reason \
            age 0 hits 0 fresh 1 priority $::state::cache::priority \
            statskey $::state::cache::statskey stored 1 hit 0 \
            stored_tick $cache_tick]
        set ::state::cache::stored 1
        return 1
    }

    proc cache_header_command {args} {
        _cache_require_event {CACHE_RESPONSE} CACHE::header
        if {[llength $args] == 0} { error "CACHE::header requires a subcommand" }
        set subcommand [string tolower [lindex $args 0]]
        set headers $::state::cache::headers
        switch -exact -- $subcommand {
            value {
                if {[llength $args] != 2} { error "CACHE::header value requires a name" }
                foreach {name value} $headers {
                    if {[_cache_header_matches $name [lindex $args 1]]} { return $value }
                }
                return ""
            }
            exists {
                if {[llength $args] ni {2 3}} { error "CACHE::header exists requires a name and optional value" }
                set wanted [lindex $args 1]
                foreach {name value} $headers {
                    if {[_cache_header_matches $name $wanted] &&
                        ([llength $args] == 2 || $value eq [lindex $args 2])} { return 1 }
                }
                return 0
            }
            insert {
                if {[llength $args] != 3} { error "CACHE::header insert requires name and value" }
                lappend headers [lindex $args 1] [lindex $args 2]
            }
            remove {
                if {[llength $args] ni {2 3}} { error "CACHE::header remove requires a name and optional value" }
                set updated {}
                foreach {name value} $headers {
                    set remove [expr {[_cache_header_matches $name [lindex $args 1]] &&
                        ([llength $args] == 2 || $value eq [lindex $args 2])}]
                    if {!$remove} { lappend updated $name $value }
                }
                set headers $updated
            }
            replace {
                if {[llength $args] != 3} { error "CACHE::header replace requires name and value" }
                set updated {}
                set replaced 0
                foreach {name value} $headers {
                    if {[_cache_header_matches $name [lindex $args 1]]} {
                        if {!$replaced} {
                            lappend updated [lindex $args 1] [lindex $args 2]
                            set replaced 1
                        }
                    } else { lappend updated $name $value }
                }
                if {!$replaced} { lappend updated [lindex $args 1] [lindex $args 2] }
                set headers $updated
            }
            default { error "unsupported CACHE::header subcommand $subcommand" }
        }
        set ::state::cache::headers $headers
        return ""
    }

    proc cache_simple_set {field command_name args} {
        if {[llength $args] != 1} { error "$command_name requires one value" }
        set ::state::cache::$field [lindex $args 0]
        return ""
    }

    proc cache_noarg {field command_name args} {
        if {[llength $args] != 0} { error "$command_name takes no arguments" }
        return [set ::state::cache::$field]
    }

    proc cache_disable_command {args} {
        if {[llength $args] != 0} { error "CACHE::disable takes no arguments" }
        set ::state::cache::disabled 1
        return ""
    }

    proc cache_enable_command {args} {
        if {[llength $args] != 0} { error "CACHE::enable takes no arguments" }
        set ::state::cache::disabled 0
        set ::state::cache::forced 1
        return ""
    }

    proc cache_expire_command {args} {
        if {[llength $args] != 0} { error "CACHE::expire takes no arguments" }
        set ::state::cache::expired 1
        return ""
    }

    proc cache_priority_command {args} {
        if {[llength $args] != 1 || ![string is integer -strict [lindex $args 0]] ||
            [lindex $args 0] < 1 || [lindex $args 0] > 10} {
            error "CACHE::priority requires an integer from 1 through 10"
        }
        set ::state::cache::priority [lindex $args 0]
        return ""
    }

    proc cache_trace_command {args} {
        variable cache_objects
        if {[llength $args] > 1} { error "CACHE::trace accepts an optional maximum" }
        set maximum [array size cache_objects]
        if {[llength $args] == 1} {
            set maximum [lindex $args 0]
            if {![string is integer -strict $maximum] || $maximum < 0} {
                error "CACHE::trace maximum must be a non-negative integer"
            }
        }
        set output {}
        set index 0
        foreach key [lsort [array names cache_objects]] {
            if {$index >= $maximum} { break }
            lappend output $key
            incr index
        }
        return $output
    }

    proc cache_snapshot {} {
        variable cache_objects
        return [list uri $::state::cache::uri useragent $::state::cache::useragent \
            userkey $::state::cache::userkey accept_encoding $::state::cache::accept_encoding \
            key $::state::cache::key age $::state::cache::age hits $::state::cache::hits \
            fresh $::state::cache::fresh disabled $::state::cache::disabled \
            forced $::state::cache::forced expired $::state::cache::expired \
            priority $::state::cache::priority statskey $::state::cache::statskey \
            stored $::state::cache::stored hit $::state::cache::hit \
            object_count [array size cache_objects]]
    }

    proc cache_accept_encoding_command {args} {
        return [cache_simple_set accept_encoding CACHE::accept_encoding {*}$args]
    }
    proc cache_age_command {args} { return [cache_noarg age CACHE::age {*}$args] }
    proc cache_disabled_command {args} {
        return [cache_noarg disabled CACHE::disabled {*}$args]
    }
    proc cache_fresh_command {args} { return [cache_noarg fresh CACHE::fresh {*}$args] }
    proc cache_headers_command {args} {
        return [cache_noarg headers CACHE::headers {*}$args]
    }
    proc cache_hits_command {args} { return [cache_noarg hits CACHE::hits {*}$args] }
    proc cache_payload_command {args} {
        return [cache_noarg payload CACHE::payload {*}$args]
    }
    proc cache_statskey_command {args} {
        return [cache_noarg statskey CACHE::statskey {*}$args]
    }
    proc cache_uri_command {args} { return [cache_simple_set uri CACHE::uri {*}$args] }
    proc cache_useragent_command {args} {
        return [cache_simple_set useragent CACHE::useragent {*}$args]
    }
    proc cache_userkey_command {args} {
        return [cache_simple_set userkey CACHE::userkey {*}$args]
    }

    proc _datagram_reset_state {} {
        set ::state::datagram::ip_version 4
        set ::state::datagram::ip_tos 0
        set ::state::datagram::ip_ttl 64
        set ::state::datagram::ip_flags 0
        set ::state::datagram::ip_options {}
        set ::state::datagram::ip6_hop_limit 64
        set ::state::datagram::ip6_options {}
        set ::state::datagram::l2_dest ""
        set ::state::datagram::protocol 0
        set ::state::datagram::tcp_flags 0
        set ::state::datagram::tcp_window 0
        set ::state::datagram::tcp_options {}
        set ::state::datagram::payload ""
        set ::state::datagram::payload_length 0
        set ::state::datagram::dns_id 0
        set ::state::datagram::dns_qr 0
        set ::state::datagram::dns_opcode QUERY
        set ::state::datagram::dns_qdcount 0
        set ::state::datagram::dns_ancount 0
        set ::state::datagram::dns_nscount 0
        set ::state::datagram::dns_arcount 0
    }

    proc datagram_reset_connection {} {
        _datagram_reset_state
    }

    proc datagram_prepare_event {} {
        _datagram_reset_state
    }

    proc datagram_sync_from_layers {} {
        if {[info exists ::state::connection::protocol]} {
            set ::state::datagram::protocol $::state::connection::protocol
        }
        foreach field {tos ttl} {
            if {[info exists ::state::connection::$field]} {
                set ::state::datagram::ip_$field [set ::state::connection::$field]
            }
        }
        foreach field {client_addr local_addr server_addr remote_addr} {
            if {[info exists ::state::connection::$field] &&
                [string first ":" [set ::state::connection::$field]] >= 0} {
                set ::state::datagram::ip_version 6
                break
            }
        }
        if {[info exists ::state::udp::payload]} {
            set ::state::datagram::payload $::state::udp::payload
            set ::state::datagram::payload_length \
                [::itest::cmd::_payload_bytelength $::state::udp::payload]
        } elseif {[info exists ::state::connection::client_payload]} {
            set ::state::datagram::payload $::state::connection::client_payload
            set ::state::datagram::payload_length \
                [::itest::cmd::_payload_bytelength $::state::connection::client_payload]
        }
        if {[info exists ::state::dns::id]} {
            foreach field {id qr opcode qdcount ancount nscount arcount} {
                if {[info exists ::state::dns::$field]} {
                    set ::state::datagram::dns_$field [set ::state::dns::$field]
                }
            }
        }
    }

    proc _datagram_require {command_name events} {
        if {![_profile_enabled DATAGRAM]} {
            error "$command_name requires the DATAGRAM profile"
        }
        if {$::itest::current_event ni $events} {
            error "$command_name is not valid in $::itest::current_event"
        }
    }

    proc _datagram_protocol {command_name} {
        set protocol [string tolower $::state::datagram::protocol]
        if {$protocol in {tcp 6}} { return 6 }
        if {$protocol in {udp 17}} { return 17 }
        error "$command_name requires a TCP or UDP datagram"
    }

    proc _datagram_require_protocol {command_name expected} {
        if {[_datagram_protocol $command_name] != $expected} {
            set label [expr {$expected == 6 ? "TCP" : "UDP"}]
            error "$command_name requires a $label datagram"
        }
    }

    proc _datagram_ip_version {command_name} {
        set version $::state::datagram::ip_version
        if {![string is integer -strict $version] || $version ni {4 6}} {
            error "$command_name has an invalid IP version"
        }
        return $version
    }

    proc _datagram_option_query {raw command_name args} {
        if {[llength $args] > 1} {
            error "$command_name accepts at most one option code"
        }
        set filter ""
        if {[llength $args] == 1} {
            set filter [lindex $args 0]
            if {![string is integer -strict $filter] || $filter < 0 || $filter > 255} {
                error "$command_name option code must be an integer from 0 to 255"
            }
        }
        set result {}
        foreach option $raw {
            if {[llength $option] ni {1 2} ||
                ![string is integer -strict [lindex $option 0]] ||
                [lindex $option 0] < 0 || [lindex $option 0] > 255} {
                error "$command_name has an invalid option list"
            }
            if {$filter eq "" || [lindex $option 0] == $filter} {
                lappend result $option
            }
        }
        return $result
    }

    proc _datagram_option_command {raw operation command_name args} {
        set matches [_datagram_option_query $raw $command_name {*}$args]
        if {$operation eq "option_count"} {
            return [llength $matches]
        }
        return $matches
    }

    proc _datagram_dns_port_available {} {
        foreach field {client_port server_port local_port remote_port} {
            if {[info exists ::state::connection::$field]} {
                set value [set ::state::connection::$field]
                if {[string is integer -strict $value] && $value == 53} {
                    return 1
                }
            }
            if {[info exists ::state::udp::$field]} {
                set value [set ::state::udp::$field]
                if {[string is integer -strict $value] && $value == 53} {
                    return 1
                }
            }
        }
        return 0
    }

    proc datagram_ip {args} {
        _datagram_require DATAGRAM::ip {FLOW_INIT}
        if {[_datagram_ip_version DATAGRAM::ip] != 4} {
            error "DATAGRAM::ip requires an IPv4 datagram"
        }
        if {[llength $args] < 1} {
            error "DATAGRAM::ip requires a property"
        }
        set property [lindex $args 0]
        set remaining [lrange $args 1 end]
        switch -exact -- $property {
            tos - ttl - flags {
                if {[llength $remaining] != 0} {
                    error "DATAGRAM::ip $property takes no option code"
                }
                return [set ::state::datagram::ip_$property]
            }
            option - option_count {
                return [_datagram_option_command \
                    $::state::datagram::ip_options $property DATAGRAM::ip {*}$remaining]
            }
            default {
                error "unsupported DATAGRAM::ip property $property"
            }
        }
    }

    proc datagram_ip6 {args} {
        _datagram_require DATAGRAM::ip6 {FLOW_INIT}
        if {[_datagram_ip_version DATAGRAM::ip6] != 6} {
            error "DATAGRAM::ip6 requires an IPv6 datagram"
        }
        if {[llength $args] < 1} {
            error "DATAGRAM::ip6 requires a property"
        }
        set property [lindex $args 0]
        set remaining [lrange $args 1 end]
        switch -exact -- $property {
            hop_limit {
                if {[llength $remaining] != 0} {
                    error "DATAGRAM::ip6 hop_limit takes no option code"
                }
                return $::state::datagram::ip6_hop_limit
            }
            option - option_count {
                return [_datagram_option_command \
                    $::state::datagram::ip6_options $property DATAGRAM::ip6 {*}$remaining]
            }
            default {
                error "unsupported DATAGRAM::ip6 property $property"
            }
        }
    }

    proc datagram_l2 {args} {
        _datagram_require DATAGRAM::l2 {
            FLOW_INIT CLIENT_ACCEPTED SA_PICKED LB_SELECTED CLIENT_DATA
            SERVER_DATA SERVER_CONNECTED
        }
        if {[llength $args] != 1 || [lindex $args 0] ne "dest"} {
            error "DATAGRAM::l2 syntax is dest"
        }
        return $::state::datagram::l2_dest
    }

    proc datagram_tcp {args} {
        _datagram_require DATAGRAM::tcp {FLOW_INIT}
        _datagram_require_protocol DATAGRAM::tcp 6
        if {[llength $args] < 1} {
            error "DATAGRAM::tcp requires a property"
        }
        set property [lindex $args 0]
        set remaining [lrange $args 1 end]
        switch -exact -- $property {
            flags - payload_length - window {
                if {[llength $remaining] != 0} {
                    error "DATAGRAM::tcp $property takes no arguments"
                }
                if {$property eq "payload_length"} {
                    return [::itest::cmd::_payload_bytelength $::state::datagram::payload]
                }
                return [set ::state::datagram::tcp_$property]
            }
            payload {
                if {[llength $remaining] > 1} {
                    error "DATAGRAM::tcp payload accepts an optional size"
                }
                if {[llength $remaining] == 1} {
                    set size [lindex $remaining 0]
                    if {![string is integer -strict $size] || $size < 0} {
                        error "DATAGRAM::tcp payload size must be a non-negative integer"
                    }
                    return [::itest::cmd::_payload_first $::state::datagram::payload $size]
                }
                return $::state::datagram::payload
            }
            option - option_count {
                return [_datagram_option_command \
                    $::state::datagram::tcp_options $property DATAGRAM::tcp {*}$remaining]
            }
            default {
                error "unsupported DATAGRAM::tcp property $property"
            }
        }
    }

    proc datagram_udp {args} {
        _datagram_require DATAGRAM::udp {FLOW_INIT CLIENT_DATA}
        _datagram_require_protocol DATAGRAM::udp 17
        if {[llength $args] < 1 || [llength $args] > 2} {
            error "DATAGRAM::udp syntax is payload, optional size, or payload_length"
        }
        set property [lindex $args 0]
        if {$property eq "payload_length"} {
            if {[llength $args] != 1} {
                error "DATAGRAM::udp payload_length takes no arguments"
            }
            return [::itest::cmd::_payload_bytelength $::state::datagram::payload]
        }
        if {$property ne "payload"} {
            error "unsupported DATAGRAM::udp property $property"
        }
        if {[llength $args] == 2} {
            set size [lindex $args 1]
            if {![string is integer -strict $size] || $size < 0} {
                error "DATAGRAM::udp payload size must be a non-negative integer"
            }
            return [::itest::cmd::_payload_first $::state::datagram::payload $size]
        }
        return $::state::datagram::payload
    }

    proc datagram_dns {args} {
        _datagram_require DATAGRAM::dns {FLOW_INIT CLIENT_DATA}
        set protocol [_datagram_protocol DATAGRAM::dns]
        if {$protocol ni {6 17} || ![_datagram_dns_port_available]} {
            error "DATAGRAM::dns requires TCP or UDP traffic on port 53"
        }
        if {[llength $args] != 1} {
            error "DATAGRAM::dns requires a property"
        }
        set property [lindex $args 0]
        if {$property ni {id qr opcode qdcount ancount nscount arcount}} {
            error "unsupported DATAGRAM::dns property $property"
        }
        if {$property eq "opcode"} {
            set opcode $::state::datagram::dns_opcode
            switch -exact -- $opcode {
                0 - QUERY { return QUERY }
                1 - IQUERY { return IQUERY }
                2 - STATUS { return STATUS }
                4 - NOTIFY { return NOTIFY }
                5 - UPDATE { return UPDATE }
                default { return $opcode }
            }
        }
        return [set ::state::datagram::dns_$property]
    }

    proc udp_reset_connection {} {
        namespace eval ::state::udp {
            variable payload ""
            variable payload_length 0
            variable client_port 0
            variable server_port 0
            variable local_port 0
            variable remote_port 0
            variable mss 1460
            variable max_buf_pkts 0
            variable max_rate 0
            variable sendbuffer 0
            variable debug_queue 0
            variable dropped 0
            variable held 0
            variable released 0
            variable responded 0
            variable response ""
            variable response_length 0
        }
    }

    proc udp_prepare_event {} {
        namespace eval ::state::udp {
            variable payload ""
            variable payload_length 0
            variable dropped 0
            variable released 0
            variable responded 0
            variable response ""
            variable response_length 0
        }
    }

    proc udp_payload_command {args} {
        if {[llength $args] == 0} {
            return $::state::udp::payload
        }
        set subcmd [lindex $args 0]
        switch -exact -- $subcmd {
            length {
                if {[llength $args] != 1} { error "UDP::payload length takes no arguments" }
                return [::itest::cmd::_payload_bytelength $::state::udp::payload]
            }
            replace {
                if {[llength $args] != 4} {
                    error "UDP::payload replace requires offset, length, and data"
                }
                set offset [lindex $args 1]
                set length [lindex $args 2]
                if {![string is integer -strict $offset] || $offset < 0 ||
                    ![string is integer -strict $length] || $length < 0} {
                    error "UDP::payload replace offsets must be non-negative integers"
                }
                set ::state::udp::payload [::itest::cmd::_payload_splice \
                    $::state::udp::payload $offset $length [lindex $args 3]]
                set ::state::udp::payload_length \
                    [::itest::cmd::_payload_bytelength $::state::udp::payload]
                ::itest::log_decision udp payload_replace [list $offset $length]
                return ""
            }
            default {
                if {![string is integer -strict $subcmd] || $subcmd < 0 ||
                    [llength $args] != 1} {
                    error "UDP::payload accepts length, replace, or an optional non-negative size"
                }
                return [::itest::cmd::_payload_first $::state::udp::payload $subcmd]
            }
        }
    }

    proc udp_port_command {which args} {
        if {[llength $args] != 0} { error "UDP::$which takes no arguments" }
        return [set ::state::udp::$which]
    }

    proc udp_client_port_command {args} { return [udp_port_command client_port {*}$args] }
    proc udp_server_port_command {args} { return [udp_port_command server_port {*}$args] }

    proc udp_local_port_command {args} {
        if {[llength $args] > 1} { error "UDP::local_port accepts an optional side" }
        if {[llength $args] == 1} {
            set side [string tolower [lindex $args 0]]
            if {$side ni {clientside serverside}} {
                error "UDP::local_port side must be clientside or serverside"
            }
            return [expr {$side eq "clientside" ? $::state::udp::client_port : $::state::udp::server_port}]
        }
        return $::state::udp::local_port
    }

    proc udp_remote_port_command {args} {
        if {[llength $args] > 1} { error "UDP::remote_port accepts an optional side" }
        if {[llength $args] == 1} {
            set side [string tolower [lindex $args 0]]
            if {$side ni {clientside serverside}} {
                error "UDP::remote_port side must be clientside or serverside"
            }
            return [expr {$side eq "clientside" ? $::state::udp::server_port : $::state::udp::client_port}]
        }
        return $::state::udp::remote_port
    }

    proc udp_integer_setting {name args} {
        if {[llength $args] > 1} { error "UDP::$name accepts an optional non-negative integer" }
        if {[llength $args] == 1} {
            set value [lindex $args 0]
            if {![string is integer -strict $value] || $value < 0} {
                error "UDP::$name requires a non-negative integer"
            }
            set ::state::udp::$name $value
            ::itest::log_decision udp $name $value
        }
        return [set ::state::udp::$name]
    }

    proc udp_max_buf_pkts_command {args} { return [udp_integer_setting max_buf_pkts {*}$args] }
    proc udp_max_rate_command {args} { return [udp_integer_setting max_rate {*}$args] }
    proc udp_sendbuffer_command {args} { return [udp_integer_setting sendbuffer {*}$args] }

    proc udp_mss_command {args} {
        if {[llength $args] != 0} { error "UDP::mss takes no arguments" }
        return $::state::udp::mss
    }

    proc udp_debug_queue_command {args} {
        if {[llength $args] != 1 || [lindex $args 0] ni {enable disable}} {
            error "UDP::debug_queue requires enable or disable"
        }
        set ::state::udp::debug_queue [expr {[lindex $args 0] eq "enable"}]
        ::itest::log_decision udp debug_queue $::state::udp::debug_queue
        return ""
    }

    proc udp_flag_command {name args} {
        if {[llength $args] != 0} { error "UDP::$name takes no arguments" }
        set ::state::udp::$name 1
        ::itest::log_decision udp $name 1
        return ""
    }

    proc udp_drop_command {args} { return [udp_flag_command dropped {*}$args] }
    proc udp_hold_command {args} { return [udp_flag_command held {*}$args] }

    proc udp_release_command {args} {
        if {[llength $args] != 0} { error "UDP::release takes no arguments" }
        set ::state::udp::held 0
        set ::state::udp::released 1
        ::itest::log_decision udp release 1
        return ""
    }

    proc udp_respond_command {args} {
        if {[llength $args] != 1} { error "UDP::respond requires a payload" }
        set ::state::udp::responded 1
        set ::state::udp::response [lindex $args 0]
        set ::state::udp::response_length [string bytelength $::state::udp::response]
        ::itest::log_decision udp respond $::state::udp::response
        return ""
    }

    proc udp_unused_port_command {args} {
        variable udp_unused_port_next
        if {[llength $args] != 3} {
            error "UDP::unused_port requires remote address, remote port, and local address"
        }
        set remote_port [lindex $args 1]
        if {![string is integer -strict $remote_port] || $remote_port < 0 || $remote_port > 65535} {
            error "UDP::unused_port remote port must be an integer from 0 to 65535"
        }
        foreach address [list [lindex $args 0] [lindex $args 2]] {
            if {$address eq ""} { error "UDP::unused_port addresses must not be empty" }
        }
        set result $udp_unused_port_next
        incr udp_unused_port_next
        if {$udp_unused_port_next > 65535} { set udp_unused_port_next 1024 }
        ::itest::log_decision udp unused_port [list [lindex $args 0] $remote_port [lindex $args 2] $result]
        return $result
    }

    proc sctp_reset_connection {} {
        namespace eval ::state::sctp {
            variable payload ""
            variable payload_length 0
            variable client_port 0
            variable server_port 0
            variable local_port 0
            variable remote_port 0
            variable mss 1460
            variable ppi 0
            variable collect_requested 0
            variable collect_length 0
            variable released 0
            variable released_length 0
            variable responded 0
            variable response ""
            variable response_length 0
            variable rto_initial 1000
            variable rto_max 60000
            variable rto_min 100
            variable sack_timeout 200
        }
        unset -nocomplain ::state::vars::connection_vars(__testcl_sctp_collect_client)
        unset -nocomplain ::state::vars::connection_vars(__testcl_sctp_collect_server)
    }

    proc sctp_prepare_event {} {
        namespace eval ::state::sctp {
            variable payload ""
            variable payload_length 0
            variable released 0
            variable released_length 0
            variable responded 0
            variable response ""
            variable response_length 0
        }
    }

    proc sctp_collection_request {side} {
        if {$side ni {client server}} {
            error "SCTP collection side must be client or server"
        }
        set key "__testcl_sctp_collect_$side"
        if {[info exists ::state::vars::connection_vars($key)]} {
            return $::state::vars::connection_vars($key)
        }
        return ""
    }

    proc sctp_clear_collection {side} {
        if {$side ni {client server}} {
            error "SCTP collection side must be client or server"
        }
        unset -nocomplain ::state::vars::connection_vars(__testcl_sctp_collect_$side)
        set ::state::sctp::collect_requested 0
        set ::state::sctp::collect_length 0
    }

    proc sctp_port_command {which args} {
        if {[llength $args] != 0} { error "SCTP::$which takes no arguments" }
        return [set ::state::sctp::$which]
    }

    proc sctp_client_port_command {args} {
        return [sctp_port_command client_port {*}$args]
    }

    proc sctp_server_port_command {args} {
        return [sctp_port_command server_port {*}$args]
    }

    proc sctp_local_port_command {args} {
        if {[llength $args] > 1} {
            error "SCTP::local_port accepts an optional side"
        }
        if {[llength $args] == 1} {
            set side [string tolower [lindex $args 0]]
            if {$side ni {clientside serverside}} {
                error "SCTP::local_port side must be clientside or serverside"
            }
            return $::state::sctp::server_port
        }
        return $::state::sctp::local_port
    }

    proc sctp_remote_port_command {args} {
        if {[llength $args] > 1} {
            error "SCTP::remote_port accepts an optional side"
        }
        if {[llength $args] == 1} {
            set side [string tolower [lindex $args 0]]
            if {$side ni {clientside serverside}} {
                error "SCTP::remote_port side must be clientside or serverside"
            }
            return [expr {$side eq "clientside" ? $::state::sctp::client_port : $::state::sctp::server_port}]
        }
        return $::state::sctp::remote_port
    }

    proc sctp_mss_command {args} {
        if {[llength $args] != 0} { error "SCTP::mss takes no arguments" }
        return $::state::sctp::mss
    }

    proc sctp_ppi_command {args} {
        if {[llength $args] > 1} { error "SCTP::ppi accepts an optional integer" }
        if {[llength $args] == 1} {
            set value [lindex $args 0]
            if {![string is integer -strict $value] || $value < 0 || $value > 65535} {
                error "SCTP::ppi requires an integer from 0 to 65535"
            }
            set ::state::sctp::ppi $value
            ::itest::log_decision sctp ppi $value
        }
        return $::state::sctp::ppi
    }

    proc sctp_collect_command {args} {
        if {[llength $args] > 1} { error "SCTP::collect accepts an optional length" }
        set length 0
        set every_packet 1
        if {[llength $args] == 1} {
            set length [lindex $args 0]
            if {![string is integer -strict $length] || $length <= 0} {
                error "SCTP::collect length must be a positive integer"
            }
            set every_packet 0
        }
        set side [expr {[info exists ::itest::semantic::peer_side] &&
            $::itest::semantic::peer_side eq "server" ? "server" : "client"}]
        set ::state::vars::connection_vars(__testcl_sctp_collect_$side) \
            [list length $length every_packet $every_packet]
        set ::state::sctp::collect_requested 1
        set ::state::sctp::collect_length $length
        ::itest::log_decision sctp collect [list $side $length $every_packet]
        return ""
    }

    proc sctp_payload_command {args} {
        if {[llength $args] == 0} { return $::state::sctp::payload }
        if {[lindex $args 0] eq "length"} {
            if {[llength $args] != 1} { error "SCTP::payload length takes no arguments" }
            return [::itest::cmd::_payload_bytelength $::state::sctp::payload]
        }
        if {[lindex $args 0] eq "replace"} {
            if {[llength $args] != 4} {
                error "SCTP::payload replace requires offset, length, and data"
            }
            set offset [lindex $args 1]
            set length [lindex $args 2]
            if {![string is integer -strict $offset] || $offset < 0 ||
                ![string is integer -strict $length] || $length < 0} {
                error "SCTP::payload replace offsets must be non-negative integers"
            }
            set ::state::sctp::payload [::itest::cmd::_payload_splice \
                $::state::sctp::payload $offset $length [lindex $args 3]]
            set ::state::sctp::payload_length \
                [::itest::cmd::_payload_bytelength $::state::sctp::payload]
            ::itest::log_decision sctp payload_replace [list $offset $length]
            return ""
        }
        if {[llength $args] == 1} {
            set length [lindex $args 0]
            if {![string is integer -strict $length] || $length < 0} {
                error "SCTP::payload accepts a non-negative size"
            }
            return [::itest::cmd::_payload_first $::state::sctp::payload $length]
        }
        if {[llength $args] == 2} {
            set offset [lindex $args 0]
            set length [lindex $args 1]
            if {![string is integer -strict $offset] || $offset < 0 ||
                ![string is integer -strict $length] || $length < 0} {
                error "SCTP::payload offsets must be non-negative integers"
            }
            set tail [string range [binary format a* $::state::sctp::payload] $offset end]
            return [::itest::cmd::_payload_first $tail $length]
        }
        error "SCTP::payload accepts length, offset/length, or replace"
    }

    proc sctp_release_command {args} {
        if {[llength $args] > 1} { error "SCTP::release accepts an optional length" }
        set available [::itest::cmd::_payload_bytelength $::state::sctp::payload]
        set length $available
        if {[llength $args] == 1} { set length [lindex $args 0] }
        if {![string is integer -strict $length] || $length < 0} {
            error "SCTP::release length must be a non-negative integer"
        }
        if {$length > $available} { set length $available }
        if {$length > 0} {
            set ::state::sctp::payload [::itest::cmd::_payload_splice \
                $::state::sctp::payload 0 $length ""]
        }
        set ::state::sctp::payload_length \
            [::itest::cmd::_payload_bytelength $::state::sctp::payload]
        set ::state::sctp::released 1
        set ::state::sctp::released_length $length
        sctp_clear_collection [expr {[info exists ::itest::semantic::peer_side] &&
            $::itest::semantic::peer_side eq "server" ? "server" : "client"}]
        ::itest::log_decision sctp release $length
        return $length
    }

    proc sctp_respond_command {args} {
        if {[llength $args] < 1 || [llength $args] > 3} {
            error "SCTP::respond requires data and optional offset and length"
        }
        set data [lindex $args 0]
        set offset 0
        set length [::itest::cmd::_payload_bytelength $data]
        if {[llength $args] >= 2} { set offset [lindex $args 1] }
        if {[llength $args] == 3} { set length [lindex $args 2] }
        if {![string is integer -strict $offset] || $offset < 0 ||
            ![string is integer -strict $length] || $length < 0} {
            error "SCTP::respond offset and length must be non-negative integers"
        }
        set tail [string range [binary format a* $data] $offset end]
        set ::state::sctp::response [::itest::cmd::_payload_first $tail $length]
        set ::state::sctp::response_length \
            [::itest::cmd::_payload_bytelength $::state::sctp::response]
        set ::state::sctp::responded 1
        ::itest::log_decision sctp respond [list $offset $length]
        return ""
    }

    proc sctp_timeout_command {name args} {
        if {[llength $args] > 1} { error "SCTP::$name accepts an optional side" }
        if {[llength $args] == 1 && [string tolower [lindex $args 0]] ni {clientside serverside}} {
            error "SCTP::$name side must be clientside or serverside"
        }
        return [set ::state::sctp::$name]
    }

    proc sctp_rto_initial_command {args} { return [sctp_timeout_command rto_initial {*}$args] }
    proc sctp_rto_max_command {args} { return [sctp_timeout_command rto_max {*}$args] }
    proc sctp_rto_min_command {args} { return [sctp_timeout_command rto_min {*}$args] }
    proc sctp_sack_timeout_command {args} { return [sctp_timeout_command sack_timeout {*}$args] }

    proc dhcp_reset_connection {} {
        set ::state::dhcp::version 4
        namespace eval ::state::dhcpv4 {
            variable chaddr ""
            variable ciaddr 0.0.0.0
            variable drop 0
            variable giaddr 0.0.0.0
            variable hlen 6
            variable hops 0
            variable len 0
            variable opcode 1
            variable options {}
            variable reject 0
            variable secs 0
            variable siaddr 0.0.0.0
            variable type DISCOVER
            variable xid 0
            variable yiaddr 0.0.0.0
            variable payload ""
            variable payload_length 0
        }
        namespace eval ::state::dhcpv6 {
            variable drop 0
            variable hop_count 0
            variable len 0
            variable link_address ::
            variable msg_type SOLICIT
            variable options {}
            variable peer_address ::
            variable reject 0
            variable transaction_id 000000
            variable payload ""
            variable payload_length 0
        }
    }

    proc dhcp_prepare_event {} {
        set ::state::dhcpv4::drop 0
        set ::state::dhcpv4::reject 0
        set ::state::dhcpv6::drop 0
        set ::state::dhcpv6::reject 0
    }

    proc dhcp_version_command {args} {
        if {[llength $args] != 0} { error "DHCP::version takes no arguments" }
        return $::state::dhcp::version
    }

    proc dhcp_field_command {family field args} {
        if {[llength $args] != 0} { error "DHCP${family}::$field takes no arguments" }
        return [set ::state::dhcp${family}::$field]
    }

    proc dhcp_flag_command {family field args} {
        if {[llength $args] != 0} { error "DHCP${family}::$field takes no arguments" }
        set ::state::dhcp${family}::$field 1
        ::itest::log_decision dhcp${family} $field 1
        return ""
    }

    proc dhcp_option_id {family value} {
        if {![string is integer -strict $value] || $value < 0 || $value > 65535} {
            error "DHCP${family}::option ID must be an integer from 0 to 65535"
        }
        return [expr {int($value)}]
    }

    proc dhcp_option_command {family args} {
        set namespace "::state::dhcp${family}"
        if {[llength $args] == 0 || [llength $args] > 3} {
            error "DHCP${family}::option requires an ID and optional value"
        }
        set operation get
        set id_index 0
        if {[lindex $args 0] eq "delete"} {
            if {$family ne "v6" || [llength $args] != 2} {
                set version [expr {$family eq "v4" ? 4 : 6}]
                error "DHCPv${version}::option delete is not valid"
            }
            set operation delete
            set id_index 1
        }
        set id [dhcp_option_id $family [lindex $args $id_index]]
        set options [set ${namespace}::options]
        if {$operation eq "delete"} {
            dict unset options $id
            set ${namespace}::options $options
            ::itest::log_decision dhcp${family} option_delete $id
            return ""
        }
        if {[llength $args] == $id_index + 1} {
            if {[dict exists $options $id]} { return [dict get $options $id] }
            return ""
        }
        if {[llength $args] != $id_index + 2} {
            error "DHCP${family}::option accepts one optional value"
        }
        set value [lindex $args [expr {$id_index + 1}]]
        dict set options $id $value
        set ${namespace}::options $options
        ::itest::log_decision dhcp${family} option_set [list $id $value]
        return ""
    }

    proc dhcpv4_chaddr_command {args} { return [dhcp_field_command v4 chaddr {*}$args] }
    proc dhcpv4_ciaddr_command {args} { return [dhcp_field_command v4 ciaddr {*}$args] }
    proc dhcpv4_drop_command {args} { return [dhcp_flag_command v4 drop {*}$args] }
    proc dhcpv4_giaddr_command {args} { return [dhcp_field_command v4 giaddr {*}$args] }
    proc dhcpv4_hlen_command {args} { return [dhcp_field_command v4 hlen {*}$args] }
    proc dhcpv4_hops_command {args} { return [dhcp_field_command v4 hops {*}$args] }
    proc dhcpv4_len_command {args} { return [dhcp_field_command v4 len {*}$args] }
    proc dhcpv4_opcode_command {args} { return [dhcp_field_command v4 opcode {*}$args] }
    proc dhcpv4_option_command {args} { return [dhcp_option_command v4 {*}$args] }
    proc dhcpv4_reject_command {args} { return [dhcp_flag_command v4 reject {*}$args] }
    proc dhcpv4_secs_command {args} { return [dhcp_field_command v4 secs {*}$args] }
    proc dhcpv4_siaddr_command {args} { return [dhcp_field_command v4 siaddr {*}$args] }
    proc dhcpv4_type_command {args} { return [dhcp_field_command v4 type {*}$args] }
    proc dhcpv4_xid_command {args} { return [dhcp_field_command v4 xid {*}$args] }
    proc dhcpv4_yiaddr_command {args} { return [dhcp_field_command v4 yiaddr {*}$args] }
    proc dhcpv6_drop_command {args} { return [dhcp_flag_command v6 drop {*}$args] }
    proc dhcpv6_hop_count_command {args} { return [dhcp_field_command v6 hop_count {*}$args] }
    proc dhcpv6_len_command {args} { return [dhcp_field_command v6 len {*}$args] }
    proc dhcpv6_link_address_command {args} { return [dhcp_field_command v6 link_address {*}$args] }
    proc dhcpv6_msg_type_command {args} { return [dhcp_field_command v6 msg_type {*}$args] }
    proc dhcpv6_option_command {args} { return [dhcp_option_command v6 {*}$args] }
    proc dhcpv6_peer_address_command {args} { return [dhcp_field_command v6 peer_address {*}$args] }
    proc dhcpv6_reject_command {args} { return [dhcp_flag_command v6 reject {*}$args] }
    proc dhcpv6_transaction_id_command {args} { return [dhcp_field_command v6 transaction_id {*}$args] }

    proc ftp_reset_connection {} {
        foreach {name value} {
            allow_active_mode disable
            command ""
            disabled 0
            enabled 1
            enforce_tls_session_reuse disable
            ftps_mode allow
            payload ""
            payload_length 0
            port_first 1024
            port_last 65535
            response_code 0
            tls_active 0
            tls_session_reused 0
            type command
            dropped 0
            rejected 0
        } {
            set ::state::ftp::$name $value
        }
    }

    proc ftp_prepare_event {} {
        set ::state::ftp::dropped 0
        set ::state::ftp::rejected 0
    }

    proc ftp_toggle_command {field command_name args} {
        if {[llength $args] > 1} {
            error "$command_name accepts zero or one argument"
        }
        set variable_name ::state::ftp::$field
        if {[llength $args] == 0} {
            return [set $variable_name]
        }
        set value [string tolower [lindex $args 0]]
        if {$value ni {enable disable}} {
            error "$command_name requires enable or disable"
        }
        set $variable_name $value
        ::itest::log_decision ftp ${field}_set $value
        return $value
    }

    proc ftp_disable_command {args} {
        if {[llength $args] != 0} { error "FTP::disable takes no arguments" }
        set ::state::ftp::enabled 0
        set ::state::ftp::disabled 1
        ::itest::log_decision ftp disable 1
        return ""
    }

    proc ftp_enable_command {args} {
        if {[llength $args] != 0} { error "FTP::enable takes no arguments" }
        set ::state::ftp::enabled 1
        set ::state::ftp::disabled 0
        ::itest::log_decision ftp enable 1
        return ""
    }

    proc ftp_allow_active_mode_command {args} {
        return [ftp_toggle_command allow_active_mode FTP::allow_active_mode {*}$args]
    }

    proc ftp_enforce_tls_session_reuse_command {args} {
        return [ftp_toggle_command enforce_tls_session_reuse FTP::enforce_tls_session_reuse {*}$args]
    }

    proc ftp_ftps_mode_command {args} {
        if {[llength $args] > 1} {
            error "FTP::ftps_mode accepts zero or one argument"
        }
        if {[llength $args] == 0} {
            return $::state::ftp::ftps_mode
        }
        set mode [string tolower [lindex $args 0]]
        if {$mode ni {disallow allow require}} {
            error "FTP::ftps_mode requires disallow, allow, or require"
        }
        set ::state::ftp::ftps_mode $mode
        ::itest::log_decision ftp ftps_mode $mode
        return $mode
    }

    proc ftp_port_command {args} {
        if {[llength $args] ni {1 2}} {
            error "FTP::port requires FIRST and optional LAST"
        }
        set first [lindex $args 0]
        set last $first
        if {[llength $args] == 2} {
            set last [lindex $args 1]
        }
        foreach {name value} [list FIRST $first LAST $last] {
            if {![string is integer -strict $value] || $value < 1 || $value > 65535} {
                error "FTP::port $name must be an integer from 1 to 65535"
            }
        }
        if {$first > $last} {
            error "FTP::port FIRST must not exceed LAST"
        }
        set ::state::ftp::port_first $first
        set ::state::ftp::port_last $last
        ::itest::log_decision ftp port [list $first $last]
        return ""
    }

    proc starttls_reset_connection {protocol} {
        foreach {name value} {
            activation_mode none
            command ""
            disabled 0
            enabled 1
            payload ""
            payload_length 0
            tls_active 0
            type command
        } {
            set ::state::${protocol}::$name $value
        }
    }

    proc starttls_prepare_event {protocol} {}

    proc imap_reset_connection {} { starttls_reset_connection imap }
    proc imap_prepare_event {} { starttls_prepare_event imap }
    proc pop3_reset_connection {} { starttls_reset_connection pop3 }
    proc pop3_prepare_event {} { starttls_prepare_event pop3 }
    proc ldap_reset_connection {} { starttls_reset_connection ldap }
    proc ldap_prepare_event {} { starttls_prepare_event ldap }

    proc _starttls_require_event {allowed command_name} {
        if {$allowed ne "ANY_EVENT" && $::itest::current_event ni $allowed} {
            error "$command_name is not valid during $::itest::current_event"
        }
    }

    proc starttls_activation_mode_command {protocol command_name allowed args} {
        _starttls_require_event $allowed $command_name
        if {[llength $args] > 1} {
            error "$command_name accepts zero or one argument"
        }
        set variable_name ::state::${protocol}::activation_mode
        if {[llength $args] == 0} {
            return [set $variable_name]
        }
        set mode [string tolower [lindex $args 0]]
        if {$mode ni {none allow require}} {
            error "$command_name requires none, allow, or require"
        }
        set $variable_name $mode
        ::itest::log_decision $protocol activation_mode $mode
        return ""
    }

    proc starttls_toggle_command {protocol command_name allowed enabled args} {
        _starttls_require_event $allowed $command_name
        if {[llength $args] != 0} {
            error "$command_name takes no arguments"
        }
        set enabled_value [expr {$enabled ? 1 : 0}]
        set ::state::${protocol}::enabled $enabled_value
        set ::state::${protocol}::disabled [expr {!$enabled_value}]
        ::itest::log_decision $protocol [expr {$enabled_value ? "enable" : "disable"}] 1
        return ""
    }

    proc imap_activation_mode_command {args} {
        return [starttls_activation_mode_command imap IMAP::activation_mode {ANY_EVENT} {*}$args]
    }

    proc imap_enable_command {args} {
        return [starttls_toggle_command imap IMAP::enable {SERVER_CONNECTED CLIENT_ACCEPTED} 1 {*}$args]
    }

    proc imap_disable_command {args} {
        return [starttls_toggle_command imap IMAP::disable {ANY_EVENT} 0 {*}$args]
    }

    proc pop3_activation_mode_command {args} {
        return [starttls_activation_mode_command pop3 POP3::activation_mode {SERVER_CONNECTED CLIENT_ACCEPTED} {*}$args]
    }

    proc pop3_enable_command {args} {
        return [starttls_toggle_command pop3 POP3::enable {ANY_EVENT} 1 {*}$args]
    }

    proc pop3_disable_command {args} {
        return [starttls_toggle_command pop3 POP3::disable {ANY_EVENT} 0 {*}$args]
    }

    proc ldap_activation_mode_command {args} {
        return [starttls_activation_mode_command ldap LDAP::activation_mode {SERVER_CONNECTED CLIENT_ACCEPTED} {*}$args]
    }

    proc ldap_enable_command {args} {
        return [starttls_toggle_command ldap LDAP::enable {SERVER_CONNECTED CLIENT_ACCEPTED} 1 {*}$args]
    }

    proc ldap_disable_command {args} {
        return [starttls_toggle_command ldap LDAP::disable {SERVER_CONNECTED CLIENT_ACCEPTED} 0 {*}$args]
    }

    proc smtps_reset_connection {} { starttls_reset_connection smtps }
    proc smtps_prepare_event {} { starttls_prepare_event smtps }

    proc smtps_activation_mode_command {args} {
        return [starttls_activation_mode_command smtps SMTPS::activation_mode {SERVER_CONNECTED CLIENT_ACCEPTED} {*}$args]
    }

    proc smtps_enable_command {args} {
        return [starttls_toggle_command smtps SMTPS::enable {ANY_EVENT} 1 {*}$args]
    }

    proc smtps_disable_command {args} {
        return [starttls_toggle_command smtps SMTPS::disable {ANY_EVENT} 0 {*}$args]
    }

    proc ntlm_reset_connection {} {
        set ::state::ntlm::disabled 0
        set ::state::ntlm::enabled 1
        set ::state::ntlm::payload ""
        set ::state::ntlm::payload_length 0
    }

    proc ntlm_prepare_event {} {}

    proc ntlm_toggle_command {command_name enabled args} {
        if {[llength $args] != 0} {
            error "$command_name takes no arguments"
        }
        set enabled_value [expr {$enabled ? 1 : 0}]
        set ::state::ntlm::enabled $enabled_value
        set ::state::ntlm::disabled [expr {!$enabled_value}]
        ::itest::log_decision ntlm [expr {$enabled_value ? "enable" : "disable"}] 1
        return ""
    }

    proc ntlm_enable_command {args} {
        return [ntlm_toggle_command NTLM::enable 1 {*}$args]
    }

    proc ntlm_disable_command {args} {
        return [ntlm_toggle_command NTLM::disable 0 {*}$args]
    }

    proc protocol_inspection_reset_connection {} {
        set ::state::protocol_inspection::disabled 0
        set ::state::protocol_inspection::enabled 1
        set ::state::protocol_inspection::ids {}
        set ::state::protocol_inspection::matched 0
        set ::state::protocol_inspection::payload ""
        set ::state::protocol_inspection::payload_length 0
    }

    proc protocol_inspection_prepare_event {} {}

    proc _protocol_inspection_require_match {command_name} {
        if {$::itest::current_event ne "PROTOCOL_INSPECTION_MATCH"} {
            error "$command_name is not valid during $::itest::current_event"
        }
    }

    proc protocol_inspection_disable_command {args} {
        _protocol_inspection_require_match PROTOCOL_INSPECTION::disable
        if {[llength $args] != 0} {
            error "PROTOCOL_INSPECTION::disable takes no arguments"
        }
        set ::state::protocol_inspection::enabled 0
        set ::state::protocol_inspection::disabled 1
        ::itest::log_decision protocol_inspection disable 1
        return ""
    }

    proc protocol_inspection_id_command {args} {
        _protocol_inspection_require_match PROTOCOL_INSPECTION::id
        if {[llength $args] != 0} {
            error "PROTOCOL_INSPECTION::id takes no arguments"
        }
        return $::state::protocol_inspection::ids
    }

    proc classification_reset_connection {} {
        foreach {name value} {
            app ""
            category ""
            classify_application_add {}
            classify_application_set ""
            classify_additions {}
            classify_category_add {}
            classify_category_set ""
            classify_classified 0
            classify_defer 0
            classify_urlcat_add {}
            classify_urlcat_set ""
            classify_username ""
            classify_username_context ""
            detected 1
            deferred 0
            disabled 0
            enabled 1
            payload ""
            payload_length 0
            protocol ""
            result {}
            urlcat ""
            username ""
        } {
            set ::state::classification::$name $value
        }
    }

    proc classification_prepare_event {} {}

    proc _classification_require_detected {command_name} {
        if {$::itest::current_event ne "CLASSIFICATION_DETECTED"} {
            error "$command_name is not valid during $::itest::current_event"
        }
    }

    proc classification_field_command {field command_name args} {
        _classification_require_detected $command_name
        if {[llength $args] != 0} {
            error "$command_name takes no arguments"
        }
        return [set ::state::classification::$field]
    }

    proc classification_toggle_command {command_name enabled args} {
        if {[llength $args] != 0} {
            error "$command_name takes no arguments"
        }
        set enabled_value [expr {$enabled ? 1 : 0}]
        set ::state::classification::enabled $enabled_value
        set ::state::classification::disabled [expr {!$enabled_value}]
        ::itest::log_decision classification [expr {$enabled_value ? "enable" : "disable"}] 1
        return ""
    }

    proc classification_app_command {args} {
        return [classification_field_command app CLASSIFICATION::app {*}$args]
    }

    proc classification_category_command {args} {
        return [classification_field_command category CLASSIFICATION::category {*}$args]
    }

    proc classification_disable_command {args} {
        return [classification_toggle_command CLASSIFICATION::disable 0 {*}$args]
    }

    proc classification_enable_command {args} {
        return [classification_toggle_command CLASSIFICATION::enable 1 {*}$args]
    }

    proc classification_protocol_command {args} {
        return [classification_field_command protocol CLASSIFICATION::protocol {*}$args]
    }

    proc classification_result_command {args} {
        return [classification_field_command result CLASSIFICATION::result {*}$args]
    }

    proc classification_urlcat_command {args} {
        return [classification_field_command urlcat CLASSIFICATION::urlcat {*}$args]
    }

    proc classification_username_command {args} {
        return [classification_field_command username CLASSIFICATION::username {*}$args]
    }

    proc _classify_require_http {command_name} {
        if {$::itest::current_event ni {HTTP_REQUEST HTTP_RESPONSE}} {
            error "$command_name is not valid during $::itest::current_event"
        }
    }

    proc _classify_require_value {command_name value} {
        if {$value eq "" || [string first "\x00" $value] >= 0} {
            error "$command_name requires a non-empty value without NUL bytes"
        }
    }

    proc _classify_set_or_add {kind command_name args} {
        _classify_require_http $command_name
        if {[llength $args] != 2} {
            error "$command_name requires set or add and a value"
        }
        set operation [lindex $args 0]
        set value [lindex $args 1]
        if {$operation ni {set add}} {
            error "$command_name requires set or add"
        }
        _classify_require_value $command_name $value
        if {$::state::classification::classify_classified} {
            ::itest::log_decision classify "${kind}_${operation}_ignored" $value
            return ""
        }
        if {$operation eq "set"} {
            set ::state::classification::classify_${kind}_set $value
            set ::state::classification::$kind $value
            set ::state::classification::classify_classified 1
        } else {
            set additions [set ::state::classification::classify_${kind}_add]
            lappend additions $value
            set ::state::classification::classify_${kind}_add $additions
            set ordered_additions $::state::classification::classify_additions
            lappend ordered_additions [list $kind $value]
            set ::state::classification::classify_additions $ordered_additions
        }
        ::itest::log_decision classify "${kind}_${operation}" $value
        return ""
    }

    proc classify_application_command {args} {
        return [_classify_set_or_add application CLASSIFY::application {*}$args]
    }

    proc classify_category_command {args} {
        return [_classify_set_or_add category CLASSIFY::category {*}$args]
    }

    proc classify_urlcat_command {args} {
        return [_classify_set_or_add urlcat CLASSIFY::urlcat {*}$args]
    }

    proc classify_defer_command {args} {
        if {$::itest::current_event ne "FLOW_INIT"} {
            error "CLASSIFY::defer is not valid during $::itest::current_event"
        }
        if {[llength $args] != 0} {
            error "CLASSIFY::defer takes no arguments"
        }
        set ::state::classification::classify_defer 1
        ::itest::log_decision classify defer 1
        return ""
    }

    proc classify_disable_command {args} {
        if {[llength $args] != 0} {
            error "CLASSIFY::disable takes no arguments"
        }
        set ::state::classification::enabled 0
        set ::state::classification::disabled 1
        ::itest::log_decision classify disable 1
        return ""
    }

    proc classify_username_command {args} {
        if {[llength $args] ni {1 2}} {
            error "CLASSIFY::username requires a username and optional context"
        }
        set username [lindex $args 0]
        _classify_require_value CLASSIFY::username $username
        set context ""
        if {[llength $args] == 2} {
            set context [lindex $args 1]
            if {[string first "\x00" $context] >= 0} {
                error "CLASSIFY::username context cannot contain NUL bytes"
            }
        }
        set ::state::classification::classify_username $username
        set ::state::classification::classify_username_context $context
        set ::state::classification::username $username
        ::itest::log_decision classify username [list $username $context]
        return ""
    }

    proc classification_apply_overrides {} {
        set result $::state::classification::result
        if {$::state::classification::classify_classified} {
            foreach {field value} {
                classify_application_set app
                classify_category_set category
                classify_urlcat_set urlcat
            } {
                set override [set ::state::classification::$field]
                if {$override ne ""} {
                    set ::state::classification::$value $override
                    set result [list $override]
                    break
                }
            }
        } else {
            foreach addition $::state::classification::classify_additions {
                lassign $addition kind value
                lappend result $value
            }
        }
        if {$::state::classification::classify_username ne ""} {
            set ::state::classification::username $::state::classification::classify_username
        }
        set ::state::classification::result $result
        # CLASSIFY::set/add only affect classification before the engine has
        # produced its result. Prevent pending additions from being replayed
        # if a synthetic trace supplies another detection on this connection.
        set ::state::classification::classify_classified 1
        return ""
    }

    proc category_reset_connection {} {
        foreach {name value} {
            analytics disable
            categories {}
            detected 1
            filetype_mimetype application/octet-stream
            filetype_mimesubtype octet-stream
            lookup_url ""
            matchtype request_default
            matched 1
            payload ""
            payload_length 0
            safesearch {}
            url ""
        } {
            set ::state::category::$name $value
        }
    }

    proc category_prepare_event {} {}

    proc _category_require_event {allowed command_name} {
        if {$::itest::current_event ni $allowed} {
            error "$command_name is not valid during $::itest::current_event"
        }
    }

    proc category_analytics_command {args} {
        _category_require_event {HTTP_REQUEST HTTP_RESPONSE} CATEGORY::analytics
        if {[llength $args] != 1} {
            error "CATEGORY::analytics requires enable or disable"
        }
        set value [string tolower [lindex $args 0]]
        if {$value ni {enable disable}} {
            error "CATEGORY::analytics requires enable or disable"
        }
        set ::state::category::analytics $value
        ::itest::log_decision category analytics $value
        return ""
    }

    proc category_lookup_command {args} {
        if {[llength $args] < 1} {
            error "CATEGORY::lookup requires a URL"
        }
        set lookup_url [lindex $args 0]
        if {$lookup_url eq ""} {
            error "CATEGORY::lookup requires a non-empty URL"
        }
        set display 0
        set mode request_default
        set mode_seen 0
        set ip ""
        set custom_category ""
        set seen_display 0
        set seen_ip 0
        set seen_custom 0
        for {set index 1} {$index < [llength $args]} {incr index} {
            set option [lindex $args $index]
            switch -- $option {
                -display {
                    if {$seen_display} { error "CATEGORY::lookup received duplicate -display" }
                    set seen_display 1
                    set display 1
                }
                request_default -
                request_default_and_custom -
                custom {
                    if {$mode_seen} { error "CATEGORY::lookup received duplicate category type" }
                    set mode $option
                    set mode_seen 1
                }
                -ip {
                    if {$seen_ip} { error "CATEGORY::lookup received duplicate -ip" }
                    incr index
                    if {$index >= [llength $args] || [lindex $args $index] eq "" ||
                        [lindex $args $index] in {-display request_default request_default_and_custom custom -ip -custom_cat_match}} {
                        error "CATEGORY::lookup -ip requires a value"
                    }
                    set ip [lindex $args $index]
                    set seen_ip 1
                }
                -custom_cat_match {
                    if {$seen_custom} { error "CATEGORY::lookup received duplicate -custom_cat_match" }
                    incr index
                    if {$index >= [llength $args] || [lindex $args $index] eq "" ||
                        [lindex $args $index] in {-display request_default request_default_and_custom custom -ip -custom_cat_match}} {
                        error "CATEGORY::lookup -custom_cat_match requires a value"
                    }
                    set custom_category [lindex $args $index]
                    set seen_custom 1
                }
                default {
                    error "CATEGORY::lookup received unknown option $option"
                }
            }
        }
        set ::state::category::lookup_url $lookup_url
        ::itest::log_decision category lookup [list $lookup_url $mode $display $ip $custom_category]
        return $::state::category::categories
    }

    proc category_safesearch_command {args} {
        _category_require_event {HTTP_REQUEST} CATEGORY::safesearch
        if {[llength $args] != 1 || [lindex $args 0] eq ""} {
            error "CATEGORY::safesearch requires a non-empty URL"
        }
        set ::state::category::lookup_url [lindex $args 0]
        ::itest::log_decision category safesearch $::state::category::lookup_url
        return $::state::category::safesearch
    }

    proc _category_require_match {command_name} {
        if {$::itest::current_event ne "CATEGORY_MATCHED"} {
            error "$command_name is not valid during $::itest::current_event"
        }
    }

    proc category_matchtype_command {args} {
        _category_require_match CATEGORY::matchtype
        if {[llength $args] != 1 || [lindex $args 0] eq ""} {
            error "CATEGORY::matchtype requires a variable name"
        }
        # The command reaches this proc through the unknown-command
        # dispatcher, so the iRule handler is two frames up.
        upvar 2 [lindex $args 0] matchtype_target
        set matchtype_target $::state::category::matchtype
        return $::state::category::matchtype
    }

    proc category_result_command {args} {
        _category_require_match CATEGORY::result
        if {[llength $args] < 1 || [llength $args] > 3} {
            error "CATEGORY::result requires category or safesearch"
        }
        set result_type [lindex $args 0]
        if {$result_type eq "safesearch"} {
            if {[llength $args] != 1} {
                error "CATEGORY::result safesearch takes no options"
            }
            return $::state::category::safesearch
        }
        if {$result_type ne "category"} {
            error "CATEGORY::result requires category or safesearch"
        }
        set display 0
        set mode ""
        foreach option [lrange $args 1 end] {
            if {$option eq "-display"} {
                if {$display} { error "CATEGORY::result received duplicate -display" }
                set display 1
            } elseif {$option in {custom request_default request_default_and_custom}} {
                if {$mode ne ""} { error "CATEGORY::result received duplicate category type" }
                set mode $option
            } else {
                error "CATEGORY::result received unknown option $option"
            }
        }
        return $::state::category::categories
    }

    proc category_filetype_command {args} {
        _category_require_event {HTTP_RESPONSE_DATA} CATEGORY::filetype
        if {[llength $args] < 3} {
            error "CATEGORY::filetype requires a payload and an output variable"
        }
        set remaining [lrange $args 1 end]
        if {[llength $remaining] % 2 != 0} {
            error "CATEGORY::filetype options require variable names"
        }
        set got_option 0
        set got_mimetype 0
        set got_mimesubtype 0
        foreach {option variable_name} $remaining {
            if {$variable_name eq ""} {
                error "CATEGORY::filetype requires a non-empty variable name"
            }
            switch -- $option {
                -mimetype {
                    if {$got_mimetype} { error "CATEGORY::filetype received duplicate -mimetype" }
                    upvar 2 $variable_name mimetype_target
                    set mimetype_target $::state::category::filetype_mimetype
                    set got_mimetype 1
                    set got_option 1
                }
                -mimesubtype {
                    if {$got_mimesubtype} { error "CATEGORY::filetype received duplicate -mimesubtype" }
                    upvar 2 $variable_name mimesubtype_target
                    set mimesubtype_target $::state::category::filetype_mimesubtype
                    set got_mimesubtype 1
                    set got_option 1
                }
                default {
                    error "CATEGORY::filetype received unknown option $option"
                }
            }
        }
        if {!$got_option} {
            error "CATEGORY::filetype requires -mimetype and/or -mimesubtype"
        }
        return ""
    }

    proc icap_reset_connection {} {
        set ::state::icap::headers [list Host icap.example.net]
        set ::state::icap::method REQMOD
        set ::state::icap::payload ""
        set ::state::icap::payload_length 0
        set ::state::icap::status 200
        set ::state::icap::type request
        set ::state::icap::uri icap://icap.example.net/reqmod
    }

    proc icap_prepare_event {} {}

    proc _icap_require_event {allowed command_name} {
        if {$::itest::current_event ni $allowed} {
            error "$command_name is not valid during $::itest::current_event"
        }
    }

    proc _icap_header_matches {actual wanted} {
        return [string equal -nocase $actual $wanted]
    }

    proc _icap_header_names {headers} {
        set names {}
        foreach {name value} $headers {
            lappend names $name
        }
        return $names
    }

    proc icap_header_parse_text {text} {
        set headers {}
        set normalised [string map {\r\n \n \r \n} $text]
        foreach line [split $normalised \n] {
            if {$line eq ""} { continue }
            set colon [string first : $line]
            if {$colon <= 0} {
                error "ICAP header text must contain name/value lines"
            }
            set name [string trim [string range $line 0 [expr {$colon - 1}]]]
            set value [string trim [string range $line [expr {$colon + 1}] end]]
            if {$name eq ""} { error "ICAP header name cannot be empty" }
            lappend headers $name $value
        }
        return $headers
    }

    proc icap_header_command {args} {
        _icap_require_event {ICAP_REQUEST ICAP_RESPONSE} ICAP::header
        if {[llength $args] == 0} {
            error "ICAP::header requires a subcommand"
        }
        set subcommand [string tolower [lindex $args 0]]
        set headers $::state::icap::headers
        switch -exact -- $subcommand {
            names {
                if {[llength $args] != 1} { error "ICAP::header names takes no arguments" }
                return [_icap_header_names $headers]
            }
            at {
                if {[llength $args] != 2 || ![string is integer -strict [lindex $args 1]] || [lindex $args 1] < 0} {
                    error "ICAP::header at requires a non-negative index"
                }
                set names [_icap_header_names $headers]
                set index [lindex $args 1]
                if {$index >= [llength $names]} { return "" }
                return [lindex $names $index]
            }
            count {
                if {[llength $args] > 2} { error "ICAP::header count accepts an optional name" }
                if {[llength $args] == 1} { return [expr {[llength $headers] / 2}] }
                set count 0
                foreach {name value} $headers {
                    if {[_icap_header_matches $name [lindex $args 1]]} { incr count }
                }
                return $count
            }
            exists {
                if {[llength $args] != 2} { error "ICAP::header exists requires a name" }
                foreach {name value} $headers {
                    if {[_icap_header_matches $name [lindex $args 1]] && $value ne ""} {
                        return 1
                    }
                }
                return 0
            }
            values {
                if {[llength $args] != 2} { error "ICAP::header values requires a name" }
                set values {}
                foreach {name value} $headers {
                    if {[_icap_header_matches $name [lindex $args 1]]} { lappend values $value }
                }
                if {[llength $values] == 1} { return [lindex $values 0] }
                return $values
            }
            value {
                if {[llength $args] ni {2 3}} { error "ICAP::header value requires a name and optional value" }
                set wanted [lindex $args 1]
                set matches {}
                set position 0
                foreach {name item} $headers {
                    if {[_icap_header_matches $name $wanted]} { lappend matches $position }
                    incr position 2
                }
                if {[llength $args] == 2} {
                    if {[llength $matches] == 0} { return "" }
                    return [lindex $headers [expr {[lindex $matches end] + 1}]]
                }
                set replacement [lindex $args 2]
                if {[llength $matches] == 0} {
                    lappend headers $wanted $replacement
                } else {
                    set pair [lindex $matches end]
                    lset headers [expr {$pair + 1}] $replacement
                }
                set ::state::icap::headers $headers
            }
            add {
                if {[llength $args] != 3} { error "ICAP::header add requires name and value" }
                set name [lindex $args 1]
                if {$name eq ""} { error "ICAP header name cannot be empty" }
                lappend headers $name [lindex $args 2]
                set ::state::icap::headers $headers
            }
            replace {
                if {[llength $args] != 3} { error "ICAP::header replace requires name and value" }
                set wanted [lindex $args 1]
                set replacement [lindex $args 2]
                set position 0
                set last -1
                foreach {name value} $headers {
                    if {[_icap_header_matches $name $wanted]} { set last $position }
                    incr position 2
                }
                if {$last < 0} {
                    lappend headers $wanted $replacement
                } else {
                    lset headers [expr {$last + 1}] $replacement
                }
                set ::state::icap::headers $headers
            }
            remove {
                if {[llength $args] != 2} { error "ICAP::header remove requires a name" }
                set wanted [lindex $args 1]
                set updated {}
                foreach {name value} $headers {
                    if {![_icap_header_matches $name $wanted]} { lappend updated $name $value }
                }
                set ::state::icap::headers $updated
            }
            replace-all {
                if {[llength $args] != 2} { error "ICAP::header replace-all requires header text" }
                set ::state::icap::headers [icap_header_parse_text [lindex $args 1]]
            }
            default { error "unsupported ICAP::header subcommand $subcommand" }
        }
        ::itest::log_decision icap header [list $subcommand]
        return ""
    }

    proc icap_method_command {args} {
        _icap_require_event {ICAP_REQUEST} ICAP::method
        if {[llength $args] != 0} { error "ICAP::method takes no arguments" }
        return $::state::icap::method
    }

    proc icap_status_command {args} {
        _icap_require_event {ICAP_RESPONSE} ICAP::status
        if {[llength $args] != 0} { error "ICAP::status takes no arguments" }
        return $::state::icap::status
    }

    proc icap_uri_command {args} {
        _icap_require_event {ICAP_REQUEST} ICAP::uri
        if {[llength $args] > 1} { error "ICAP::uri accepts an optional URI" }
        if {[llength $args] == 1} {
            set ::state::icap::uri [lindex $args 0]
            ::itest::log_decision icap uri $::state::icap::uri
        }
        return $::state::icap::uri
    }

    proc tcp_reset_transport {} {
        namespace eval ::state::tcp {
            set abc enable
            set analytics disable
            set analytics_key ""
            set autowin enable
            set delayed_ack enable
            set dsack enable
            set earlyrxmit enable
            set ecn enable
            set enhanced_loss_recovery enable
            set limxmit enable
            set lossfilter_rate 0
            set lossfilter_burst 0
            set nagle auto
            set naglemode auto
            set naglestate enabled
            set keepalive 0
            set idletime 300
            set sendbuf 0
            set recvwnd 0
            set rcv_size 65535
            set snd_wnd 65535
            set snd_cwnd 14600
            set rto 1000
            set rttvar 0
            set rexmt_thresh 3
            set rt_metrics_timeout 0
            set rcv_scale 0
            set snd_scale 0
            set snd_ssthresh 1073725440
            set pacing 0
            set proxybuffer_high 0
            set proxybuffer_low 0
            set push_flag default
            set congestion ""
        }
    }

    proc _tcp_bool_word {value command} {
        set value [string tolower $value]
        if {$value in {enable enabled 1 true yes}} { return enable }
        if {$value in {disable disabled 0 false no}} { return disable }
        error "$command requires enable or disable"
    }

    proc tcp_toggle_command {name args} {
        if {[llength $args] != 1} {
            error "TCP::$name requires enable or disable"
        }
        set value [_tcp_bool_word [lindex $args 0] TCP::$name]
        set ::state::tcp::$name $value
        ::itest::log_decision tcp $name $value
        return ""
    }

    proc tcp_optional_toggle_command {name args} {
        if {[llength $args] > 1} {
            error "TCP::$name accepts an optional enable or disable"
        }
        if {[llength $args] == 1} {
            set value [_tcp_bool_word [lindex $args 0] TCP::$name]
            set ::state::tcp::$name $value
            ::itest::log_decision tcp $name $value
        }
        return [set ::state::tcp::$name]
    }

    proc tcp_abc_command {args} { return [tcp_toggle_command abc {*}$args] }
    proc tcp_autowin_command {args} { return [tcp_toggle_command autowin {*}$args] }
    proc tcp_delayed_ack_command {args} { return [tcp_toggle_command delayed_ack {*}$args] }
    proc tcp_dsack_command {args} { return [tcp_toggle_command dsack {*}$args] }
    proc tcp_earlyrxmit_command {args} { return [tcp_optional_toggle_command earlyrxmit {*}$args] }
    proc tcp_ecn_command {args} { return [tcp_toggle_command ecn {*}$args] }
    proc tcp_enhanced_loss_recovery_command {args} {
        return [tcp_toggle_command enhanced_loss_recovery {*}$args]
    }
    proc tcp_limxmit_command {args} { return [tcp_toggle_command limxmit {*}$args] }

    proc tcp_analytics_command {args} {
        if {[llength $args] < 1 || [llength $args] > 2} {
            error "TCP::analytics accepts enable, disable, or key with an optional value"
        }
        set operation [string tolower [lindex $args 0]]
        if {$operation in {enable disable}} {
            if {[llength $args] != 1} {
                error "TCP::analytics $operation takes no additional arguments"
            }
            set ::state::tcp::analytics $operation
            ::itest::log_decision tcp analytics $operation
            return ""
        }
        if {$operation eq "key"} {
            set key ""
            if {[llength $args] == 2} {
                set key [lindex $args 1]
            }
            set ::state::tcp::analytics enable
            set ::state::tcp::analytics_key $key
            ::itest::log_decision tcp analytics_key $key
            return ""
        }
        error "TCP::analytics requires enable, disable, or key"
    }

    proc tcp_lossfilter_command {args} {
        if {[llength $args] != 2} {
            error "TCP::lossfilter requires rate and burst"
        }
        set rate [lindex $args 0]
        set burst [lindex $args 1]
        if {![string is integer -strict $rate] || $rate < 0 || $rate > 1000000} {
            error "TCP::lossfilter rate must be an integer from 0 to 1000000"
        }
        if {![string is integer -strict $burst] || $burst < 0 || $burst > 32} {
            error "TCP::lossfilter burst must be an integer from 0 to 32"
        }
        set ::state::tcp::lossfilter_rate $rate
        set ::state::tcp::lossfilter_burst $burst
        ::itest::log_decision tcp lossfilter [list $rate $burst]
        return ""
    }

    proc tcp_lossfilter_value {name args} {
        if {[llength $args] != 0} { error "TCP::$name takes no arguments" }
        return [set ::state::tcp::$name]
    }

    proc tcp_lossfilter_burst_command {args} {
        return [tcp_lossfilter_value lossfilter_burst {*}$args]
    }

    proc tcp_lossfilter_rate_command {args} {
        return [tcp_lossfilter_value lossfilter_rate {*}$args]
    }

    proc tcp_rexmt_thresh_command {args} {
        if {[llength $args] > 1} {
            error "TCP::rexmt_thresh accepts an optional integer"
        }
        if {[llength $args] == 1} {
            set value [lindex $args 0]
            if {![string is integer -strict $value] || $value < 3 || $value > 255} {
                error "TCP::rexmt_thresh requires an integer from 3 to 255"
            }
            set ::state::tcp::rexmt_thresh $value
            ::itest::log_decision tcp rexmt_thresh $value
        }
        return $::state::tcp::rexmt_thresh
    }

    proc tcp_rt_metrics_timeout_command {args} {
        if {[llength $args] != 1} {
            error "TCP::rt_metrics_timeout requires a non-negative integer"
        }
        set value [lindex $args 0]
        if {![string is integer -strict $value] || $value < 0} {
            error "TCP::rt_metrics_timeout requires a non-negative integer"
        }
        set ::state::tcp::rt_metrics_timeout $value
        ::itest::log_decision tcp rt_metrics_timeout $value
        return ""
    }

    proc tcp_rcv_scale_command {args} { return [tcp_readonly_numeric rcv_scale {*}$args] }
    proc tcp_snd_scale_command {args} { return [tcp_readonly_numeric snd_scale {*}$args] }
    proc tcp_snd_ssthresh_command {args} { return [tcp_readonly_numeric snd_ssthresh {*}$args] }

    proc tcp_unused_port_command {args} {
        variable tcp_unused_port_next
        variable tcp_unused_ports
        if {[llength $args] ni {3 4}} {
            error "TCP::unused_port requires remote address, remote port, local address, and optional hint port"
        }
        set remote_port [lindex $args 1]
        if {![string is integer -strict $remote_port] || $remote_port < 0 || $remote_port > 65535} {
            error "TCP::unused_port remote port must be an integer from 0 to 65535"
        }
        foreach address [list [lindex $args 0] [lindex $args 2]] {
            if {$address eq ""} { error "TCP::unused_port addresses must not be empty" }
        }
        set result $tcp_unused_port_next
        set has_hint 0
        if {[llength $args] == 4} {
            set hint [lindex $args 3]
            if {![string is integer -strict $hint] || $hint < 0 || $hint > 65535} {
                error "TCP::unused_port hint port must be an integer from 0 to 65535"
            }
            if {$hint > 0} {
                set result $hint
                set has_hint 1
            }
        }
        set selected 0
        for {set attempt 0} {$attempt < 16384} {incr attempt} {
            if {![dict exists $tcp_unused_ports $result]} {
                set selected 1
                break
            }
            incr result
            if {$result > 65535} { set result 49152 }
        }
        if {!$selected} { return 0 }
        dict set tcp_unused_ports $result 1
        if {!$has_hint} {
            set tcp_unused_port_next [expr {$result + 1}]
            if {$tcp_unused_port_next > 65535} { set tcp_unused_port_next 49152 }
        }
        ::itest::log_decision tcp unused_port [list [lindex $args 0] $remote_port [lindex $args 2] $result]
        return $result
    }

    proc tcp_nagle_command {args} {
        if {[llength $args] > 1 ||
            ([llength $args] == 1 && [lindex $args 0] ni {enable disable auto})} {
            error "TCP::nagle accepts enable, disable, or auto"
        }
        if {[llength $args] == 1} {
            set mode [lindex $args 0]
            set ::state::tcp::nagle $mode
            set ::state::tcp::naglemode $mode
            set ::state::tcp::naglestate [expr {$mode eq "disable" ? "disabled" : "enabled"}]
            ::itest::log_decision tcp nagle $mode
        }
        return $::state::tcp::nagle
    }

    proc tcp_naglemode_command {args} {
        if {[llength $args] != 0} { error "TCP::naglemode takes no arguments" }
        return $::state::tcp::naglemode
    }

    proc tcp_naglestate_command {args} {
        if {[llength $args] != 0} { error "TCP::naglestate takes no arguments" }
        return $::state::tcp::naglestate
    }

    proc tcp_numeric_setting {name args} {
        if {[llength $args] > 1} { error "TCP::$name accepts an optional non-negative integer" }
        if {[llength $args] == 1} {
            set value [lindex $args 0]
            if {![string is integer -strict $value] || $value < 0} {
                error "TCP::$name requires a non-negative integer"
            }
            set ::state::tcp::$name $value
            ::itest::log_decision tcp $name $value
        }
        return [set ::state::tcp::$name]
    }

    proc tcp_keepalive_command {args} { return [tcp_numeric_setting keepalive {*}$args] }
    proc tcp_sendbuf_command {args} { return [tcp_numeric_setting sendbuf {*}$args] }
    proc tcp_recvwnd_command {args} { return [tcp_numeric_setting recvwnd {*}$args] }

    proc tcp_idletime_command {args} {
        if {[llength $args] != 1} { error "TCP::idletime requires a non-negative integer" }
        tcp_numeric_setting idletime {*}$args
        return ""
    }

    proc tcp_readonly_numeric {name args} {
        if {[llength $args] != 0} { error "TCP::$name takes no arguments" }
        return [set ::state::tcp::$name]
    }

    proc tcp_rcv_size_command {args} { return [tcp_readonly_numeric rcv_size {*}$args] }
    proc tcp_snd_wnd_command {args} { return [tcp_readonly_numeric snd_wnd {*}$args] }
    proc tcp_snd_cwnd_command {args} { return [tcp_readonly_numeric snd_cwnd {*}$args] }
    proc tcp_rto_command {args} { return [tcp_readonly_numeric rto {*}$args] }
    proc tcp_rttvar_command {args} { return [tcp_readonly_numeric rttvar {*}$args] }

    proc tcp_setmss_command {args} {
        if {[llength $args] != 1 ||
            ![string is integer -strict [lindex $args 0]] ||
            [lindex $args 0] < 1 || [lindex $args 0] > 65535} {
            error "TCP::setmss requires an integer from 1 to 65535"
        }
        set ::state::connection::mss [lindex $args 0]
        ::itest::log_decision tcp setmss $::state::connection::mss
        return ""
    }

    proc tcp_pacing_command {args} {
        if {[llength $args] > 1} { error "TCP::pacing accepts an optional boolean" }
        if {[llength $args] == 1} {
            set value [string tolower [lindex $args 0]]
            if {$value ni {enable disable 1 0 true false}} {
                error "TCP::pacing requires enable or disable"
            }
            set ::state::tcp::pacing [expr {$value in {enable 1 true}}]
            ::itest::log_decision tcp pacing $::state::tcp::pacing
        }
        return $::state::tcp::pacing
    }

    proc tcp_push_flag_command {args} {
        if {[llength $args] > 1 ||
            ([llength $args] == 1 && [lindex $args 0] ni {default none one auto})} {
            error "TCP::push_flag accepts default, none, one, or auto"
        }
        if {[llength $args] == 1} {
            set ::state::tcp::push_flag [lindex $args 0]
            ::itest::log_decision tcp push_flag $::state::tcp::push_flag
        }
        return $::state::tcp::push_flag
    }

    proc tcp_proxybuffer_command {args} {
        if {[llength $args] != 2} { error "TCP::proxybuffer requires high and low thresholds" }
        foreach value $args {
            if {![string is integer -strict $value] || $value < 0} {
                error "TCP::proxybuffer thresholds must be non-negative integers"
            }
        }
        set ::state::tcp::proxybuffer_high [lindex $args 0]
        set ::state::tcp::proxybuffer_low [lindex $args 1]
        ::itest::log_decision tcp proxybuffer $args
        return ""
    }

    proc tcp_proxybuffer_threshold_command {name args} {
        if {[llength $args] != 0} { error "TCP::$name takes no arguments" }
        return [set ::state::tcp::$name]
    }

    proc tcp_proxybufferhigh_command {args} {
        return [tcp_proxybuffer_threshold_command proxybuffer_high {*}$args]
    }

    proc tcp_proxybufferlow_command {args} {
        return [tcp_proxybuffer_threshold_command proxybuffer_low {*}$args]
    }

    proc tcp_congestion_command {args} {
        if {[llength $args] > 1} { error "TCP::congestion accepts an optional algorithm" }
        if {[llength $args] == 1} {
            set value [lindex $args 0]
            if {$value eq ""} { error "TCP::congestion algorithm must not be empty" }
            set ::state::tcp::congestion $value
            ::itest::log_decision tcp congestion $value
        }
        return $::state::tcp::congestion
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

    proc http2_reset_pushes {} {
        set ::state::http2::push_count 0
        set ::state::http2::pushes {}
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

    proc http2_push_command {args} {
        if {![http2_active_command]} {
            error "HTTP2::push requires an active HTTP/2 transaction"
        }
        if {[llength $args] < 1} {
            error "HTTP2::push requires a URI"
        }
        set uri [lindex $args 0]
        if {$uri eq "" || [string first "\x00" $uri] >= 0} {
            error "HTTP2::push URI must be non-empty and contain no NUL bytes"
        }
        set priority 0
        set content ""
        set content_set 0
        set ifile ""
        set noserver 0
        set nohost 0
        set request_headers {}
        set response_headers {}
        set response_mode 0
        set index 1
        while {$index < [llength $args]} {
            set arg [lindex $args $index]
            if {$arg eq "--"} {
                set response_mode 1
                incr index
                break
            }
            if {$arg eq "-priority"} {
                incr index
                if {$index >= [llength $args]} { error "HTTP2::push -priority requires a value" }
                set priority [lindex $args $index]
                if {![string is integer -strict $priority] || $priority < 0 || $priority > 255} {
                    error "HTTP2::push priority must be between 0 and 255"
                }
            } elseif {$arg eq "-content"} {
                incr index
                if {$index >= [llength $args]} { error "HTTP2::push -content requires data" }
                if {$content_set || $ifile ne ""} { error "HTTP2::push accepts only one content source" }
                set content [lindex $args $index]
                if {[string first "\x00" $content] >= 0} { error "HTTP2::push content cannot contain NUL bytes" }
                set content_set 1
            } elseif {$arg eq "-ifile"} {
                incr index
                if {$index >= [llength $args]} { error "HTTP2::push -ifile requires an object" }
                if {$content_set || $ifile ne ""} { error "HTTP2::push accepts only one content source" }
                set ifile [lindex $args $index]
                if {$ifile eq "" || [string first "\x00" $ifile] >= 0} { error "HTTP2::push iFile must be non-empty and contain no NUL bytes" }
            } elseif {$arg eq "-noserver"} {
                set noserver 1
            } elseif {$arg eq "-nohost"} {
                set nohost 1
            } elseif {[string match -* $arg]} {
                error "HTTP2::push received unsupported option $arg"
            } else {
                lappend request_headers $arg
            }
            incr index
        }
        while {$index < [llength $args]} {
            set arg [lindex $args $index]
            if {[string match -* $arg]} { error "HTTP2::push response headers cannot contain options" }
            lappend response_headers $arg
            incr index
        }
        if {[llength $request_headers] % 2 != 0} {
            error "HTTP2::push request headers require name/value pairs"
        }
        if {[llength $response_headers] % 2 != 0} {
            error "HTTP2::push response headers require name/value pairs"
        }
        foreach header_value [concat $request_headers $response_headers] {
            if {[string first "\x00" $header_value] >= 0} {
                error "HTTP2::push headers cannot contain NUL bytes"
            }
        }
        if {[string bytelength $content] > 2097152} {
            error "HTTP2::push content exceeds 2 MiB"
        }
        if {!$nohost} {
            set has_host 0
            foreach {header_name header_value} $request_headers {
                if {[string tolower $header_name] in {host :authority}} {
                    set has_host 1
                    break
                }
            }
            if {!$has_host} {
                error "HTTP2::push requires a Host or :authority request header unless -nohost is used"
            }
        }
        incr ::itest::semantic::http2_push_counter
        set record [dict create \
            id $::itest::semantic::http2_push_counter uri $uri priority $priority \
            content $content ifile $ifile noserver $noserver nohost $nohost \
            request_headers $request_headers response_headers $response_headers]
        lappend ::state::http2::pushes $record
        set ::state::http2::push_count [llength $::state::http2::pushes]
        ::itest::log_decision http2 push $record
        return ""
    }

    proc stream_prepare_event {} {
        set ::state::stream::match ""
        set ::state::stream::replacement ""
        set ::state::stream::replacement_requested 0
        set ::state::stream::replaced 0
    }

    proc stream_reset_connection {} {
        set ::state::stream::match ""
        set ::state::stream::encoding ascii
        set ::state::stream::expression ""
        set ::state::stream::max_matchsize 4096
        set ::state::stream::enabled 1
        set ::state::stream::disabled 0
        stream_prepare_event
    }

    proc stream_disable_command {args} {
        if {[llength $args] != 0} { error "STREAM::disable takes no arguments" }
        set ::state::stream::enabled 0
        set ::state::stream::disabled 1
        ::itest::log_decision stream disable
        return ""
    }

    proc stream_enable_command {args} {
        if {[llength $args] != 0} { error "STREAM::enable takes no arguments" }
        set ::state::stream::enabled 1
        set ::state::stream::disabled 0
        ::itest::log_decision stream enable
        return ""
    }

    proc stream_encoding_command {args} {
        if {[llength $args] != 1 || [lindex $args 0] ni {ascii utf-8 unicode}} {
            error "STREAM::encoding requires ascii, utf-8, or unicode"
        }
        set ::state::stream::encoding [lindex $args 0]
        ::itest::log_decision stream encoding $::state::stream::encoding
        return ""
    }

    proc stream_expression_command {args} {
        if {[llength $args] != 1 || [string first "\x00" [lindex $args 0]] >= 0} {
            error "STREAM::expression requires one expression without NUL bytes"
        }
        set ::state::stream::expression [lindex $args 0]
        ::itest::log_decision stream expression $::state::stream::expression
        return ""
    }

    proc stream_match_command {args} {
        if {[llength $args] != 0} { error "STREAM::match takes no arguments" }
        return $::state::stream::match
    }

    proc stream_max_matchsize_command {args} {
        if {[llength $args] != 1 || ![string is integer -strict [lindex $args 0]]} {
            error "STREAM::max_matchsize requires a positive integer"
        }
        set value [lindex $args 0]
        if {$value < 1} {
            error "STREAM::max_matchsize must be a positive integer"
        }
        set ::state::stream::max_matchsize $value
        ::itest::log_decision stream max_matchsize $value
        return ""
    }

    proc stream_replace_command {args} {
        if {[llength $args] > 1} { error "STREAM::replace accepts an optional target string" }
        if {[llength $args] == 0} {
            set ::state::stream::replacement ""
            set ::state::stream::replacement_requested 0
            return ""
        }
        set value [lindex $args 0]
        if {[string first "\x00" $value] >= 0} {
            error "STREAM::replace target cannot contain NUL bytes"
        }
        set ::state::stream::replacement $value
        set ::state::stream::replacement_requested 1
        set ::state::stream::replaced 1
        ::itest::log_decision stream replace $value
        return ""
    }

    proc _route_zero_metrics {} {
        foreach field {age expiration mtu rtt rttvar cwnd bandwidth} {
            set ::state::route::$field 0
        }
    }

    proc _route_prepare_lookup {} {
        set ::state::route::destination ""
        set ::state::route::gateway ""
        _route_zero_metrics
    }

    proc route_reset_connection {} {
        _route_prepare_lookup
        set ::state::route::cleared 0
    }

    proc route_configure {args} {
        variable route_metrics
        if {[llength $args] != 2} {
            error "route configuration requires a domain and metric list"
        }
        set domain [lindex $args 0]
        set flattened [lindex $args 1]
        if {[llength $flattened] % 9 != 0} {
            error "route metric list must contain groups of nine values"
        }
        set route_metrics [dict create]
        foreach {destination gateway age expiration mtu rtt rttvar cwnd bandwidth} $flattened {
            dict set route_metrics $destination $gateway [dict create \
                age $age expiration $expiration mtu $mtu rtt $rtt \
                rttvar $rttvar cwnd $cwnd bandwidth $bandwidth]
        }
        set ::state::route::domain $domain
        route_reset_connection
    }

    proc _route_lookup {args} {
        variable route_metrics
        if {[llength $args] < 1 || [llength $args] > 2} {
            error "ROUTE command requires a destination and optional gateway"
        }
        set destination [lindex $args 0]
        set gateway [expr {[llength $args] == 2 ? [lindex $args 1] : ""}]
        if {$destination eq ""} {
            error "ROUTE destination must not be empty"
        }
        _route_prepare_lookup
        set ::state::route::destination $destination
        set ::state::route::gateway $gateway
        if {![dict exists $route_metrics $destination $gateway]} {
            return {}
        }
        set record [dict get $route_metrics $destination $gateway]
        foreach field {age expiration mtu rtt rttvar cwnd bandwidth} {
            set ::state::route::$field [dict get $record $field]
        }
        return $record
    }

    proc _route_metric_command {field args} {
        set record [_route_lookup {*}$args]
        if {[dict size $record] == 0} {
            return 0
        }
        return [dict get $record $field]
    }

    proc route_age_command {args} { return [_route_metric_command age {*}$args] }
    proc route_bandwidth_command {args} { return [_route_metric_command bandwidth {*}$args] }
    proc route_cwnd_command {args} { return [_route_metric_command cwnd {*}$args] }
    proc route_expiration_command {args} { return [_route_metric_command expiration {*}$args] }
    proc route_mtu_command {args} { return [_route_metric_command mtu {*}$args] }
    proc route_rtt_command {args} { return [_route_metric_command rtt {*}$args] }
    proc route_rttvar_command {args} { return [_route_metric_command rttvar {*}$args] }

    proc route_domain_command {args} {
        if {[llength $args] != 0} {
            error "ROUTE::domain takes no arguments"
        }
        return $::state::route::domain
    }

    proc route_clear_command {args} {
        variable route_metrics
        _route_lookup {*}$args
        set destination $::state::route::destination
        set gateway $::state::route::gateway
        if {[dict exists $route_metrics $destination $gateway]} {
            dict unset route_metrics $destination $gateway
        }
        _route_zero_metrics
        set ::state::route::cleared 1
        ::itest::log_decision route clear [list destination $destination gateway $gateway]
        return ""
    }

    # ── TLS/SSL inspection and control semantics ─────────────────────
    proc _ssl_namespace {{side ""}} {
        if {$side eq "serverside" || [string match "SERVERSSL_*" $::itest::current_event] ||
            [lsearch -exact {SERVER_CONNECTED SERVER_DATA SERVER_CLOSED SERVER_INIT} $::itest::current_event] >= 0} {
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

    proc ssl_alpn_command {args} {
        set ns [_ssl_namespace]
        if {[llength $args] == 0} {
            return [_ssl_value alpn]
        }
        if {[lindex $args 0] ne "set" || [llength $args] < 2} {
            error "SSL::alpn accepts no arguments or set followed by one or more protocols"
        }
        foreach protocol [lrange $args 1 end] {
            if {$protocol eq "" || [string first "\x00" $protocol] >= 0} {
                error "SSL::alpn protocol names cannot be empty or contain NUL"
            }
        }
        set ${ns}::alpn [join [lrange $args 1 end] " "]
        ::itest::log_decision ssl alpn_set [set ${ns}::alpn]
        return ""
    }

    proc ssl_mode_command {args} {
        if {[llength $args] != 0} { error "SSL::mode takes no arguments" }
        return [expr {![_ssl_value disabled 0]}]
    }

    proc ssl_is_renegotiation_secure_command {args} {
        if {[llength $args] != 0} { error "SSL::is_renegotiation_secure takes no arguments" }
        return [_ssl_value renegotiation_secure 0]
    }

    proc ssl_clientrandom_command {args} {
        if {[llength $args] != 0} { error "SSL::clientrandom takes no arguments" }
        return [_ssl_value clientrandom]
    }

    proc ssl_sessionticket_command {args} {
        if {[llength $args] != 0} { error "SSL::sessionticket takes no arguments" }
        return [_ssl_value sessionticket]
    }

    proc ssl_authenticate_command {args} {
        if {[llength $args] == 1 && [lindex $args 0] in {once always}} {
            set ns [_ssl_namespace]
            set ${ns}::authenticate_frequency [lindex $args 0]
            ::itest::log_decision ssl authenticate_[lindex $args 0] $ns
            return ""
        }
        if {[llength $args] == 2 && [lindex $args 0] eq "depth"} {
            set depth [lindex $args 1]
            if {![string is integer -strict $depth] || $depth < 0} {
                error "SSL::authenticate depth requires a non-negative integer"
            }
            set ns [_ssl_namespace]
            set ${ns}::authenticate_depth $depth
            ::itest::log_decision ssl authenticate_depth [list $depth $ns]
            return ""
        }
        error "SSL::authenticate requires once, always, or depth followed by a non-negative integer"
    }

    proc ssl_handshake_command {args} {
        if {[llength $args] != 1 || [lindex $args 0] ni {hold resume}} {
            error "SSL::handshake requires hold or resume"
        }
        set held [expr {[lindex $args 0] eq "hold"}]
        set ns [_ssl_namespace]
        set ${ns}::handshake_held $held
        ::itest::log_decision ssl handshake_[lindex $args 0] [_ssl_namespace]
        return ""
    }

    proc ssl_renegotiate_command {args} {
        if {[llength $args] > 1 || ([llength $args] == 1 && [lindex $args 0] ni {enable disable})} {
            error "SSL::renegotiate accepts optional enable or disable"
        }
        if {[_ssl_value disabled 0]} {
            error "SSL::renegotiate requires SSL to be enabled"
        }
        set ns [_ssl_namespace]
        if {[llength $args] == 0} {
            set ${ns}::renegotiation_requested 1
            ::itest::log_decision ssl renegotiate $ns
            return ""
        }
        set enabled [expr {[lindex $args 0] eq "enable"}]
        set ${ns}::renegotiation_enabled $enabled
        ::itest::log_decision ssl renegotiation_[lindex $args 0] $ns
        return ""
    }

    proc ssl_secure_renegotiation_command {args} {
        if {[llength $args] > 1 || ([llength $args] == 1 && [lindex $args 0] ni {request require require-strict})} {
            error "SSL::secure_renegotiation accepts request, require, or require-strict"
        }
        set ns [_ssl_namespace]
        if {[llength $args] == 1} {
            set mode [dict get [dict create request 0 require 1 require-strict 2] [lindex $args 0]]
            set ${ns}::secure_renegotiation $mode
            ::itest::log_decision ssl secure_renegotiation_set $mode
        }
        return [_ssl_value secure_renegotiation 0]
    }

    proc ssl_allow_nonssl_command {args} {
        if {[llength $args] > 1} { error "SSL::allow_nonssl accepts an optional 0 or 1" }
        set ns [_ssl_namespace]
        if {[llength $args] == 1} {
            set value [lindex $args 0]
            if {![string is integer -strict $value] || $value ni {0 1}} {
                error "SSL::allow_nonssl requires 0 or 1"
            }
            set ${ns}::allow_nonssl $value
            ::itest::log_decision ssl allow_nonssl_set $value
            return ""
        }
        return [_ssl_value allow_nonssl 0]
    }

    proc ssl_allow_dynamic_record_sizing_command {args} {
        if {[llength $args] > 1} {
            error "SSL::allow_dynamic_record_sizing accepts an optional 0 or 1"
        }
        set ns [_ssl_namespace]
        if {[llength $args] == 1} {
            set value [lindex $args 0]
            if {![string is integer -strict $value] || $value ni {0 1}} {
                error "SSL::allow_dynamic_record_sizing requires 0 or 1"
            }
            set ${ns}::dynamic_record_sizing $value
            ::itest::log_decision ssl dynamic_record_sizing_set $value
            return ""
        }
        return [_ssl_value dynamic_record_sizing 0]
    }

    proc ssl_maximum_record_size_command {args} {
        if {[llength $args] > 1} { error "SSL::maximum_record_size accepts an optional size" }
        set ns [_ssl_namespace]
        if {[llength $args] == 1} {
            set value [lindex $args 0]
            if {![string is integer -strict $value] || $value < 1 || $value > 16384} {
                error "SSL::maximum_record_size must be between 1 and 16384"
            }
            set ${ns}::maximum_record_size $value
            ::itest::log_decision ssl maximum_record_size_set $value
            return ""
        }
        return [_ssl_value maximum_record_size 16384]
    }

    proc ssl_profile_command {args} {
        if {[llength $args] != 1 || [lindex $args 0] eq "" || [string first "\x00" [lindex $args 0]] >= 0} {
            error "SSL::profile requires a non-empty profile name"
        }
        set ns [_ssl_namespace]
        set ${ns}::profile [lindex $args 0]
        ::itest::log_decision ssl profile_set [list [lindex $args 0] $ns]
        return ""
    }

    proc ssl_session_command {args} {
        if {[llength $args] < 1 || [llength $args] > 2 || [lindex $args 0] ne "invalidate" ||
            ([llength $args] == 2 && [lindex $args 1] ni {drop nodrop})} {
            error "SSL::session requires invalidate with optional drop or nodrop"
        }
        set ns [_ssl_namespace]
        set drop [expr {[llength $args] < 2 || [lindex $args 1] eq "drop"}]
        set ${ns}::session_invalidated 1
        set ${ns}::session_drop $drop
        ::itest::log_decision ssl session_invalidate $drop
        return ""
    }

    proc ssl_unclean_shutdown_command {args} {
        if {[llength $args] != 1 || [lindex $args 0] ni {enable disable}} {
            error "SSL::unclean_shutdown requires enable or disable"
        }
        set ns [_ssl_namespace]
        set enabled [expr {[lindex $args 0] eq "enable"}]
        set ${ns}::unclean_shutdown $enabled
        ::itest::log_decision ssl unclean_shutdown_[lindex $args 0] $ns
        return ""
    }

    proc ssl_reset_connection {} {
        foreach side {client server} {
            set ns ::state::tls::$side
            set ${ns}::handshake_held 0
            set ${ns}::renegotiation_enabled 1
            set ${ns}::renegotiation_requested 0
            set ${ns}::renegotiation_secure 0
            set ${ns}::secure_renegotiation 0
            set ${ns}::allow_nonssl 0
            set ${ns}::dynamic_record_sizing 0
            set ${ns}::maximum_record_size 16384
            set ${ns}::profile ""
            set ${ns}::session_invalidated 0
            set ${ns}::session_drop 1
            set ${ns}::unclean_shutdown 0
            set ${ns}::authenticate_frequency ""
            set ${ns}::authenticate_depth 0
            set ${ns}::cert_subject ""
            set ${ns}::cert_issuer ""
            set ${ns}::cert_serial ""
            set ${ns}::cert_hash ""
            set ${ns}::cert_extensions ""
            set ${ns}::cert_not_valid_after ""
            set ${ns}::cert_not_valid_before ""
            set ${ns}::cert_signature_algorithm ""
            set ${ns}::cert_public_key ""
            set ${ns}::cert_public_key_type "unknown"
            set ${ns}::cert_public_key_bits 0
            set ${ns}::cert_public_key_curve ""
            set ${ns}::cert_version 3
            set ${ns}::cert_pem ""
            set ${ns}::cert_der ""
            set ${ns}::initial_session_id ""
            set ${ns}::nextproto ""
            set ${ns}::session_secret ""
            set ${ns}::tls13_client_app_secret ""
            set ${ns}::tls13_client_hs_secret ""
            set ${ns}::tls13_client_early_secret ""
            set ${ns}::tls13_server_app_secret ""
            set ${ns}::tls13_server_hs_secret ""
            set ${ns}::c3d_cert ""
            set ${ns}::c3d_subject_cn ""
            set ${ns}::c3d_extensions [dict create]
            set ${ns}::cert_constraints [list]
            set ${ns}::collect_requested 0
            set ${ns}::collect_length 0
            set ${ns}::payload ""
            set ${ns}::payload_length 0
            set ${ns}::release_requested 0
            set ${ns}::released_length 0
            set ${ns}::forward_proxy_policy bypass
            set ${ns}::forward_proxy_cert ""
            set ${ns}::forward_proxy_extensions [dict create]
            set ${ns}::forward_proxy_verified_handshake 0
            set ${ns}::forward_proxy_response_control ignore
            set ${ns}::forward_proxy_cert_status ""
        }
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
        if {[dict exists $ssl_cert_objects $ns $index]} {
            set handle [dict get $ssl_cert_objects $ns $index]
        } else {
            incr ssl_cert_counter
            set handle "cert$ssl_cert_counter"
            dict set ssl_cert_objects $ns $index $handle
        }
        set subject [_ssl_value cert_subject]
        set issuer [_ssl_value cert_issuer]
        set serial [_ssl_value cert_serial]
        set hash [_ssl_value cert_hash]
        set extensions [_ssl_value cert_extensions]
        set not_valid_after [_ssl_value cert_not_valid_after]
        set not_valid_before [_ssl_value cert_not_valid_before]
        set signature_algorithm [_ssl_value cert_signature_algorithm]
        set public_key [_ssl_value cert_public_key]
        set public_key_type [_ssl_value cert_public_key_type unknown]
        set public_key_bits [_ssl_value cert_public_key_bits 0]
        set public_key_curve [_ssl_value cert_public_key_curve]
        set version [_ssl_value cert_version 3]
        set pem [_ssl_value cert_pem]
        set der [_ssl_value cert_der]
        if {$pem eq ""} {
            set pem "-----BEGIN CERTIFICATE-----\n$handle\n-----END CERTIFICATE-----"
        }
        dict set ssl_cert_objects objects $handle [dict create \
            subject $subject issuer $issuer serial $serial hash $hash \
            extensions $extensions not_valid_after $not_valid_after \
            not_valid_before $not_valid_before signature_algorithm $signature_algorithm \
            public_key $public_key public_key_type $public_key_type \
            public_key_bits $public_key_bits public_key_curve $public_key_curve \
            version $version pem $pem der $der]
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

    proc _ssl_require_text {value field} {
        if {$value eq "" || [string first "\x00" $value] >= 0} {
            error "$field requires a non-empty value without NUL bytes"
        }
        return $value
    }

    proc _ssl_set_payload {ns value} {
        set ${ns}::payload $value
        set ${ns}::payload_length [string bytelength $value]
        return $value
    }

    proc ssl_c3d_command {args} {
        set ns [_ssl_namespace]
        if {[llength $args] < 1 || [llength $args] > 3} {
            error "SSL::c3d requires extension, cert, or subject"
        }
        set operation [lindex $args 0]
        switch -exact -- $operation {
            extension {
                if {[llength $args] != 3} {
                    error "SSL::c3d extension requires an OID and value"
                }
                set oid [_ssl_require_text [lindex $args 1] "SSL::c3d extension OID"]
                set value [lindex $args 2]
                if {[string first "\x00" $value] >= 0} {
                    error "SSL::c3d extension value cannot contain NUL bytes"
                }
                dict set ${ns}::c3d_extensions $oid $value
                ::itest::log_decision ssl c3d_extension [list $oid $value]
            }
            cert {
                if {[llength $args] != 2} {
                    error "SSL::c3d cert requires a certificate"
                }
                set ${ns}::c3d_cert [_ssl_require_text [lindex $args 1] "SSL::c3d cert"]
                ::itest::log_decision ssl c3d_cert $ns
            }
            subject {
                if {[llength $args] != 3 || [lindex $args 1] ne "commonName"} {
                    error "SSL::c3d subject requires commonName and a value"
                }
                set value [_ssl_require_text [lindex $args 2] "SSL::c3d subject commonName"]
                set ${ns}::c3d_subject_cn $value
                ::itest::log_decision ssl c3d_subject [list commonName $value]
            }
            default {
                error "SSL::c3d requires extension, cert, or subject"
            }
        }
        return ""
    }

    proc ssl_cert_constraint_command {args} {
        if {[llength $args] != 2} {
            error "SSL::cert_constraint requires an OID and value"
        }
        set oid [_ssl_require_text [lindex $args 0] "SSL::cert_constraint OID"]
        set value [lindex $args 1]
        if {[string first "\x00" $value] >= 0} {
            error "SSL::cert_constraint value cannot contain NUL bytes"
        }
        set ns [_ssl_namespace]
        lappend ${ns}::cert_constraints [list $oid $value]
        ::itest::log_decision ssl cert_constraint [list $oid $value]
        return ""
    }

    proc ssl_collect_command {args} {
        if {[llength $args] > 1} {
            error "SSL::collect accepts an optional positive length"
        }
        set length 0
        if {[llength $args] == 1} {
            set length [lindex $args 0]
            if {![string is integer -strict $length] || $length <= 0} {
                error "SSL::collect length must be a positive integer"
            }
        }
        set ns [_ssl_namespace]
        set ${ns}::collect_requested 1
        set ${ns}::collect_length $length
        _ssl_set_payload $ns ""
        set ${ns}::release_requested 0
        set ${ns}::released_length 0
        ::itest::log_decision ssl collect [list $ns $length]
        return ""
    }

    proc ssl_payload_command {args} {
        set ns [_ssl_namespace]
        set payload [set ${ns}::payload]
        if {[llength $args] == 0} { return $payload }
        set operation [lindex $args 0]
        if {$operation eq "length"} {
            if {[llength $args] != 1} { error "SSL::payload length takes no arguments" }
            return [string bytelength $payload]
        }
        if {$operation eq "replace"} {
            if {[llength $args] != 4} {
                error "SSL::payload replace requires offset, length, and data"
            }
            set offset [lindex $args 1]
            set length [lindex $args 2]
            if {![string is integer -strict $offset] || $offset < 0 ||
                ![string is integer -strict $length] || $length < 0} {
                error "SSL::payload replace offsets must be non-negative integers"
            }
            set value [lindex $args 3]
            if {[string first "\x00" $value] >= 0} {
                error "SSL::payload replacement cannot contain NUL bytes"
            }
            _ssl_set_payload $ns [::itest::cmd::_payload_splice $payload $offset $length $value]
            ::itest::log_decision ssl payload_replace [list $ns $offset $length $value]
            return ""
        }
        if {![string is integer -strict $operation] || $operation < 0 ||
            [llength $args] != 1} {
            error "SSL::payload accepts length, replace, or an optional size"
        }
        return [::itest::cmd::_payload_first $payload $operation]
    }

    proc ssl_release_command {args} {
        if {[llength $args] > 1} { error "SSL::release accepts an optional length" }
        set ns [_ssl_namespace]
        set payload [set ${ns}::payload]
        set available [string bytelength $payload]
        set length $available
        if {[llength $args] == 1} { set length [lindex $args 0] }
        if {![string is integer -strict $length] || $length < 0} {
            error "SSL::release length must be a non-negative integer"
        }
        if {$length > $available} { set length $available }
        _ssl_set_payload $ns [::itest::cmd::_payload_splice $payload 0 $length ""]
        set ${ns}::collect_requested 0
        set ${ns}::release_requested 1
        set ${ns}::released_length $length
        ::itest::log_decision ssl release [list $ns $length]
        return $length
    }

    proc ssl_forward_proxy_command {args} {
        set ns [_ssl_namespace]
        if {[llength $args] == 0} { return [set ${ns}::forward_proxy_policy] }
        set operation [lindex $args 0]
        switch -exact -- $operation {
            policy {
                if {[llength $args] > 2} { error "SSL::forward_proxy policy accepts an optional value" }
                if {[llength $args] == 2} {
                    set value [lindex $args 1]
                    if {$value ni {bypass intercept}} {
                        error "SSL::forward_proxy policy must be bypass or intercept"
                    }
                    set ${ns}::forward_proxy_policy $value
                    ::itest::log_decision ssl forward_proxy_policy $value
                    return ""
                }
                return [set ${ns}::forward_proxy_policy]
            }
            cert {
                if {[llength $args] == 1} { return [set ${ns}::forward_proxy_cert] }
                set selector [lindex $args 1]
                if {$selector eq "response_control"} {
                    if {[llength $args] > 3} { error "SSL::forward_proxy cert response_control accepts an optional value" }
                    if {[llength $args] == 3} {
                        set value [lindex $args 2]
                        if {$value ni {ignore mask}} { error "response_control must be ignore or mask" }
                        set ${ns}::forward_proxy_response_control $value
                        ::itest::log_decision ssl forward_proxy_response_control $value
                        return ""
                    }
                    return [set ${ns}::forward_proxy_response_control]
                }
                if {$selector eq "status"} {
                    if {[llength $args] > 3} { error "SSL::forward_proxy cert status accepts an optional value" }
                    if {[llength $args] == 3} {
                        set value [lindex $args 2]
                        if {[string first "\x00" $value] >= 0} { error "certificate status cannot contain NUL bytes" }
                        set ${ns}::forward_proxy_cert_status $value
                        ::itest::log_decision ssl forward_proxy_cert_status $value
                        return ""
                    }
                    return [set ${ns}::forward_proxy_cert_status]
                }
                error "SSL::forward_proxy cert supports response_control or status"
            }
            verified_handshake {
                if {[llength $args] > 2} { error "SSL::forward_proxy verified_handshake accepts an optional value" }
                if {[llength $args] == 2} {
                    set value [lindex $args 1]
                    if {$value ni {enable disable}} { error "verified_handshake must be enable or disable" }
                    set ${ns}::forward_proxy_verified_handshake [expr {$value eq "enable"}]
                    ::itest::log_decision ssl forward_proxy_verified_handshake $value
                    return ""
                }
                return [set ${ns}::forward_proxy_verified_handshake]
            }
            extension {
                if {[llength $args] != 3} { error "SSL::forward_proxy extension requires an OID and value" }
                set oid [_ssl_require_text [lindex $args 1] "SSL::forward_proxy extension OID"]
                set value [lindex $args 2]
                if {[string first "\x00" $value] >= 0} { error "certificate extension value cannot contain NUL bytes" }
                dict set ${ns}::forward_proxy_extensions $oid $value
                ::itest::log_decision ssl forward_proxy_extension [list $oid $value]
                return ""
            }
            default { error "SSL::forward_proxy requires policy, cert, verified_handshake, or extension" }
        }
    }

    proc ssl_modssl_sessionid_headers_command {args} {
        if {[llength $args] > 1 || ([llength $args] == 1 && [lindex $args 0] ni {initial current})} {
            error "SSL::modssl_sessionid_headers accepts initial or current"
        }
        set ns [_ssl_namespace]
        set selector [expr {[llength $args] == 1 ? [lindex $args 0] : "current"}]
        set field [expr {$selector eq "initial" ? "initial_session_id" : "session_id"}]
        return [list SSLClientSessionId [set ${ns}::$field]]
    }

    proc ssl_nextproto_command {args} {
        if {[llength $args] > 1} { error "SSL::nextproto accepts an optional protocol string" }
        set ns [_ssl_namespace]
        if {[llength $args] == 1} {
            set value [_ssl_require_text [lindex $args 0] "SSL::nextproto"]
            set ${ns}::nextproto $value
            ::itest::log_decision ssl nextproto_set $value
            return ""
        }
        return [set ${ns}::nextproto]
    }

    proc ssl_sessionsecret_command {args} {
        if {[llength $args] != 0} { error "SSL::sessionsecret takes no arguments" }
        return [_ssl_value session_secret]
    }

    proc ssl_tls13_secret_command {args} {
        if {[llength $args] != 2} { error "SSL::tls13_secret requires a side and secret type" }
        set side [lindex $args 0]
        set secret [lindex $args 1]
        if {$side ni {client server}} { error "SSL::tls13_secret side must be client or server" }
        if {$side eq "server" && $secret eq "early"} {
            error "SSL::tls13_secret server does not support early"
        }
        if {$secret ni {app hs early}} { error "unsupported TLS 1.3 secret type" }
        set field tls13_${side}_${secret}_secret
        set ns ::state::tls::$side
        return [set ${ns}::$field]
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

    proc _x509_certificate_arg {args command} {
        if {[llength $args] != 1} { error "$command requires a certificate" }
        return [lindex $args 0]
    }

    proc x509_extensions_command {args} {
        set certificate [_x509_certificate_arg $args X509::extensions]
        set value [_ssl_cert_get $certificate extensions]
        if {$value eq ""} { return "(no extensions)" }
        return $value
    }

    proc x509_hash_command {args} {
        return [_ssl_cert_get [_x509_certificate_arg $args X509::hash] hash]
    }

    proc x509_not_valid_after_command {args} {
        return [_ssl_cert_get [_x509_certificate_arg $args X509::not_valid_after] not_valid_after]
    }

    proc x509_not_valid_before_command {args} {
        return [_ssl_cert_get [_x509_certificate_arg $args X509::not_valid_before] not_valid_before]
    }

    proc x509_serial_number_command {args} {
        return [_ssl_cert_get [_x509_certificate_arg $args X509::serial_number] serial]
    }

    proc x509_signature_algorithm_command {args} {
        return [_ssl_cert_get [_x509_certificate_arg $args X509::signature_algorithm] signature_algorithm]
    }

    proc x509_subject_public_key_type_command {args} {
        return [_ssl_cert_get [_x509_certificate_arg $args X509::subject_public_key_type] public_key_type]
    }

    proc x509_subject_public_key_RSA_bits_command {args} {
        set certificate [_x509_certificate_arg $args X509::subject_public_key_RSA_bits]
        set key_type [_ssl_cert_get $certificate public_key_type]
        if {[string toupper $key_type] ne "RSA"} {
            error "X509::subject_public_key_RSA_bits requires an RSA certificate"
        }
        return [_ssl_cert_get $certificate public_key_bits]
    }

    proc x509_subject_public_key_command {args} {
        if {[llength $args] == 1} {
            return [_ssl_cert_get [lindex $args 0] public_key]
        }
        if {[llength $args] != 2 || [lindex $args 0] ni {type bits curve_name}} {
            error "X509::subject_public_key accepts an optional type, bits, or curve_name"
        }
        set selector [lindex $args 0]
        set certificate [lindex $args 1]
        switch -exact -- $selector {
            type { return [_ssl_cert_get $certificate public_key_type] }
            bits { return [_ssl_cert_get $certificate public_key_bits] }
            curve_name { return [_ssl_cert_get $certificate public_key_curve] }
        }
    }

    proc x509_version_command {args} {
        return [_ssl_cert_get [_x509_certificate_arg $args X509::version] version]
    }

    proc x509_whole_command {args} {
        return [_ssl_cert_get [_x509_certificate_arg $args X509::whole] pem]
    }

    proc _x509_known_certificate {value} {
        variable ssl_cert_objects
        if {[dict exists $ssl_cert_objects objects $value]} { return $value }
        if {![dict exists $ssl_cert_objects objects]} { return "" }
        dict for {handle fields} [dict get $ssl_cert_objects objects] {
            if {[dict get $fields pem] eq $value} { return $handle }
        }
        return ""
    }

    proc x509_pem2der_command {args} {
        if {[llength $args] != 1} { error "X509::pem2der requires a PEM certificate" }
        set value [lindex $args 0]
        set handle [_x509_known_certificate $value]
        if {$handle ne ""} {
            set der [_ssl_cert_get $handle der]
            if {$der ne ""} { return $der }
            set value [_ssl_cert_get $handle pem]
        }
        set value [string trim $value]
        if {![regexp -- {^-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\r\n\t ]+)-----END CERTIFICATE-----$} $value -> encoded]} {
            error "X509::pem2der requires a PEM certificate"
        }
        set encoded [string map {"\n" "" "\r" "" " " "" "\t" ""} $encoded]
        if {$encoded eq ""} { error "X509::pem2der received empty PEM data" }
        if {[catch {binary decode base64 $encoded} der]} {
            error "X509::pem2der received invalid PEM data"
        }
        return $der
    }

    proc x509_cert_fields_command {args} {
        if {[llength $args] < 3} {
            error "X509::cert_fields requires a certificate, error code, and options"
        }
        set certificate [lindex $args 0]
        set error_code [lindex $args 1]
        if {![string is integer -strict $error_code] || $error_code < 0} {
            error "X509::cert_fields error code must be a non-negative integer"
        }
        set options [lrange $args 2 end]
        if {[llength $options] == 1} {
            set candidate [lindex $options 0]
            if {![catch {llength $candidate} candidate_length] && $candidate_length > 1} {
                set options $candidate
            }
        }
        if {[llength $options] == 0} {
            error "X509::cert_fields requires at least one option"
        }
        set fields [dict create \
            hash [list SSL_CLIENT_CERT_HASH [_ssl_cert_get $certificate hash]] \
            issuer [list SSL_CLIENT_I_DN [_ssl_cert_get $certificate issuer]] \
            serial [list SSL_CLIENT_M_SERIAL [_ssl_cert_get $certificate serial]] \
            sigalg [list SSL_CLIENT_A_SIG [_ssl_cert_get $certificate signature_algorithm]] \
            subject [list SSL_CLIENT_S_DN [_ssl_cert_get $certificate subject]] \
            subpubkey [list SSL_CLIENT_A_KEY [_ssl_cert_get $certificate public_key]] \
            validity [list SSL_CLIENT_V_START [_ssl_cert_get $certificate not_valid_before] \
                           SSL_CLIENT_V_END [_ssl_cert_get $certificate not_valid_after]] \
            versionnum [list SSL_CLIENT_M_VERSION [_ssl_cert_get $certificate version]] \
            whole [list SSL_CLIENT_CERT [_ssl_cert_get $certificate pem]]]
        set result [list SSL_CLIENT_VERIFY $error_code]
        foreach option $options {
            if {![dict exists $fields $option]} {
                error "X509::cert_fields does not support option $option"
            }
            foreach {name value} [dict get $fields $option] {
                lappend result $name $value
            }
        }
        return $result
    }

    proc x509_verify_cert_error_string_command {args} {
        if {[llength $args] != 1 || ![string is integer -strict [lindex $args 0]] || [lindex $args 0] < 0} {
            error "X509::verify_cert_error_string requires a non-negative error code"
        }
        set code [lindex $args 0]
        set messages [dict create \
            0 "ok" \
            2 "unable to get issuer certificate" \
            10 "certificate has expired" \
            18 "self-signed certificate" \
            20 "unable to get local issuer certificate" \
            21 "unable to verify the first certificate" \
            23 "certificate revoked" \
            24 "invalid CA certificate" \
            26 "unsupported certificate purpose" \
            50 "application verification failure"]
        if {[dict exists $messages $code]} { return [dict get $messages $code] }
        return "unknown certificate verification error"
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
            rpz_policy "" wideips {} response_sent 0 tsig_present 0
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

    proc dns_tsig_command {args} {
        if {[llength $args] != 1 || [lindex $args 0] ni {exists remove}} {
            error "DNS::tsig requires exists or remove"
        }
        if {[lindex $args 0] eq "exists"} {
            if {![info exists ::state::dns::tsig_present]} { return 0 }
            return [expr {$::state::dns::tsig_present in {1 true TRUE}}]
        }
        set ::state::dns::tsig_present 0
        ::itest::log_decision dns tsig_remove
        return ""
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

    proc _crypto_parse {args command_name operation} {
        set parsed [dict create algorithm "" key "" signature "" data "" has_data 0 \
            key_set 0 signature_set 0 context "" context_set 0 final 0]
        set index 0
        set end_options 0
        while {$index < [llength $args]} {
            set token [lindex $args $index]
            if {!$end_options && $token eq "--"} {
                set end_options 1
                incr index
                continue
            }
            if {!$end_options && [string match -* $token]} {
                switch -exact -- $token {
                    -alg - -key - -keyhex - -signature - -ctx {
                        if {$index + 1 >= [llength $args]} {
                            error "$command_name option $token requires a value"
                        }
                        set value [lindex $args [incr index]]
                        if {$token eq "-ctx"} {
                            if {$value eq "" || [string first "\x00" $value] >= 0} {
                                error "$command_name -ctx requires a non-empty name without NUL bytes"
                            }
                            if {[dict get $parsed context_set]} {
                                error "$command_name accepts -ctx only once"
                            }
                            dict set parsed context $value
                            dict set parsed context_set 1
                        } elseif {$token eq "-alg"} {
                            if {[dict get $parsed algorithm] ne ""} {
                                error "$command_name accepts -alg only once"
                            }
                            dict set parsed algorithm $value
                        } elseif {$token eq "-signature"} {
                            if {[dict get $parsed signature_set]} {
                                error "$command_name accepts -signature only once"
                            }
                            dict set parsed signature $value
                            dict set parsed signature_set 1
                        } else {
                            if {[dict get $parsed key_set]} {
                                error "$command_name accepts only one key option"
                            }
                            if {$token eq "-keyhex"} {
                                if {[catch {binary decode hex $value} value]} {
                                    error "$command_name -keyhex requires an even hexadecimal value"
                                }
                            }
                            dict set parsed key $value
                            dict set parsed key_set 1
                        }
                    }
                    -final {
                        dict set parsed final 1
                    }
                    default {
                        error "$command_name does not support option $token"
                    }
                }
            } else {
                if {[dict get $parsed has_data]} {
                    error "$command_name accepts at most one data value"
                }
                dict set parsed data $token
                dict set parsed has_data 1
            }
            incr index
        }
        if {[dict get $parsed final] && ![dict get $parsed context_set]} {
            error "$command_name -final requires -ctx"
        }
        if {[dict get $parsed algorithm] eq "" && ![dict get $parsed context_set]} {
            error "$command_name requires -alg"
        }
        if {$operation eq "hash" && [dict get $parsed key_set]} {
            error "$command_name does not accept a key"
        }
        if {$operation in {sign verify} && ![dict get $parsed context_set] &&
            ![dict get $parsed key_set]} {
            error "$command_name requires -key or -keyhex"
        }
        if {$operation ne "verify" && [dict get $parsed signature_set]} {
            error "$command_name does not accept -signature"
        }
        if {$operation eq "verify" && ![dict get $parsed context_set] &&
            ![dict get $parsed signature_set]} {
            error "$command_name requires -signature"
        }
        return $parsed
    }

    proc _crypto_encoded {value} {
        return [binary encode base64 $value]
    }

    proc _crypto_execute {operation algorithm key data signature} {
        set encoded [::itest::semantic::py_crypto $operation $algorithm \
            [_crypto_encoded $key] [_crypto_encoded $data] [_crypto_encoded $signature]]
        if {$operation eq "verify"} {
            return $encoded
        }
        return [binary decode base64 $encoded]
    }

    proc _crypto_context_execute {parsed command_name operation} {
        variable crypto_contexts
        variable crypto_context_max_bytes
        set context [dict get $parsed context]
        if {[dict exists $crypto_contexts $context]} {
            set entry [dict get $crypto_contexts $context]
            if {[dict get $entry operation] ne $operation} {
                error "$command_name context is already used for another CRYPTO command"
            }
            if {[dict get $parsed algorithm] ne "" &&
                [dict get $parsed algorithm] ne [dict get $entry algorithm]} {
                error "$command_name cannot change the context algorithm"
            }
            if {[dict get $parsed key_set]} {
                if {[dict get $entry data_started] ||
                    [dict get $parsed key] ne [dict get $entry key]} {
                    error "$command_name cannot change the context key after it starts"
                }
                dict set entry key [dict get $parsed key]
            }
        } else {
            if {[dict get $parsed algorithm] eq ""} {
                error "$command_name requires -alg for a new context"
            }
            if {$operation in {sign verify} && ![dict get $parsed key_set]} {
                error "$command_name requires -key or -keyhex for a new context"
            }
            set entry [dict create \
                operation $operation \
                algorithm [dict get $parsed algorithm] \
                key [dict get $parsed key] \
                data "" \
                data_started 0]
        }
        if {[dict get $parsed has_data]} {
            set data [string cat [dict get $entry data] [dict get $parsed data]]
            if {[string bytelength $data] > $crypto_context_max_bytes} {
                error "$command_name context data exceeds the $crypto_context_max_bytes-byte limit"
            }
            dict set entry data $data
            dict set entry data_started 1
        }
        if {$operation eq "verify" && [dict get $parsed signature_set] &&
            ![dict get $parsed final]} {
            error "$command_name -signature requires -final in context mode"
        }
        if {![dict get $parsed final]} {
            dict set crypto_contexts $context $entry
            return ""
        }
        if {$operation eq "verify" && ![dict get $parsed signature_set]} {
            error "$command_name requires -signature when finalizing a context"
        }
        set result [_crypto_execute $operation \
            [dict get $entry algorithm] [dict get $entry key] \
            [dict get $entry data] [dict get $parsed signature]]
        dict unset crypto_contexts $context
        return $result
    }

    proc _crypto_command {args command_name operation} {
        set parsed [_crypto_parse $args $command_name $operation]
        if {[dict get $parsed context_set]} {
            return [_crypto_context_execute $parsed $command_name $operation]
        }
        return [_crypto_execute $operation \
            [dict get $parsed algorithm] [dict get $parsed key] \
            [dict get $parsed data] [dict get $parsed signature]]
    }

    proc crypto_hash_command {args} {
        return [_crypto_command $args CRYPTO::hash hash]
    }

    proc crypto_sign_command {args} {
        return [_crypto_command $args CRYPTO::sign sign]
    }

    proc crypto_verify_command {args} {
        return [_crypto_command $args CRYPTO::verify verify]
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
    lb_bias lb_bias_command
    lb_class lb_class_command
    lb_command lb_command_command
    lb_connect lb_connect_command
    lb_connlimit lb_connlimit_command
    lb_context_id lb_context_id_command
    lb_dst_tag lb_dst_tag_command
    lb_enable_decisionlog lb_enable_decisionlog_command
    lb_mode lb_mode_command
    lb_prime lb_prime_command
    lb_queue lb_queue_command
    lb_snat lb_snat_command
    lb_src_tag lb_src_tag_command
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
        if {$event_name eq "CLIENT_ACCEPTED"} {
            ::itest::semantic::lb_reset_connection
            ::itest::semantic::dosl7_reset_connection
            ::itest::semantic::asm_reset_connection
            ::itest::semantic::botdefense_reset_connection
            ::itest::semantic::antifraud_reset_connection
            ::itest::semantic::auth_reset_connection
            ::itest::semantic::rewrite_reset_connection
            ::itest::semantic::html_reset_connection
            ::itest::semantic::compression_reset_connection
            ::itest::semantic::httplog_reset_connection
        }
        set rewrite_auto [expr {$gated && !$::itest::semantic::rewrite_injecting &&
            [::itest::semantic::_profile_enabled REWRITE]}]
        if {$gated && $event_name eq "HTTP_REQUEST" && [::itest::semantic::_cache_profile_enabled]} {
            ::itest::semantic::cache_prepare_request
        }
        if {$gated && $event_name eq "HTTP_REQUEST"} {
            ::itest::semantic::compression_process_decompress request
        } elseif {$gated && $event_name eq "HTTP_RESPONSE"} {
            ::itest::semantic::compression_process_decompress response
        }
        set result [uplevel 1 [list ::itest::_testcl_fire_event_orig $event_name]]
        if {$gated && $event_name eq "HTTP_REQUEST"} {
            if {$rewrite_auto &&
                [lsearch -exact [::itest::registered_events] REWRITE_REQUEST_DONE] >= 0} {
                set ::itest::semantic::rewrite_injecting 1
                set rewrite_result [::itest::_testcl_fire_event_orig REWRITE_REQUEST_DONE]
                set ::itest::semantic::rewrite_injecting 0
                ::itest::semantic::event_errors_record REWRITE_REQUEST_DONE $rewrite_result
            }
            if {[::itest::semantic::_profile_enabled BOTDEFENSE]} {
                uplevel 1 [list ::itest::_testcl_fire_event_orig BOTDEFENSE_REQUEST]
                uplevel 1 [list ::itest::_testcl_fire_event_orig BOTDEFENSE_ACTION]
            }
            if {[::itest::semantic::_profile_enabled ANTIFRAUD] &&
                [::itest::semantic::antifraud_should_login]} {
                uplevel 1 [list ::itest::_testcl_fire_event_orig ANTIFRAUD_LOGIN]
            }
            if {[::itest::semantic::_profile_enabled ANTIFRAUD] &&
                [::itest::semantic::antifraud_should_alert]} {
                uplevel 1 [list ::itest::_testcl_fire_event_orig ANTIFRAUD_ALERT]
            }
            ::itest::semantic::_maybe_fire_lb_failed
            ::itest::semantic::cache_request_event
            ::itest::semantic::compression_process_request
            ::itest::semantic::httplog_record request
        } elseif {$gated && $event_name eq "HTTP_RESPONSE"} {
            if {[::itest::semantic::_profile_enabled HTML]} {
                ::itest::semantic::html_process_response
            }
            ::itest::semantic::cache_update_event
            if {$rewrite_auto && $::itest::semantic::rewrite_post_process &&
                [lsearch -exact [::itest::registered_events] REWRITE_RESPONSE_DONE] >= 0} {
                set ::itest::semantic::rewrite_injecting 1
                set rewrite_result [::itest::_testcl_fire_event_orig REWRITE_RESPONSE_DONE]
                set ::itest::semantic::rewrite_injecting 0
                ::itest::semantic::event_errors_record REWRITE_RESPONSE_DONE $rewrite_result
            }
            ::itest::semantic::compression_process_response
            ::itest::semantic::httplog_record response
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
    ws_payload_ivs ws_payload_ivs_command
    ws_payload_processing ws_payload_processing_command
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
    TCP::abc ::itest::semantic::tcp_abc_command
    TCP::analytics ::itest::semantic::tcp_analytics_command
    TCP::autowin ::itest::semantic::tcp_autowin_command
    TCP::congestion ::itest::semantic::tcp_congestion_command
    TCP::delayed_ack ::itest::semantic::tcp_delayed_ack_command
    TCP::dsack ::itest::semantic::tcp_dsack_command
    TCP::earlyrxmit ::itest::semantic::tcp_earlyrxmit_command
    TCP::ecn ::itest::semantic::tcp_ecn_command
    TCP::enhanced_loss_recovery ::itest::semantic::tcp_enhanced_loss_recovery_command
    TCP::idletime ::itest::semantic::tcp_idletime_command
    TCP::keepalive ::itest::semantic::tcp_keepalive_command
    TCP::limxmit ::itest::semantic::tcp_limxmit_command
    TCP::lossfilter ::itest::semantic::tcp_lossfilter_command
    TCP::lossfilterburst ::itest::semantic::tcp_lossfilter_burst_command
    TCP::lossfilterrate ::itest::semantic::tcp_lossfilter_rate_command
    TCP::nagle ::itest::semantic::tcp_nagle_command
    TCP::naglemode ::itest::semantic::tcp_naglemode_command
    TCP::naglestate ::itest::semantic::tcp_naglestate_command
    TCP::offset ::itest::semantic::tcp_offset_command
    TCP::payload ::itest::cmd::tcp_payload
    TCP::pacing ::itest::semantic::tcp_pacing_command
    TCP::proxybuffer ::itest::semantic::tcp_proxybuffer_command
    TCP::proxybufferhigh ::itest::semantic::tcp_proxybufferhigh_command
    TCP::proxybufferlow ::itest::semantic::tcp_proxybufferlow_command
    TCP::push_flag ::itest::semantic::tcp_push_flag_command
    TCP::rcv_size ::itest::semantic::tcp_rcv_size_command
    TCP::rcv_scale ::itest::semantic::tcp_rcv_scale_command
    TCP::recvwnd ::itest::semantic::tcp_recvwnd_command
    TCP::release ::itest::cmd::tcp_release
    TCP::respond ::itest::cmd::tcp_respond
    TCP::rto ::itest::semantic::tcp_rto_command
    TCP::rttvar ::itest::semantic::tcp_rttvar_command
    TCP::rexmt_thresh ::itest::semantic::tcp_rexmt_thresh_command
    TCP::rt_metrics_timeout ::itest::semantic::tcp_rt_metrics_timeout_command
    TCP::sendbuf ::itest::semantic::tcp_sendbuf_command
    TCP::setmss ::itest::semantic::tcp_setmss_command
    TCP::snd_cwnd ::itest::semantic::tcp_snd_cwnd_command
    TCP::snd_scale ::itest::semantic::tcp_snd_scale_command
    TCP::snd_ssthresh ::itest::semantic::tcp_snd_ssthresh_command
    TCP::snd_wnd ::itest::semantic::tcp_snd_wnd_command
    TCP::unused_port ::itest::semantic::tcp_unused_port_command
    RTSP::collect ::itest::semantic::rtsp_collect_command
    RTSP::header ::itest::semantic::rtsp_header_command
    RTSP::method ::itest::semantic::rtsp_method_command
    RTSP::msg_source ::itest::semantic::rtsp_msg_source_command
    RTSP::payload ::itest::semantic::rtsp_payload_command
    RTSP::release ::itest::semantic::rtsp_release_command
    RTSP::respond ::itest::semantic::rtsp_respond_command
    RTSP::status ::itest::semantic::rtsp_status_command
    RTSP::uri ::itest::semantic::rtsp_uri_command
    RTSP::version ::itest::semantic::rtsp_version_command
    CACHE::accept_encoding ::itest::semantic::cache_accept_encoding_command
    CACHE::age ::itest::semantic::cache_age_command
    CACHE::disable ::itest::semantic::cache_disable_command
    CACHE::disabled ::itest::semantic::cache_disabled_command
    CACHE::enable ::itest::semantic::cache_enable_command
    CACHE::expire ::itest::semantic::cache_expire_command
    CACHE::fresh ::itest::semantic::cache_fresh_command
    CACHE::header ::itest::semantic::cache_header_command
    CACHE::headers ::itest::semantic::cache_headers_command
    CACHE::hits ::itest::semantic::cache_hits_command
    CACHE::payload ::itest::semantic::cache_payload_command
    CACHE::priority ::itest::semantic::cache_priority_command
    CACHE::statskey ::itest::semantic::cache_statskey_command
    CACHE::trace ::itest::semantic::cache_trace_command
    CACHE::uri ::itest::semantic::cache_uri_command
    CACHE::useragent ::itest::semantic::cache_useragent_command
    CACHE::userkey ::itest::semantic::cache_userkey_command
    UDP::client_port ::itest::semantic::udp_client_port_command
    UDP::debug_queue ::itest::semantic::udp_debug_queue_command
    UDP::drop ::itest::semantic::udp_drop_command
    UDP::hold ::itest::semantic::udp_hold_command
    UDP::local_port ::itest::semantic::udp_local_port_command
    UDP::max_buf_pkts ::itest::semantic::udp_max_buf_pkts_command
    UDP::max_rate ::itest::semantic::udp_max_rate_command
    UDP::mss ::itest::semantic::udp_mss_command
    UDP::payload ::itest::semantic::udp_payload_command
    UDP::release ::itest::semantic::udp_release_command
    UDP::remote_port ::itest::semantic::udp_remote_port_command
    UDP::respond ::itest::semantic::udp_respond_command
    UDP::sendbuffer ::itest::semantic::udp_sendbuffer_command
    UDP::server_port ::itest::semantic::udp_server_port_command
    UDP::unused_port ::itest::semantic::udp_unused_port_command
    SCTP::client_port ::itest::semantic::sctp_client_port_command
    SCTP::collect ::itest::semantic::sctp_collect_command
    SCTP::local_port ::itest::semantic::sctp_local_port_command
    SCTP::mss ::itest::semantic::sctp_mss_command
    SCTP::payload ::itest::semantic::sctp_payload_command
    SCTP::ppi ::itest::semantic::sctp_ppi_command
    SCTP::release ::itest::semantic::sctp_release_command
    SCTP::respond ::itest::semantic::sctp_respond_command
    SCTP::remote_port ::itest::semantic::sctp_remote_port_command
    SCTP::rto_initial ::itest::semantic::sctp_rto_initial_command
    SCTP::rto_max ::itest::semantic::sctp_rto_max_command
    SCTP::rto_min ::itest::semantic::sctp_rto_min_command
    SCTP::sack_timeout ::itest::semantic::sctp_sack_timeout_command
    SCTP::server_port ::itest::semantic::sctp_server_port_command
    DHCP::version ::itest::semantic::dhcp_version_command
    DHCPv4::chaddr ::itest::semantic::dhcpv4_chaddr_command
    DHCPv4::ciaddr ::itest::semantic::dhcpv4_ciaddr_command
    DHCPv4::drop ::itest::semantic::dhcpv4_drop_command
    DHCPv4::giaddr ::itest::semantic::dhcpv4_giaddr_command
    DHCPv4::hlen ::itest::semantic::dhcpv4_hlen_command
    DHCPv4::hops ::itest::semantic::dhcpv4_hops_command
    DHCPv4::len ::itest::semantic::dhcpv4_len_command
    DHCPv4::opcode ::itest::semantic::dhcpv4_opcode_command
    DHCPv4::option ::itest::semantic::dhcpv4_option_command
    DHCPv4::reject ::itest::semantic::dhcpv4_reject_command
    DHCPv4::secs ::itest::semantic::dhcpv4_secs_command
    DHCPv4::siaddr ::itest::semantic::dhcpv4_siaddr_command
    DHCPv4::type ::itest::semantic::dhcpv4_type_command
    DHCPv4::xid ::itest::semantic::dhcpv4_xid_command
    DHCPv4::yiaddr ::itest::semantic::dhcpv4_yiaddr_command
    DHCPv6::drop ::itest::semantic::dhcpv6_drop_command
    DHCPv6::hop_count ::itest::semantic::dhcpv6_hop_count_command
    DHCPv6::len ::itest::semantic::dhcpv6_len_command
    DHCPv6::link_address ::itest::semantic::dhcpv6_link_address_command
    DHCPv6::msg_type ::itest::semantic::dhcpv6_msg_type_command
    DHCPv6::option ::itest::semantic::dhcpv6_option_command
    DHCPv6::peer_address ::itest::semantic::dhcpv6_peer_address_command
    DHCPv6::reject ::itest::semantic::dhcpv6_reject_command
    DHCPv6::transaction_id ::itest::semantic::dhcpv6_transaction_id_command
    FTP::allow_active_mode ::itest::semantic::ftp_allow_active_mode_command
    FTP::disable ::itest::semantic::ftp_disable_command
    FTP::enable ::itest::semantic::ftp_enable_command
    FTP::enforce_tls_session_reuse ::itest::semantic::ftp_enforce_tls_session_reuse_command
    FTP::ftps_mode ::itest::semantic::ftp_ftps_mode_command
    FTP::port ::itest::semantic::ftp_port_command
    IMAP::activation_mode ::itest::semantic::imap_activation_mode_command
    IMAP::disable ::itest::semantic::imap_disable_command
    IMAP::enable ::itest::semantic::imap_enable_command
    POP3::activation_mode ::itest::semantic::pop3_activation_mode_command
    POP3::disable ::itest::semantic::pop3_disable_command
    POP3::enable ::itest::semantic::pop3_enable_command
    LDAP::activation_mode ::itest::semantic::ldap_activation_mode_command
    LDAP::disable ::itest::semantic::ldap_disable_command
    LDAP::enable ::itest::semantic::ldap_enable_command
    SMTPS::activation_mode ::itest::semantic::smtps_activation_mode_command
    SMTPS::disable ::itest::semantic::smtps_disable_command
    SMTPS::enable ::itest::semantic::smtps_enable_command
    NTLM::disable ::itest::semantic::ntlm_disable_command
    NTLM::enable ::itest::semantic::ntlm_enable_command
    PROTOCOL_INSPECTION::disable ::itest::semantic::protocol_inspection_disable_command
    PROTOCOL_INSPECTION::id ::itest::semantic::protocol_inspection_id_command
    CLASSIFICATION::app ::itest::semantic::classification_app_command
    CLASSIFICATION::category ::itest::semantic::classification_category_command
    CLASSIFICATION::disable ::itest::semantic::classification_disable_command
    CLASSIFICATION::enable ::itest::semantic::classification_enable_command
    CLASSIFICATION::protocol ::itest::semantic::classification_protocol_command
    CLASSIFICATION::result ::itest::semantic::classification_result_command
    CLASSIFICATION::urlcat ::itest::semantic::classification_urlcat_command
    CLASSIFICATION::username ::itest::semantic::classification_username_command
    CLASSIFY::application ::itest::semantic::classify_application_command
    CLASSIFY::category ::itest::semantic::classify_category_command
    CLASSIFY::defer ::itest::semantic::classify_defer_command
    CLASSIFY::disable ::itest::semantic::classify_disable_command
    CLASSIFY::urlcat ::itest::semantic::classify_urlcat_command
    CLASSIFY::username ::itest::semantic::classify_username_command
    CATEGORY::analytics ::itest::semantic::category_analytics_command
    CATEGORY::filetype ::itest::semantic::category_filetype_command
    CATEGORY::lookup ::itest::semantic::category_lookup_command
    CATEGORY::matchtype ::itest::semantic::category_matchtype_command
    CATEGORY::result ::itest::semantic::category_result_command
    CATEGORY::safesearch ::itest::semantic::category_safesearch_command
    ICAP::header ::itest::semantic::icap_header_command
    ICAP::method ::itest::semantic::icap_method_command
    ICAP::status ::itest::semantic::icap_status_command
    ICAP::uri ::itest::semantic::icap_uri_command
    peer ::itest::cmd::cmd_peer
    clientside ::itest::cmd::cmd_clientside
    serverside ::itest::cmd::cmd_serverside
    IP::addr ::itest::semantic::ip_addr
    IP::version ::itest::semantic::ip_version
    IP::hops ::itest::semantic::ip_hops_command
    IP::idle_timeout ::itest::semantic::ip_idle_timeout_command
    IP::ingress_drop_rate ::itest::semantic::ip_ingress_drop_rate_command
    IP::ingress_rate_limit ::itest::semantic::ip_ingress_rate_limit_command
    IP::intelligence ::itest::semantic::ip_intelligence_command
    IP::reputation ::itest::semantic::ip_reputation_command
    IP::stats ::itest::semantic::ip_stats_command
    PROFILE::clientssl ::itest::semantic::profile_clientssl
    PROFILE::access ::itest::semantic::profile_access_command
    PROFILE::antifraud ::itest::semantic::profile_antifraud_command
    PROFILE::auth ::itest::semantic::profile_auth_command
    PROFILE::avr ::itest::semantic::profile_avr_command
    PROFILE::exists ::itest::semantic::profile_exists
    PROFILE::diameter ::itest::semantic::profile_diameter_command
    PROFILE::exchange ::itest::semantic::profile_exchange_command
    PROFILE::fastL4 ::itest::semantic::profile_fastL4
    PROFILE::fasthttp ::itest::semantic::profile_fasthttp
    PROFILE::ftp ::itest::semantic::profile_ftp_command
    PROFILE::http ::itest::semantic::profile_http
    PROFILE::httpclass ::itest::semantic::profile_httpclass_command
    PROFILE::httpcompression ::itest::semantic::profile_httpcompression_command
    PROFILE::list ::itest::semantic::profile_list
    PROFILE::oneconnect ::itest::semantic::profile_oneconnect_command
    PROFILE::persist ::itest::semantic::profile_persist_command
    PROFILE::serverssl ::itest::semantic::profile_serverssl
    PROFILE::stream ::itest::semantic::profile_stream_command
    PROFILE::tcp ::itest::semantic::profile_tcp
    PROFILE::tftp ::itest::semantic::profile_tftp_command
    PROFILE::udp ::itest::semantic::profile_udp
    PROFILE::vdi ::itest::semantic::profile_vdi_command
    PROFILE::webacceleration ::itest::semantic::profile_webacceleration_command
    PROFILE::xml ::itest::semantic::profile_xml_command
    DOSL7::disable ::itest::semantic::dosl7_disable
    DOSL7::enable ::itest::semantic::dosl7_enable
    DOSL7::health ::itest::semantic::dosl7_health
    DOSL7::is_ip_slowdown ::itest::semantic::dosl7_is_ip_slowdown
    DOSL7::is_mitigated ::itest::semantic::dosl7_is_mitigated
    DOSL7::profile ::itest::semantic::dosl7_profile
    DOSL7::slowdown ::itest::semantic::dosl7_slowdown
    ASM::captcha ::itest::semantic::asm_captcha
    ASM::captcha_age ::itest::semantic::asm_captcha_age
    ASM::captcha_status ::itest::semantic::asm_captcha_status
    ASM::client_ip ::itest::semantic::asm_client_ip
    ASM::conviction ::itest::semantic::asm_conviction
    ASM::deception ::itest::semantic::asm_deception
    ASM::disable ::itest::semantic::asm_disable
    ASM::enable ::itest::semantic::asm_enable
    ASM::fingerprint ::itest::semantic::asm_fingerprint
    ASM::is_authenticated ::itest::semantic::asm_is_authenticated
    ASM::login_status ::itest::semantic::asm_login_status
    ASM::microservice ::itest::semantic::asm_microservice
    ASM::payload ::itest::semantic::asm_payload
    ASM::policy ::itest::semantic::asm_policy
    ASM::raise ::itest::semantic::asm_raise
    ASM::severity ::itest::semantic::asm_severity
    ASM::signature ::itest::semantic::asm_signature
    ASM::status ::itest::semantic::asm_status
    ASM::support_id ::itest::semantic::asm_support_id
    ASM::threat_campaign ::itest::semantic::asm_threat_campaign
    ASM::unblock ::itest::semantic::asm_unblock
    ASM::uncaptcha ::itest::semantic::asm_uncaptcha
    ASM::username ::itest::semantic::asm_username
    ASM::violation ::itest::semantic::asm_violation
    ASM::violation_data ::itest::semantic::asm_violation_data
    BOTDEFENSE::action ::itest::semantic::botdefense_action
    BOTDEFENSE::bot_anomalies ::itest::semantic::botdefense_bot_anomalies
    BOTDEFENSE::bot_categories ::itest::semantic::botdefense_bot_categories
    BOTDEFENSE::bot_name ::itest::semantic::botdefense_bot_name
    BOTDEFENSE::bot_signature ::itest::semantic::botdefense_bot_signature
    BOTDEFENSE::bot_signature_category ::itest::semantic::botdefense_bot_signature_category
    BOTDEFENSE::captcha_age ::itest::semantic::botdefense_captcha_age
    BOTDEFENSE::captcha_status ::itest::semantic::botdefense_captcha_status
    BOTDEFENSE::client_class ::itest::semantic::botdefense_client_class
    BOTDEFENSE::client_type ::itest::semantic::botdefense_client_type
    BOTDEFENSE::cookie_age ::itest::semantic::botdefense_cookie_age
    BOTDEFENSE::cookie_status ::itest::semantic::botdefense_cookie_status
    BOTDEFENSE::cs_allowed ::itest::semantic::botdefense_cs_allowed
    BOTDEFENSE::cs_attribute ::itest::semantic::botdefense_cs_attribute
    BOTDEFENSE::cs_possible ::itest::semantic::botdefense_cs_possible
    BOTDEFENSE::device_id ::itest::semantic::botdefense_device_id
    BOTDEFENSE::disable ::itest::semantic::botdefense_disable
    BOTDEFENSE::enable ::itest::semantic::botdefense_enable
    BOTDEFENSE::intent ::itest::semantic::botdefense_intent
    BOTDEFENSE::micro_service ::itest::semantic::botdefense_micro_service
    BOTDEFENSE::previous_action ::itest::semantic::botdefense_previous_action
    BOTDEFENSE::previous_request_age ::itest::semantic::botdefense_previous_request_age
    BOTDEFENSE::previous_support_id ::itest::semantic::botdefense_previous_support_id
    BOTDEFENSE::reason ::itest::semantic::botdefense_reason
    BOTDEFENSE::support_id ::itest::semantic::botdefense_support_id
    ANTIFRAUD::alert_additional_info ::itest::semantic::antifraud_alert_additional_info
    ANTIFRAUD::alert_bait_signatures ::itest::semantic::antifraud_alert_bait_signatures
    ANTIFRAUD::alert_component ::itest::semantic::antifraud_alert_component
    ANTIFRAUD::alert_defined_value ::itest::semantic::antifraud_alert_defined_value
    ANTIFRAUD::alert_details ::itest::semantic::antifraud_alert_details
    ANTIFRAUD::alert_device_id ::itest::semantic::antifraud_alert_device_id
    ANTIFRAUD::alert_expected_value ::itest::semantic::antifraud_alert_expected_value
    ANTIFRAUD::alert_fingerprint ::itest::semantic::antifraud_alert_fingerprint
    ANTIFRAUD::alert_forbidden_added_element ::itest::semantic::antifraud_alert_forbidden_added_element
    ANTIFRAUD::alert_guid ::itest::semantic::antifraud_alert_guid
    ANTIFRAUD::alert_html ::itest::semantic::antifraud_alert_html
    ANTIFRAUD::alert_http_referrer ::itest::semantic::antifraud_alert_http_referrer
    ANTIFRAUD::alert_id ::itest::semantic::antifraud_alert_id
    ANTIFRAUD::alert_license_id ::itest::semantic::antifraud_alert_license_id
    ANTIFRAUD::alert_min ::itest::semantic::antifraud_alert_min
    ANTIFRAUD::alert_origin ::itest::semantic::antifraud_alert_origin
    ANTIFRAUD::alert_resolved_value ::itest::semantic::antifraud_alert_resolved_value
    ANTIFRAUD::alert_score ::itest::semantic::antifraud_alert_score
    ANTIFRAUD::alert_transaction_data ::itest::semantic::antifraud_alert_transaction_data
    ANTIFRAUD::alert_transaction_id ::itest::semantic::antifraud_alert_transaction_id
    ANTIFRAUD::alert_type ::itest::semantic::antifraud_alert_type
    ANTIFRAUD::alert_username ::itest::semantic::antifraud_alert_username
    ANTIFRAUD::alert_view_id ::itest::semantic::antifraud_alert_view_id
    ANTIFRAUD::client_id ::itest::semantic::antifraud_client_id
    ANTIFRAUD::device_id ::itest::semantic::antifraud_device_id
    ANTIFRAUD::disable ::itest::semantic::antifraud_disable
    ANTIFRAUD::disable_alert ::itest::semantic::antifraud_disable_alert
    ANTIFRAUD::disable_app_layer_encryption ::itest::semantic::antifraud_disable_app_layer_encryption
    ANTIFRAUD::disable_auto_transactions ::itest::semantic::antifraud_disable_auto_transactions
    ANTIFRAUD::disable_injection ::itest::semantic::antifraud_disable_injection
    ANTIFRAUD::disable_malware ::itest::semantic::antifraud_disable_malware
    ANTIFRAUD::disable_phishing ::itest::semantic::antifraud_disable_phishing
    ANTIFRAUD::enable ::itest::semantic::antifraud_enable
    ANTIFRAUD::enable_log ::itest::semantic::antifraud_enable_log
    ANTIFRAUD::fingerprint ::itest::semantic::antifraud_fingerprint
    ANTIFRAUD::geo ::itest::semantic::antifraud_geo
    ANTIFRAUD::guid ::itest::semantic::antifraud_guid
    ANTIFRAUD::result ::itest::semantic::antifraud_result
    ANTIFRAUD::username ::itest::semantic::antifraud_username
    AAA::acct_result ::itest::semantic::aaa_acct_result
    AAA::acct_send ::itest::semantic::aaa_acct_send
    AAA::auth_result ::itest::semantic::aaa_auth_result
    AAA::auth_send ::itest::semantic::aaa_auth_send
    ACCESS::acl ::itest::semantic::access_acl
    ACCESS::disable ::itest::semantic::access_disable
    ACCESS::enable ::itest::semantic::access_enable
    ACCESS::ephemeral-auth ::itest::semantic::access_ephemeral_auth
    ACCESS::flowid ::itest::semantic::access_flowid
    ACCESS::log ::itest::semantic::access_log
    ACCESS::oauth ::itest::semantic::access_oauth
    ACCESS::perflow ::itest::semantic::access_perflow
    ACCESS::policy ::itest::semantic::access_policy
    ACCESS::respond ::itest::semantic::access_respond
    ACCESS::restrict_irule_events ::itest::semantic::access_restrict_irule_events
    ACCESS::saml ::itest::semantic::access_saml
    ACCESS::session ::itest::semantic::access_session
    ACCESS::user ::itest::semantic::access_user
    ACCESS::uuid ::itest::semantic::access_uuid
    AUTH::abort ::itest::semantic::auth_abort
    AUTH::authenticate ::itest::semantic::auth_authenticate
    AUTH::authenticate_continue ::itest::semantic::auth_authenticate_continue
    AUTH::cert_credential ::itest::semantic::auth_cert_credential
    AUTH::cert_issuer_credential ::itest::semantic::auth_cert_issuer_credential
    AUTH::last_event_session_id ::itest::semantic::auth_last_event_session_id
    AUTH::password_credential ::itest::semantic::auth_password_credential
    AUTH::response_data ::itest::semantic::auth_response_data
    AUTH::ssl_cc_ldap_status ::itest::semantic::auth_ssl_cc_ldap_status
    AUTH::ssl_cc_ldap_username ::itest::semantic::auth_ssl_cc_ldap_username
    AUTH::start ::itest::semantic::auth_start
    AUTH::status ::itest::semantic::auth_status
    AUTH::subscribe ::itest::semantic::auth_subscribe
    AUTH::unsubscribe ::itest::semantic::auth_unsubscribe
    AUTH::username_credential ::itest::semantic::auth_username_credential
    AUTH::wantcredential_prompt ::itest::semantic::auth_wantcredential_prompt
    AUTH::wantcredential_prompt_style ::itest::semantic::auth_wantcredential_prompt_style
    AUTH::wantcredential_type ::itest::semantic::auth_wantcredential_type
    FLOW::create_related ::itest::semantic::flow_create_related
    FLOW::idle_duration ::itest::semantic::flow_idle_duration
    FLOW::idle_timeout ::itest::semantic::flow_idle_timeout
    FLOW::peer ::itest::semantic::flow_peer
    FLOW::priority ::itest::semantic::flow_priority
    FLOW::refresh ::itest::semantic::flow_refresh
    FLOW::this ::itest::semantic::flow_this
    STATS::get ::itest::semantic::stats_get
    STATS::incr ::itest::semantic::stats_incr
    STATS::set ::itest::semantic::stats_set
    STATS::setmax ::itest::semantic::stats_setmax
    STATS::setmin ::itest::semantic::stats_setmin
    ADAPT::allow ::itest::semantic::adapt_allow
    ADAPT::context_create ::itest::semantic::adapt_context_create
    ADAPT::context_current ::itest::semantic::adapt_context_current
    ADAPT::context_delete_all ::itest::semantic::adapt_context_delete_all
    ADAPT::context_name ::itest::semantic::adapt_context_name
    ADAPT::context_static ::itest::semantic::adapt_context_static
    ADAPT::enable ::itest::semantic::adapt_enable
    ADAPT::preview_size ::itest::semantic::adapt_preview_size
    ADAPT::result ::itest::semantic::adapt_result
    ADAPT::select ::itest::semantic::adapt_select
    ADAPT::service_down_action ::itest::semantic::adapt_service_down_action
    ADAPT::timeout ::itest::semantic::adapt_timeout
    DATAGRAM::dns ::itest::semantic::datagram_dns
    DATAGRAM::ip ::itest::semantic::datagram_ip
    DATAGRAM::ip6 ::itest::semantic::datagram_ip6
    DATAGRAM::l2 ::itest::semantic::datagram_l2
    DATAGRAM::tcp ::itest::semantic::datagram_tcp
    DATAGRAM::udp ::itest::semantic::datagram_udp
    CRYPTO::hash ::itest::semantic::crypto_hash_command
    CRYPTO::sign ::itest::semantic::crypto_sign_command
    CRYPTO::verify ::itest::semantic::crypto_verify_command
    ISTATS::get ::itest::semantic::istats_get
    ISTATS::incr ::itest::semantic::istats_incr
    ISTATS::remove ::itest::semantic::istats_remove
    ISTATS::set ::itest::semantic::istats_set
    ONECONNECT::detach ::itest::semantic::oneconnect_detach_command
    ONECONNECT::label ::itest::semantic::oneconnect_label_command
    ONECONNECT::reuse ::itest::semantic::oneconnect_reuse_command
    ONECONNECT::select ::itest::semantic::oneconnect_select_command
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
    DNS::tsig ::itest::semantic::dns_tsig_command
    DNS::type ::itest::semantic::dns_type_command
    DNSMSG::header ::itest::semantic::dnsmsg_header_command
    DNSMSG::record ::itest::semantic::dnsmsg_record_command
    DNSMSG::section ::itest::semantic::dnsmsg_section_command
    RESOLVER::name_lookup ::itest::semantic::resolver_name_lookup
    RESOLVER::summarize ::itest::semantic::resolver_summarize
    SSL::cert ::itest::semantic::ssl_cert_command
    SSL::c3d ::itest::semantic::ssl_c3d_command
    SSL::cert_constraint ::itest::semantic::ssl_cert_constraint_command
    SSL::collect ::itest::semantic::ssl_collect_command
    SSL::cipher ::itest::semantic::ssl_cipher_command
    SSL::alpn ::itest::semantic::ssl_alpn_command
    SSL::allow_dynamic_record_sizing ::itest::semantic::ssl_allow_dynamic_record_sizing_command
    SSL::allow_nonssl ::itest::semantic::ssl_allow_nonssl_command
    SSL::authenticate ::itest::semantic::ssl_authenticate_command
    SSL::clientrandom ::itest::semantic::ssl_clientrandom_command
    SSL::disable ::itest::semantic::ssl_disable_command
    SSL::enable ::itest::semantic::ssl_enable_command
    SSL::handshake ::itest::semantic::ssl_handshake_command
    SSL::is_renegotiation_secure ::itest::semantic::ssl_is_renegotiation_secure_command
    SSL::maximum_record_size ::itest::semantic::ssl_maximum_record_size_command
    SSL::modssl_sessionid_headers ::itest::semantic::ssl_modssl_sessionid_headers_command
    SSL::mode ::itest::semantic::ssl_mode_command
    SSL::nextproto ::itest::semantic::ssl_nextproto_command
    SSL::payload ::itest::semantic::ssl_payload_command
    SSL::profile ::itest::semantic::ssl_profile_command
    SSL::renegotiate ::itest::semantic::ssl_renegotiate_command
    SSL::release ::itest::semantic::ssl_release_command
    SSL::secure_renegotiation ::itest::semantic::ssl_secure_renegotiation_command
    SSL::session ::itest::semantic::ssl_session_command
    SSL::sessionsecret ::itest::semantic::ssl_sessionsecret_command
    SSL::sessionid ::itest::semantic::ssl_sessionid_command
    SSL::sessionticket ::itest::semantic::ssl_sessionticket_command
    SSL::sni ::itest::semantic::ssl_sni_command
    SSL::tls13_secret ::itest::semantic::ssl_tls13_secret_command
    SSL::verify_result ::itest::semantic::ssl_verify_result_command
    SSL::forward_proxy ::itest::semantic::ssl_forward_proxy_command
    SSL::unclean_shutdown ::itest::semantic::ssl_unclean_shutdown_command
    X509::cert_fields ::itest::semantic::x509_cert_fields_command
    X509::extensions ::itest::semantic::x509_extensions_command
    X509::hash ::itest::semantic::x509_hash_command
    X509::issuer ::itest::semantic::x509_issuer_command
    X509::not_valid_after ::itest::semantic::x509_not_valid_after_command
    X509::not_valid_before ::itest::semantic::x509_not_valid_before_command
    X509::pem2der ::itest::semantic::x509_pem2der_command
    X509::serial_number ::itest::semantic::x509_serial_number_command
    X509::signature_algorithm ::itest::semantic::x509_signature_algorithm_command
    X509::subject ::itest::semantic::x509_subject_command
    X509::subject_public_key ::itest::semantic::x509_subject_public_key_command
    X509::subject_public_key_RSA_bits ::itest::semantic::x509_subject_public_key_RSA_bits_command
    X509::subject_public_key_type ::itest::semantic::x509_subject_public_key_type_command
    X509::verify_cert_error_string ::itest::semantic::x509_verify_cert_error_string_command
    X509::version ::itest::semantic::x509_version_command
    X509::whole ::itest::semantic::x509_whole_command
    HTTP2::active ::itest::semantic::http2_active_command
    HTTP2::concurrency ::itest::semantic::http2_concurrency_command
    HTTP2::disable ::itest::semantic::http2_disable_command
    HTTP2::disconnect ::itest::semantic::http2_disconnect_command
    HTTP2::enable ::itest::semantic::http2_enable_command
    HTTP2::header ::itest::semantic::http2_header_command
    HTTP2::requests ::itest::semantic::http2_requests_command
    HTTP2::push ::itest::semantic::http2_push_command
    HTTP2::stream ::itest::semantic::http2_stream_command
    HTTP2::version ::itest::semantic::http2_version_command
    HTTP::proxy ::itest::semantic::http_proxy_command
    REWRITE::disable ::itest::semantic::rewrite_disable_command
    REWRITE::enable ::itest::semantic::rewrite_enable_command
    REWRITE::payload ::itest::semantic::rewrite_payload_command
    REWRITE::post_process ::itest::semantic::rewrite_post_process_command
    HTML::comment ::itest::semantic::html_comment_command
    HTML::disable ::itest::semantic::html_disable_command
    HTML::enable ::itest::semantic::html_enable_command
    HTML::encode ::itest::semantic::html_encode_command
    HTML::tag ::itest::semantic::html_tag_command
    HTTPLOG::disable ::itest::semantic::httplog_disable_command
    HTTPLOG::enable ::itest::semantic::httplog_enable_command
    COMPRESS::buffer_size ::itest::semantic::compression_buffer_size_command
    COMPRESS::disable ::itest::semantic::compression_disable_command
    COMPRESS::enable ::itest::semantic::compression_enable_command
    COMPRESS::gzip ::itest::semantic::compression_gzip_command
    COMPRESS::method ::itest::semantic::compression_method_command
    COMPRESS::nodelay ::itest::semantic::compression_nodelay_command
    DECOMPRESS::disable ::itest::semantic::decompression_disable_command
    DECOMPRESS::enable ::itest::semantic::decompression_enable_command
    ROUTE::age ::itest::semantic::route_age_command
    ROUTE::bandwidth ::itest::semantic::route_bandwidth_command
    ROUTE::clear ::itest::semantic::route_clear_command
    ROUTE::cwnd ::itest::semantic::route_cwnd_command
    ROUTE::domain ::itest::semantic::route_domain_command
    ROUTE::expiration ::itest::semantic::route_expiration_command
    ROUTE::mtu ::itest::semantic::route_mtu_command
    ROUTE::rtt ::itest::semantic::route_rtt_command
    ROUTE::rttvar ::itest::semantic::route_rttvar_command
    STREAM::disable ::itest::semantic::stream_disable_command
    STREAM::enable ::itest::semantic::stream_enable_command
    STREAM::encoding ::itest::semantic::stream_encoding_command
    STREAM::expression ::itest::semantic::stream_expression_command
    STREAM::match ::itest::semantic::stream_match_command
    STREAM::max_matchsize ::itest::semantic::stream_max_matchsize_command
    STREAM::replace ::itest::semantic::stream_replace_command
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
    MQTT::insert ::itest::semantic::mqtt_insert_command
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
    MQTT::replace ::itest::semantic::mqtt_replace_command
    MQTT::respond ::itest::semantic::mqtt_respond_command
    MQTT::session_present ::itest::cmd::mqtt_session_present
    MQTT::topic ::itest::cmd::mqtt_topic
    MQTT::type ::itest::cmd::mqtt_type
    MQTT::username ::itest::cmd::mqtt_username
    MQTT::will ::itest::semantic::mqtt_will_command
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
    PSM::FTP::disable ::itest::semantic::psm_ftp_disable
    PSM::FTP::enable ::itest::semantic::psm_ftp_enable
    PSM::HTTP::disable ::itest::semantic::psm_http_disable
    PSM::HTTP::enable ::itest::semantic::psm_http_enable
    PSM::SMTP::disable ::itest::semantic::psm_smtp_disable
    PSM::SMTP::enable ::itest::semantic::psm_smtp_enable
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
        if {[llength $args] > 0} {
            ::itest::semantic::flow_begin_event [lindex $args 0]
        }
        set result [eval [linsert $args 0 ::itest::semantic::_testcl_fire_event_orig]]
        if {[llength $args] > 0} {
            ::itest::semantic::event_errors_record [lindex $args 0] $result
        }
        return $result
    }
}
