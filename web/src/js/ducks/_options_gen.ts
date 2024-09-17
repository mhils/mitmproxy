/** Auto-generated by web/gen/options_js.py */
export interface OptionsState {
    add_upstream_certs_to_client_chain: boolean;
    allow_hosts: string[];
    anticache: boolean;
    anticomp: boolean;
    block_global: boolean;
    block_list: string[];
    block_private: boolean;
    body_size_limit: string | undefined;
    cert_passphrase: string | undefined;
    certs: string[];
    ciphers_client: string | undefined;
    ciphers_server: string | undefined;
    client_certs: string | undefined;
    client_replay: string[];
    client_replay_concurrency: number;
    command_history: boolean;
    confdir: string;
    connect_addr: string | undefined;
    connection_strategy: string;
    console_focus_follow: boolean;
    content_view_lines_cutoff: number;
    dns_name_servers: string[];
    dns_use_hosts_file: boolean;
    export_preserve_original_ip: boolean;
    hardump: string;
    http2: boolean;
    http2_ping_keepalive: number;
    http3: boolean;
    http_connect_send_host_header: boolean;
    ignore_hosts: string[];
    intercept: string | undefined;
    intercept_active: boolean;
    keep_alt_svc_header: boolean;
    keep_host_header: boolean;
    key_size: number;
    listen_host: string;
    listen_port: number | undefined;
    map_local: string[];
    map_remote: string[];
    mode: string[];
    modify_body: string[];
    modify_headers: string[];
    normalize_outbound_headers: boolean;
    onboarding: boolean;
    onboarding_host: string;
    proxy_debug: boolean;
    proxyauth: string | undefined;
    rawtcp: boolean;
    readfile_filter: string | undefined;
    request_client_cert: boolean;
    rfile: string | undefined;
    save_stream_file: string | undefined;
    save_stream_filter: string | undefined;
    scripts: string[];
    server: boolean;
    server_replay: string[];
    server_replay_extra: string;
    server_replay_ignore_content: boolean;
    server_replay_ignore_host: boolean;
    server_replay_ignore_params: string[];
    server_replay_ignore_payload_params: string[];
    server_replay_ignore_port: boolean;
    server_replay_kill_extra: boolean;
    server_replay_nopop: boolean;
    server_replay_refresh: boolean;
    server_replay_reuse: boolean;
    server_replay_use_headers: string[];
    showhost: boolean;
    ssl_insecure: boolean;
    ssl_verify_upstream_trusted_ca: string | undefined;
    ssl_verify_upstream_trusted_confdir: string | undefined;
    stickyauth: string | undefined;
    stickycookie: string | undefined;
    stream_large_bodies: string | undefined;
    strip_ech: boolean;
    tcp_hosts: string[];
    termlog_verbosity: string;
    tls_ecdh_curve_client: string | undefined;
    tls_ecdh_curve_server: string | undefined;
    tls_version_client_max: string;
    tls_version_client_min: string;
    tls_version_server_max: string;
    tls_version_server_min: string;
    udp_hosts: string[];
    upstream_auth: string | undefined;
    upstream_cert: boolean;
    validate_inbound_headers: boolean;
    view_filter: string | undefined;
    view_order: string;
    view_order_reversed: boolean;
    web_columns: string[];
    web_debug: boolean;
    web_host: string;
    web_open_browser: boolean;
    web_port: number;
    web_static_viewer: string | undefined;
    websocket: boolean;
}

export type Option = keyof OptionsState;

export const defaultState: OptionsState = {
    add_upstream_certs_to_client_chain: false,
    allow_hosts: [],
    anticache: false,
    anticomp: false,
    block_global: true,
    block_list: [],
    block_private: false,
    body_size_limit: undefined,
    cert_passphrase: undefined,
    certs: [],
    ciphers_client: undefined,
    ciphers_server: undefined,
    client_certs: undefined,
    client_replay: [],
    client_replay_concurrency: 1,
    command_history: true,
    confdir: "~/.mitmproxy",
    connect_addr: undefined,
    connection_strategy: "eager",
    console_focus_follow: false,
    content_view_lines_cutoff: 512,
    dns_name_servers: [],
    dns_use_hosts_file: true,
    export_preserve_original_ip: false,
    hardump: "",
    http2: true,
    http2_ping_keepalive: 58,
    http3: true,
    http_connect_send_host_header: true,
    ignore_hosts: [],
    intercept: undefined,
    intercept_active: false,
    keep_alt_svc_header: false,
    keep_host_header: false,
    key_size: 2048,
    listen_host: "",
    listen_port: undefined,
    map_local: [],
    map_remote: [],
    mode: ["regular"],
    modify_body: [],
    modify_headers: [],
    normalize_outbound_headers: true,
    onboarding: true,
    onboarding_host: "mitm.it",
    proxy_debug: false,
    proxyauth: undefined,
    rawtcp: true,
    readfile_filter: undefined,
    request_client_cert: false,
    rfile: undefined,
    save_stream_file: undefined,
    save_stream_filter: undefined,
    scripts: [],
    server: true,
    server_replay: [],
    server_replay_extra: "forward",
    server_replay_ignore_content: false,
    server_replay_ignore_host: false,
    server_replay_ignore_params: [],
    server_replay_ignore_payload_params: [],
    server_replay_ignore_port: false,
    server_replay_kill_extra: false,
    server_replay_nopop: false,
    server_replay_refresh: true,
    server_replay_reuse: false,
    server_replay_use_headers: [],
    showhost: false,
    ssl_insecure: false,
    ssl_verify_upstream_trusted_ca: undefined,
    ssl_verify_upstream_trusted_confdir: undefined,
    stickyauth: undefined,
    stickycookie: undefined,
    stream_large_bodies: undefined,
    strip_ech: true,
    tcp_hosts: [],
    termlog_verbosity: "info",
    tls_ecdh_curve_client: undefined,
    tls_ecdh_curve_server: undefined,
    tls_version_client_max: "UNBOUNDED",
    tls_version_client_min: "TLS1_2",
    tls_version_server_max: "UNBOUNDED",
    tls_version_server_min: "TLS1_2",
    udp_hosts: [],
    upstream_auth: undefined,
    upstream_cert: true,
    validate_inbound_headers: true,
    view_filter: undefined,
    view_order: "time",
    view_order_reversed: false,
    web_columns: ["tls", "icon", "path", "method", "status", "size", "time"],
    web_debug: false,
    web_host: "127.0.0.1",
    web_open_browser: true,
    web_port: 8081,
    web_static_viewer: "",
    websocket: true,
};
