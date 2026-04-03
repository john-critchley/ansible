#!/usr/bin/perl
use strict;
use warnings;

use Mojolicious::Lite;
use Mojo::UserAgent;
use Mojo::URL;
use Mojo::JSON qw(decode_json);
use Mojo::Util qw(b64_decode b64_encode);
use File::Slurp qw(read_file);
use Crypt::JWT qw(decode_jwt);
use Net::LDAP;
use Net::LDAP::Util qw(escape_filter_value);

# Canonical perl-auth flow assembled in order from Derek/perl-auth.
# Basic WebLogic integration is wired in route_home via call_weblogic().

# main
my $creds = load_creds();

app->secrets([b64_encode(pack('N4', map { int rand 0xFFFFFFFF } 1..4), '')]);
app->sessions->default_expiration($creds->{session_expiry});

get '/callback'    => \&route_callback;
get '/logout'      => \&route_logout;
get  '/breakglass' => \&route_breakglass_form;
post '/breakglass' => \&route_breakglass_auth;

under '/' => \&check_auth;

get '/'      => \&route_home;
get '/ops'   => \&route_ops;
post '/ops/action' => \&route_ops_action;
get '/debug' => sub {
    my $c = shift;
    my $email = $c->session('email') // '';
    my $name = $c->session('name') // '';
    my $has_token = $c->session('id_token') ? 'yes' : 'no';
    my $has_refresh_token = $c->session('refresh_token') ? 'yes' : 'no';
    my $token_exp = $c->session('id_token_exp') // '';
    my $groups = $c->session('ldap_groups') || [];
    $c->render(json => {
        email        => $email,
        name         => $name,
        has_id_token => $has_token,
        has_refresh_token => $has_refresh_token,
        id_token_exp => $token_exp,
        ldap_groups  => $groups,
        weblogic_url => $creds->{weblogic_url},
    });
};
get '/debug/refresh' => sub {
    my $c = shift;
    my ($ok, $reason) = ensure_fresh_id_token($c, 1);
    $c->render(json => {
        ok     => $ok ? 1 : 0,
        reason => $reason,
        has_refresh_token => $c->session('refresh_token') ? 1 : 0,
        id_token_exp      => ($c->session('id_token_exp') // ''),
    });
};

app->start;

# load_creds
sub load_creds {
    my $creds_file = '';
    my $session_expiry = 28800;
    my $weblogic_url = $ENV{WEBLOGIC_URL} || '';
    my $wls_basic_user = $ENV{WLS_BASIC_USER} || '';
    my $wls_basic_pass = $ENV{WLS_BASIC_PASS} || '';
    my $ldap_uri = $ENV{LDAP_URI} || 'ldap://weblogicserver:389';
    my $ldap_bind_dn = $ENV{LDAP_BIND_DN} || 'cn=admin,dc=critchley,dc=biz';
    my $ldap_bind_pass = $ENV{LDAP_BIND_PASS} || 'ldappass';
    my $ldap_user_base = $ENV{LDAP_USER_BASE} || 'ou=users,ou=winterbourne,dc=critchley,dc=biz';
    my $ldap_group_base = $ENV{LDAP_GROUP_BASE} || 'ou=groups,ou=winterbourne,dc=critchley,dc=biz';
    my $ldap_group_filter = $ENV{LDAP_GROUP_FILTER} || '(member=%USER_DN%)';

    for my $i (0..$#ARGV) {
        if ($ARGV[$i] eq '--creds' && defined $ARGV[$i + 1]) {
            $creds_file = $ARGV[$i + 1];
        }
        if ($ARGV[$i] eq '--session-expiry' && defined $ARGV[$i + 1]) {
            $session_expiry = $ARGV[$i + 1] + 0;
        }
        if ($ARGV[$i] eq '--weblogic-url' && defined $ARGV[$i + 1]) {
            $weblogic_url = $ARGV[$i + 1];
        }
        if ($ARGV[$i] eq '--wls-basic-user' && defined $ARGV[$i + 1]) {
            $wls_basic_user = $ARGV[$i + 1];
        }
        if ($ARGV[$i] eq '--wls-basic-pass' && defined $ARGV[$i + 1]) {
            $wls_basic_pass = $ARGV[$i + 1];
        }
        if ($ARGV[$i] eq '--ldap-uri' && defined $ARGV[$i + 1]) {
            $ldap_uri = $ARGV[$i + 1];
        }
        if ($ARGV[$i] eq '--ldap-bind-dn' && defined $ARGV[$i + 1]) {
            $ldap_bind_dn = $ARGV[$i + 1];
        }
        if ($ARGV[$i] eq '--ldap-bind-pass' && defined $ARGV[$i + 1]) {
            $ldap_bind_pass = $ARGV[$i + 1];
        }
        if ($ARGV[$i] eq '--ldap-user-base' && defined $ARGV[$i + 1]) {
            $ldap_user_base = $ARGV[$i + 1];
        }
        if ($ARGV[$i] eq '--ldap-group-base' && defined $ARGV[$i + 1]) {
            $ldap_group_base = $ARGV[$i + 1];
        }
        if ($ARGV[$i] eq '--ldap-group-filter' && defined $ARGV[$i + 1]) {
            $ldap_group_filter = $ARGV[$i + 1];
        }
    }

    if (!$weblogic_url) {
        for my $candidate (
            'http://weblogicserver:7001/testapp/',
        ) {
            my ($host) = $candidate =~ m{^https?://([^/:]+)};
            next unless $host && gethostbyname($host);
            $weblogic_url = $candidate;
            last;
        }
        $weblogic_url ||= 'http://weblogicserver:7001/testapp/';
    }

    die "Usage: perl weblogic_auth_app.pl daemon -l http://*:8080 -- --creds <client_secret.json> [--session-expiry <seconds>] [--weblogic-url <url>]\n"
        unless $creds_file;

    my $json = read_file($creds_file);
    my $data = decode_json($json)->{web};

    $data->{session_expiry} = $session_expiry;
    $data->{weblogic_url} = $weblogic_url;
    $data->{wls_basic_user} = $wls_basic_user;
    $data->{wls_basic_pass} = $wls_basic_pass;
    $data->{ldap_uri} = $ldap_uri;
    $data->{ldap_bind_dn} = $ldap_bind_dn;
    $data->{ldap_bind_pass} = $ldap_bind_pass;
    $data->{ldap_user_base} = $ldap_user_base;
    $data->{ldap_group_base} = $ldap_group_base;
    $data->{ldap_group_filter} = $ldap_group_filter;

    return $data;
}

# check_auth
sub check_auth {
    my $c = shift;

    if ($c->session('email')) {
        my ($ok, $why) = ensure_fresh_id_token($c);
        return 1 if $ok;

        warn "Session token refresh failed: $why\n";
        my $dest = $c->req->url->to_abs->to_string;
        $c->session(expires => 1);
        $c->session(redirect_to => $dest);
        $c->redirect_to(google_auth_url());
        return 0;
    }

    $c->session(redirect_to => $c->req->url->to_abs->to_string);
    $c->redirect_to(google_auth_url());

    return 0;
}

# google_auth_url (route-login note)
sub google_auth_url {
    my $url = Mojo::URL->new($creds->{auth_uri});

    $url->query(
        client_id     => $creds->{client_id},
        redirect_uri  => $creds->{redirect_uris}[0],
        response_type => 'code',
        scope         => 'openid email profile',
        access_type   => 'offline',
        prompt        => 'consent',
        state         => 'lab',
    );

    return $url->to_string;
}

# route_callback
sub route_callback {
    my $c = shift;

    my $code = $c->param('code')
        or return $c->render(status => 400, text => "No code\n");

    my $ua = Mojo::UserAgent->new;
    my $res = $ua->post($creds->{token_uri} => form => {
        code          => $code,
        client_id     => $creds->{client_id},
        client_secret => $creds->{client_secret},
        redirect_uri  => $creds->{redirect_uris}[0],
        grant_type    => 'authorization_code',
    })->result;

    unless ($res->is_success) {
        return $c->render(status => 500, text => "Token exchange failed: " . $res->body . "\n");
    }

    my $id_token = $res->json->{id_token};
    my $refresh_token = $res->json->{refresh_token};
    my $expires_in = $res->json->{expires_in};
    my $payload = verify_jwt($id_token)
        or return $c->render(status => 401, text => "JWT verification failed\n");

    # Persist identity, token metadata, and LDAP groups for UI/auth decisions.
    update_session_identity($c, $payload, $id_token, $refresh_token, $expires_in);

    my $dest = delete $c->session->{redirect_to} // '/';
    $c->redirect_to($dest);
}

# route_logout
sub route_logout {
    my $c = shift;
    $c->session(expires => 1);
    $c->redirect_to('/');
}

# route_breakglass_form — GET /breakglass
# Emergency access form. Outside check_auth — works even if Google is down.
sub route_breakglass_form {
    my $c = shift;
    $c->render(format => 'html', text => <<'HTML');
<!DOCTYPE html>
<html>
<head><title>Break-Glass Emergency Access</title>
<style>
  body { font-family: monospace; max-width: 480px; margin: 60px auto; }
  h1   { color: #c00; }
  label { display: block; margin: 12px 0 4px; }
  input[type=text], input[type=password] { width: 100%; padding: 6px; box-sizing: border-box; }
  input[type=submit] { margin-top: 16px; padding: 8px 20px; background: #c00; color: #fff; border: none; cursor: pointer; }
  .warn { background: #fff3cd; border: 1px solid #ffc107; padding: 10px; margin-bottom: 20px; }
</style>
</head>
<body>
<h1>&#9888; Break-Glass Emergency Access</h1>
<div class="warn">
  This bypasses Google OAuth2 and the JWT asserter.<br>
  Use only when the normal authentication path is unavailable.<br>
  All access is logged.
</div>
<form method="POST" action="/breakglass">
  <label>WebLogic username</label>
  <input type="text" name="username" autocomplete="off" autofocus />
  <label>Password</label>
  <input type="password" name="password" />
  <input type="submit" value="Emergency Login" />
</form>
</body>
</html>
HTML
}

# route_breakglass_auth — POST /breakglass
# Calls WebLogic with Basic auth using the submitted credentials.
sub route_breakglass_auth {
    my $c = shift;

    my $user = $c->param('username') // '';
    my $pass = $c->param('password') // '';

    return $c->render(status => 400, text => "Username and password are required.\n")
        unless $user ne '' && $pass ne '';

    # Break-glass uses the management REST API, not the testapp.
    # The testapp uses CLIENT-CERT auth-method (identity asserters only).
    # The management API uses standard Basic auth against all configured
    # authenticators — including DefaultAuthenticator where breakglass lives.
    my ($base_url) = $creds->{weblogic_url} =~ m{^(https?://[^/]+)};
    my $url = ($base_url || 'http://weblogicserver:7001') . '/management/weblogic/latest';

    my $ua   = Mojo::UserAgent->new;
    my $auth = 'Basic ' . b64_encode("$user:$pass", '');

    my $tx = eval { $ua->get($url => { Authorization => $auth, Accept => 'application/json' }) };
    if (!$tx) {
        my $err = $@ || 'Unknown error'; chomp $err;
        return $c->render(status => 502, text => "Break-glass: connection to WebLogic failed: $err\n");
    }

    my $res = $tx->result;
    if ($res->is_success) {
        return $c->render(text =>
            "BREAK-GLASS ACCESS GRANTED\n" .
            "==========================\n" .
            "User:     $user\n" .
            "Auth:     Basic (local WebLogic DefaultAuthenticator)\n" .
            "Endpoint: $url\n\n" .
            "WebLogic responded HTTP " . $res->code . " -- server is accessible.\n"
        );
    }

    return $c->render(status => $res->code || 502, text =>
        "Break-glass auth failed (HTTP " . ($res->code || 502) . ")\n" .
        "User: $user\n"
    );
}

# route_home
sub route_home {
    my $c = shift;

    my ($token_ok, $token_why) = ensure_fresh_id_token($c);
    if (!$token_ok) {
        return $c->render(status => 401, text => "Google token expired and refresh failed: $token_why\nPlease log in again.\n");
    }

    my $email = $c->session('email') // 'unknown';
    my $name = $c->session('name') // 'unknown';
    my $groups = $c->session('ldap_groups') || [];
    my $groups_text = (@$groups ? join(', ', @$groups) : '(none)');

    my ($ok, $status, $body, $auth_mode, $auth_hint) = call_weblogic($c, $creds->{weblogic_url});

    if (!$ok) {
        if ($status == 401 || $status == 403) {
            my $hint = $auth_hint ? "\nHint: $auth_hint\n" : "\n";
            return $c->render(status => 401, text => "WebLogic rejected backend auth (HTTP $status). Google session preserved.$hint");
        }
        return $c->render(status => 502, text => "WebLogic request failed (HTTP $status).\n$body\n");
    }

    return $c->render(text =>
        "Welcome $name!\n" .
        "Email: $email\n" .
        "LDAP groups: $groups_text\n" .
        "\nWebLogic backend call succeeded (HTTP $status) using $auth_mode auth.\n" .
        "Endpoint: $creds->{weblogic_url}\n"
    );
}

sub route_ops {
    my $c = shift;

    my $ops = ops_status($c);
    my $status_color = $ops->{mgmt_ok} ? '#0a7f28' : '#7a7a7a';
    my $status_text = $ops->{mgmt_ok} ? 'Reachable' : 'Unavailable';
    my $action_disabled = $ops->{can_rotate} ? '' : 'disabled';
    my $action_hint = $ops->{can_rotate} ? 'Rotate AdminServer log now' : $ops->{rotate_reason};
    my $debug_action_disabled = $ops->{can_set_debug} ? '' : 'disabled';
    my $debug_action_name = $ops->{debug_enabled} ? 'security_debug_off' : 'security_debug_on';
    my $debug_action_label = $ops->{debug_enabled} ? 'Disable Security Debug' : 'Enable Security Debug';
    my $debug_action_hint = $ops->{can_set_debug} ? 'Toggle debugSecurityAtn/debugSecurityAtz' : $ops->{set_debug_reason};

    my $last = $c->session('ops_last_result') || {};
    my $last_line = '';
    if (ref($last) eq 'HASH' && $last->{timestamp}) {
        $last_line = sprintf(
            '<p><strong>Last action:</strong> %s (%s) at %s</p>',
            html_escape($last->{result} // 'unknown'),
            html_escape($last->{message} // ''),
            html_escape($last->{timestamp} // '')
        );
    }

    my $html = sprintf(
        <<'HTML',
<!DOCTYPE html>
<html>
<head>
  <title>Operations Control</title>
  <style>
    body { font-family: monospace; max-width: 900px; margin: 30px auto; line-height: 1.35; }
    .panel { border: 1px solid #ccc; border-radius: 6px; padding: 14px; margin-bottom: 14px; }
    .ok { color: #0a7f28; }
    .bad { color: #a33; }
    .muted { color: #666; }
    .btn { padding: 8px 14px; border: 1px solid #333; background: #f2f2f2; cursor: pointer; }
    .btn:disabled { background: #ddd; color: #888; border-color: #aaa; cursor: not-allowed; }
    .btn-danger { padding: 8px 14px; border: 1px solid #900; background: #c62828; color: #fff; cursor: pointer; }
    .hint { margin-top: 8px; color: #666; }
  </style>
</head>
<body>
  <h1>WebLogic Operations Control</h1>
  <div class="panel">
    <h3>Current State</h3>
    <p><strong>User:</strong> %s</p>
    <p><strong>Role:</strong> %s</p>
    <p><strong>Mgmt API:</strong> <span style="color:%s">%s</span></p>
    <p><strong>Security debug:</strong> %s</p>
        <p><strong>Security debug flags:</strong> %s</p>
    <p><strong>Last log rotation time:</strong> %s</p>
    %s
  </div>

  <div class="panel">
    <h3>Controls</h3>
        <form method="POST" action="/ops/action" style="margin-bottom:10px;">
            <input type="hidden" name="action" value="%s" />
            <button class="btn" %s title="%s">%s</button>
        </form>
        <div class="hint">%s</div>

    <form method="POST" action="/ops/action">
      <input type="hidden" name="action" value="rotate_log" />
      <button class="btn" %s title="%s">Rotate AdminServer Log</button>
    </form>
    <div class="hint">%s</div>

    <form method="POST" action="/ops/action" style="margin-top:10px;">
      <input type="hidden" name="action" value="rotate_log" />
      <input type="hidden" name="force_attempt" value="1" />
      <button class="btn-danger">Override UI Lockout (demo)</button>
    </form>
    <div class="hint">Backend policy still applies. Override only bypasses UI greyout.</div>
  </div>

  <div class="panel muted">
    <a href="/">Back to home</a> | <a href="/debug">Debug JSON</a>
  </div>
</body>
</html>
HTML
        html_escape($ops->{email} // 'unknown'),
        html_escape($ops->{role} // 'unknown'),
        $status_color,
        $status_text,
        html_escape($ops->{debug_state} // 'unknown'),
        html_escape($ops->{debug_flags_text} // 'unknown'),
        html_escape($ops->{last_rotation} // 'unknown'),
        $last_line,
        $debug_action_name,
        $debug_action_disabled,
        html_escape($debug_action_hint),
        html_escape($debug_action_label),
        html_escape($debug_action_hint),
        $action_disabled,
        html_escape($action_hint),
        html_escape($action_hint),
    );

    $c->render(format => 'html', text => $html);
}

sub route_ops_action {
    my $c = shift;

    my $action = $c->param('action') // '';
    my $force_attempt = ($c->param('force_attempt') // '') eq '1' ? 1 : 0;
    my $ops = ops_status($c);

    my $decision = {
        allowed => 0,
        decision_source => 'role-policy',
        reason_code => 'unknown_action',
        message => 'Unknown action',
        trace_id => sprintf('%d-%06d', time, int(rand(1_000_000))),
        timestamp => scalar gmtime() . ' UTC',
    };

    if ($action eq 'rotate_log') {
        if (!$ops->{is_platform_admin}) {
            $decision->{reason_code} = 'not_platform_admin';
            $decision->{message} = 'Requires Platform Admin identity';
        } elsif (!$ops->{mgmt_ok}) {
            $decision->{decision_source} = 'service-availability';
            $decision->{reason_code} = 'mgmt_unavailable';
            $decision->{message} = $ops->{mgmt_reason} || 'WebLogic management API unavailable';
        } else {
            $decision->{allowed} = 1;
            $decision->{decision_source} = 'policy-allow';
            $decision->{reason_code} = 'ok';
            $decision->{message} = 'Action allowed by backend policy';
        }
    } elsif ($action eq 'security_debug_on' || $action eq 'security_debug_off') {
        if (!$ops->{is_platform_admin}) {
            $decision->{reason_code} = 'not_platform_admin';
            $decision->{message} = 'Requires Platform Admin identity';
        } elsif (!$ops->{mgmt_ok}) {
            $decision->{decision_source} = 'service-availability';
            $decision->{reason_code} = 'mgmt_unavailable';
            $decision->{message} = $ops->{mgmt_reason} || 'WebLogic management API unavailable';
        } elsif (($action eq 'security_debug_on' && $ops->{debug_enabled}) || ($action eq 'security_debug_off' && !$ops->{debug_enabled})) {
            $decision->{decision_source} = 'state-conflict';
            $decision->{reason_code} = 'already_in_requested_state';
            $decision->{message} = 'Security debug already in requested state';
        } else {
            $decision->{allowed} = 1;
            $decision->{decision_source} = 'policy-allow';
            $decision->{reason_code} = 'ok';
            $decision->{message} = 'Action allowed by backend policy';
        }
    }

    if ($decision->{allowed}) {
        my ($ok, $code, $msg);
        if ($action eq 'rotate_log') {
            ($ok, $code, $msg) = force_log_rotation($c);
        } elsif ($action eq 'security_debug_on') {
            ($ok, $code, $msg) = set_security_debug(1);
        } elsif ($action eq 'security_debug_off') {
            ($ok, $code, $msg) = set_security_debug(0);
        } else {
            ($ok, $code, $msg) = (0, 400, 'Unknown executable action');
        }
        $decision->{allowed} = $ok ? 1 : 0;
        $decision->{decision_source} = $ok ? 'execution' : 'execution-error';
        $decision->{reason_code} = $ok ? 'executed' : 'execution_failed';
        $decision->{message} = $msg;
        $decision->{http_status} = $code;
    } elsif ($force_attempt) {
        $decision->{message} .= ' (override attempt made)';
    }

    $c->session(ops_last_result => {
        result => ($decision->{reason_code} || 'unknown'),
        message => ($decision->{message} || ''),
        timestamp => ($decision->{timestamp} || ''),
        trace_id => ($decision->{trace_id} || ''),
    });

    $c->render(json => $decision);
}

sub ops_status {
    my ($c) = @_;

    my $email = $c->session('email') // '';
    my $platform_admin_email = $ENV{PLATFORM_ADMIN_EMAIL} || 'johnsrcritchley@gmail.com';
    my $is_platform_admin = ($email ne '' && lc($email) eq lc($platform_admin_email)) ? 1 : 0;
    my $role = $is_platform_admin ? 'platform_admin' : 'viewer';

    my ($mgmt_ok, $mgmt_reason, $last_rotation) = mgmt_runtime_status();
    my ($debug_enabled, $debug_flags_text, $debug_state) = mgmt_security_debug_status();

    my $can_rotate = 1;
    my $rotate_reason = 'Rotate AdminServer log now';
    my $can_set_debug = 1;
    my $set_debug_reason = 'Toggle security debug flags';
    if (!$is_platform_admin) {
        $can_rotate = 0;
        $rotate_reason = 'Requires Platform Admin identity';
        $can_set_debug = 0;
        $set_debug_reason = 'Requires Platform Admin identity';
    } elsif (!$mgmt_ok) {
        $can_rotate = 0;
        $rotate_reason = $mgmt_reason || 'WebLogic management unavailable';
        $can_set_debug = 0;
        $set_debug_reason = $mgmt_reason || 'WebLogic management unavailable';
    }

    return {
        email => $email,
        role => $role,
        is_platform_admin => $is_platform_admin,
        mgmt_ok => $mgmt_ok,
        mgmt_reason => $mgmt_reason,
        debug_enabled => $debug_enabled,
        debug_flags_text => $debug_flags_text,
        debug_state => $debug_state,
        last_rotation => $last_rotation,
        can_rotate => $can_rotate,
        rotate_reason => $rotate_reason,
        can_set_debug => $can_set_debug,
        set_debug_reason => $set_debug_reason,
    };
}

sub mgmt_security_debug_status {
    my $base = mgmt_base_url();
    return (0, 'unknown', 'unknown') unless $base;

    my $ua = Mojo::UserAgent->new;
    my $res = $ua->get("$base/serverConfig/servers/AdminServer/serverDebug" => mgmt_headers())->result;
    return (0, 'unknown', 'unknown') unless $res->is_success;

    my $j = $res->json || {};
    my $atn = $j->{debugSecurityAtn} ? 1 : 0;
    my $atz = $j->{debugSecurityAtz} ? 1 : 0;
    my $enabled = ($atn || $atz) ? 1 : 0;
    my $flags = sprintf('debugSecurityAtn=%s, debugSecurityAtz=%s', $atn ? 'ON' : 'OFF', $atz ? 'ON' : 'OFF');
    my $state = $enabled ? 'ON' : 'OFF';
    return ($enabled, $flags, $state);
}

sub mgmt_runtime_status {
    my $base = mgmt_base_url();
    return (0, 'Missing management base URL', 'unknown') unless $base;

    my $ua = Mojo::UserAgent->new;
    my $res = $ua->get("$base/serverRuntime/serverLogRuntime" => mgmt_headers())->result;
    return (0, 'Management API not reachable with configured credentials', 'unknown') unless $res->is_success;

    my $j = $res->json || {};
    my $opened = $j->{logFileStreamOpened};
    my $last_rotation = defined($opened) ? ($opened ? 'stream open (rotation supported)' : 'stream closed') : 'unknown';
    return (1, '', $last_rotation);
}

sub force_log_rotation {
    my ($c) = @_;
    my $base = mgmt_base_url();
    return (0, 0, 'Missing management base URL') unless $base;

    my $ua = Mojo::UserAgent->new;
    my $res = $ua->post("$base/serverRuntime/serverLogRuntime/forceLogRotation" => mgmt_headers() => json => {})->result;
    return (1, $res->code || 200, 'Log rotation triggered') if $res->is_success;

    my $msg = $res->body || $res->message || 'Unknown error';
    return (0, $res->code || 500, "Log rotation failed: $msg");
}

sub set_security_debug {
    my ($enabled) = @_;

    my $base = mgmt_base_url();
    return (0, 0, 'Missing management base URL') unless $base;

    my $ua = Mojo::UserAgent->new;

    my $start = $ua->post("$base/edit/changeManager/startEdit" => mgmt_headers() => json => {
        waitTimeInMillis => 0,
        timeoutInMillis  => 120000,
        exclusive        => 0,
    })->result;
    return (0, $start->code || 500, 'Failed to start edit session') unless $start->is_success;

    my $set = $ua->post("$base/edit/servers/AdminServer/serverDebug" => mgmt_headers() => json => {
        debugSecurityAtn => $enabled ? 1 : 0,
        debugSecurityAtz => $enabled ? 1 : 0,
    })->result;
    if (!$set->is_success) {
        my $cancel = $ua->post("$base/edit/changeManager/cancelEdit" => mgmt_headers() => json => {})->result;
        my $msg = $set->body || $set->message || 'Failed to set debug flags';
        return (0, $set->code || 500, "Security debug update failed: $msg");
    }

    my $activate = $ua->post("$base/edit/changeManager/activate" => mgmt_headers() => json => {})->result;
    if (!$activate->is_success) {
        my $msg = $activate->body || $activate->message || 'Failed to activate changes';
        return (0, $activate->code || 500, "Security debug activate failed: $msg");
    }

    my $state = $enabled ? 'ON' : 'OFF';
    return (1, $activate->code || 200, "Security debug toggled $state");
}

sub mgmt_base_url {
    my ($base_url) = $creds->{weblogic_url} =~ m{^(https?://[^/]+)};
    return '' unless $base_url;
    return $base_url . '/management/weblogic/latest';
}

sub mgmt_headers {
    my $basic_user = $creds->{wls_basic_user} || 'weblogic';
    my $basic_pass = $creds->{wls_basic_pass} || 'W3blog1c';
    my $auth = 'Basic ' . b64_encode("$basic_user:$basic_pass", '');
    return {
        Authorization => $auth,
        'X-Requested-By' => 'ops-ui',
        Accept        => 'application/json',
        'Content-Type' => 'application/json',
    };
}

sub html_escape {
    my ($s) = @_;
    $s = '' unless defined $s;
    $s =~ s/&/&amp;/g;
    $s =~ s/</&lt;/g;
    $s =~ s/>/&gt;/g;
    $s =~ s/"/&quot;/g;
    return $s;
}

sub update_session_identity {
    my ($c, $payload, $id_token, $refresh_token, $expires_in) = @_;

    my $email = $payload->{email} // 'unknown';
    my $name = $payload->{name} // 'unknown';
    my $token_exp = $payload->{exp};
    $token_exp = time + $expires_in if !defined($token_exp) && defined($expires_in) && $expires_in =~ /^\d+$/;

    $c->session(email => $email, name => $name, id_token => $id_token);
    $c->session(id_token_exp => $token_exp) if defined $token_exp;
    $c->session(refresh_token => $refresh_token) if defined($refresh_token) && $refresh_token ne '';

    my ($groups, $ldap_err) = ldap_groups_for_email($email);
    if ($groups) {
        $c->session(ldap_groups => $groups);
    } else {
        $c->session(ldap_groups => []);
        warn "LDAP group lookup failed for $email: $ldap_err\n" if $ldap_err;
    }
}

sub ensure_fresh_id_token {
    my ($c, $force_refresh) = @_;

    my $id_token = $c->session('id_token');
    return (0, 'missing id_token in session') unless $id_token;

    my $payload = decode_jwt_unverified($id_token);
    return (0, 'unable to decode current id_token payload') unless $payload;

    my $exp = $payload->{exp};
    my $now = time;
    my $refresh_skew = 120;

    if (!$force_refresh && defined($exp) && $exp > ($now + $refresh_skew)) {
        return (1, 'token still valid');
    }

    my $refresh_token = $c->session('refresh_token') // '';
    return (0, 'token expired and no refresh_token in session') if $refresh_token eq '';

    my ($new_id_token, $new_refresh_token, $expires_in, $refresh_err) = refresh_google_tokens($refresh_token);
    return (0, "refresh failed: $refresh_err") unless $new_id_token;

    my $new_payload = verify_jwt($new_id_token)
        or return (0, 'refreshed id_token failed verification');

    update_session_identity($c, $new_payload, $new_id_token, $new_refresh_token, $expires_in);
    return (1, 'token refreshed');
}

sub refresh_google_tokens {
    my ($refresh_token) = @_;

    my $ua = Mojo::UserAgent->new;
    my $res = $ua->post($creds->{token_uri} => form => {
        client_id     => $creds->{client_id},
        client_secret => $creds->{client_secret},
        refresh_token => $refresh_token,
        grant_type    => 'refresh_token',
    })->result;

    unless ($res->is_success) {
        return (undef, undef, undef, $res->body || $res->message || 'token refresh request failed');
    }

    my $json = $res->json || {};
    my $id_token = $json->{id_token};
    my $new_refresh = $json->{refresh_token};
    my $expires_in = $json->{expires_in};

    return (undef, undef, undef, 'refresh response did not include id_token') unless $id_token;

    return ($id_token, $new_refresh, $expires_in, '');
}

sub ldap_groups_for_email {
    my ($email) = @_;

    my ($uid) = split /\@/, ($email // ''), 2;
    return (undef, 'email missing local-part') unless defined($uid) && $uid ne '';

    my $ldap = Net::LDAP->new($creds->{ldap_uri}, timeout => 5);
    return (undef, "connect failed to $creds->{ldap_uri}") unless $ldap;

    my $bind = $ldap->bind($creds->{ldap_bind_dn}, password => $creds->{ldap_bind_pass});
    if ($bind->code) {
        my $err = $bind->error || 'bind failed';
        $ldap->unbind;
        return (undef, $err);
    }

    my $uid_escaped = escape_filter_value($uid);
    my $user_search = $ldap->search(
        base   => $creds->{ldap_user_base},
        scope  => 'sub',
        filter => "(uid=$uid_escaped)",
        attrs  => ['dn'],
    );
    if ($user_search->code) {
        my $err = $user_search->error || 'user search failed';
        $ldap->unbind;
        return (undef, $err);
    }

    my ($user_entry) = $user_search->entries;
    unless ($user_entry) {
        $ldap->unbind;
        return ([], 'user not found in LDAP');
    }

    my $user_dn = $user_entry->dn;
    my $group_filter = $creds->{ldap_group_filter};
    $group_filter =~ s/%USER_DN%/$user_dn/g;

    my $group_search = $ldap->search(
        base   => $creds->{ldap_group_base},
        scope  => 'sub',
        filter => $group_filter,
        attrs  => ['cn'],
    );
    if ($group_search->code) {
        my $err = $group_search->error || 'group search failed';
        $ldap->unbind;
        return (undef, $err);
    }

    my @groups;
    for my $entry ($group_search->entries) {
        push @groups, grep { defined($_) && $_ ne '' } $entry->get_value('cn');
    }
    @groups = sort @groups;

    $ldap->unbind;
    return (\@groups, '');
}

sub call_weblogic {
    my ($c, $url) = @_;

    my $id_token = $c->session('id_token');
    return (0, 401, 'Missing id_token in session') unless $id_token;

    # WebLogic base64-decodes the Bearer: header value before calling assertIdentity.
    # Pre-encode the JWT so the decoded value is the raw JWT string.
    my $bearer_encoded = b64_encode($id_token, '');

    my $ua = Mojo::UserAgent->new;
    my $tx = eval {
        $ua->get($url => {
            Authorization => "Bearer $id_token",
            Bearer        => $bearer_encoded,
            Accept        => 'application/json',
        });
    };

    if (!$tx) {
        my $err = $@ || 'Unknown connection error';
        chomp $err;
        return (0, 502, $err, 'bearer', "Backend lookup/connect failed for $url");
    }

    my $res = $tx->result;

    if ($res->is_success) {
        return (1, $res->code || 200, $res->body || '', 'bearer', '');
    }

    my $www_auth = $res->headers->header('WWW-Authenticate') || '';
    my $basic_user = $creds->{wls_basic_user} || '';
    my $basic_pass = $creds->{wls_basic_pass} || '';

    if (($res->code || 0) == 401 && $basic_user ne '' && $basic_pass ne '') {
        my $basic_header = 'Basic ' . b64_encode("$basic_user:$basic_pass", '');
        my $basic_tx = eval {
            $ua->get($url => {
                Authorization => $basic_header,
                Accept        => 'application/json',
            });
        };

        if (!$basic_tx) {
            my $err = $@ || 'Unknown connection error';
            chomp $err;
            return (0, 502, $err, 'basic-fallback', "Backend lookup/connect failed for $url");
        }

        my $basic_res = $basic_tx->result;

        if ($basic_res->is_success) {
            return (1, $basic_res->code || 200, $basic_res->body || '', 'basic-fallback', '');
        }

        return (0, $basic_res->code || 502, $basic_res->body || $basic_res->message || 'Unknown error', 'basic-fallback', 'Bearer rejected and basic fallback also failed');
    }

    my $hint = '';
    if ($www_auth =~ /Basic/i) {
        $hint = 'WebLogic is advertising Basic auth only. JWT identity assertion may not be configured yet.';
    }

    return (0, $res->code || 502, $res->body || $res->message || 'Unknown error', 'bearer', $hint);
}

# verify_jwt
sub verify_jwt {
    my ($id_token) = @_;

    my $ua = Mojo::UserAgent->new;
    my $res = $ua->get($creds->{auth_provider_x509_cert_url})->result;
    unless ($res->is_success) {
        warn "Failed to fetch Google certs\n";
        return undef;
    }
    my $keys = $res->json;

    my ($header_b64) = split /\./, $id_token;

    $header_b64 =~ s/-/+/g;
    $header_b64 =~ s/_/\//g;
    $header_b64 .= '=' x ((4 - length($header_b64) % 4) % 4);

    my $header = decode_json(b64_decode($header_b64));
    my $kid = $header->{kid};

    my $public_key = $keys->{$kid}
        or do { warn "Key ID $kid not found in Google certs\n"; return undef; };

    my $payload = eval {
        decode_jwt(
            token        => $id_token,
            key          => \$public_key,
            verify_iss   => 'https://accounts.google.com',
            verify_aud   => $creds->{client_id},
            verify_exp   => 1,
            accepted_alg => ['RS256'],
        );
    };

    if ($@) {
        warn "JWT verification error: $@\n";
        return undef;
    }

    return $payload;
}

# decode_jwt_unverified (debug/reference only)
sub decode_jwt_unverified {
    my ($id_token) = @_;

    my (undef, $payload_b64, undef) = split /\./, $id_token;

    return undef unless defined $payload_b64;

    $payload_b64 =~ s/-/+/g;
    $payload_b64 =~ s/_/\//g;
    $payload_b64 .= '=' x ((4 - length($payload_b64) % 4) % 4);

    my $payload = eval { decode_json(b64_decode($payload_b64)) };
    return undef if $@;
    return $payload;
}
