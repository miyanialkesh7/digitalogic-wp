<?php
/**
 * Auth route consolidation and Digits-backed registration guard.
 */

if (!defined('ABSPATH')) {
    exit;
}

final class Digitalogic_Plugin_Auth_Routes {
    private const AUTH_PAGE_ID = 10512;
    private const DEFAULT_COUNTRY_CODE = '98';
    private const CANONICAL_LOGIN_PATH = '/login/';

	/** Public providers that do not require an MX lookup. */
	public const EMAIL_PROVIDERS = array(
		'gmail.com', 'googlemail.com', 'hotmail.com', 'outlook.com', 'live.com', 'msn.com',
		'icloud.com', 'me.com', 'mac.com', 'yahoo.com', 'yahoo.co.uk', 'ymail.com',
		'rocketmail.com', 'aol.com', 'proton.me', 'protonmail.com',
	);

	private const ACCOUNT_HINT_COOKIE = 'digitalogic_account_hint';
	private const ASSIGNED_HINT_COOKIE = 'digitalogic_dismissed_workstation_hint';
	private const ACCOUNT_HINT_LIMIT  = 5;
	private static float $email_attempt_started = 0.0;

    public static function init(): void {
		Digitalogic_Auth_Realtime::init();
        static $booted = false;

        if ($booted || !Digitalogic_Plugin_Admin_Branding::is_enabled()) {
            return;
        }

        $booted = true;

        add_action('template_redirect', [self::class, 'redirect_legacy_login_page'], 1);
        add_action('login_init', [self::class, 'serve_auth_asset_worker'], -1);
        add_action('login_init', [self::class, 'redirect_wp_login_to_canonical'], 0);
        add_action('login_form_login', [self::class, 'render_digits_login'], 1);
        add_action('login_form_register', [self::class, 'render_digits_register'], 1);
		add_action( 'login_form_lostpassword', array( self::class, 'redirect_recovery_entry' ), 1 );
		add_action( 'login_form_retrievepassword', array( self::class, 'redirect_recovery_entry' ), 1 );
		add_action( 'wp_ajax_nopriv_digits_forms_ajax', array( self::class, 'begin_otp_response' ), 1 );
		add_action( 'wp_ajax_digits_forms_ajax', array( self::class, 'begin_otp_response' ), 1 );
		add_action( 'wp_ajax_digitalogic_otp_completion', array( self::class, 'otp_completion' ) );
		add_action( 'wp_ajax_nopriv_digitalogic_otp_completion', array( self::class, 'otp_completion' ) );
		add_action( 'wp_ajax_digitalogic_recovery_nonce', array( self::class, 'recovery_nonce' ) );
		add_action( 'wp_ajax_digitalogic_recovery_password', array( self::class, 'save_recovery_password' ) );
		add_action( 'wp_ajax_nopriv_digitalogic_email_domain', array( self::class, 'check_email_domain' ) );
		add_action( 'wp_ajax_digitalogic_email_domain', array( self::class, 'check_email_domain' ) );
		add_action( 'wp_ajax_nopriv_digitalogic_forget_account_hint', array( self::class, 'forget_account_hint' ) );
		add_action( 'set_logged_in_cookie', array( self::class, 'record_recovery_session' ), 10, 6 );
        add_action('wp_login_failed', [self::class, 'redirect_failed_login'], 99);
        add_filter('register_url', [self::class, 'register_url'], 9999);
        add_filter('lostpassword_url', [self::class, 'lostpassword_url'], 9999, 2);
        add_filter('login_url', [self::class, 'login_url'], 9999, 3);
        add_filter('authenticate', [self::class, 'authenticate_phone_user'], 30, 3);
        add_filter('wordfence_ls_require_captcha', [self::class, 'bypass_wordfence_captcha_for_digits'], 20);
		add_filter( 'send_auth_cookies', array( self::class, 'remember_account' ), PHP_INT_MAX, 4 );
		add_filter( 'authenticate', array( self::class, 'start_branded_email_login' ), 1 );
		add_filter( 'authenticate', array( self::class, 'validate_branded_email_login' ), 99, 2 );
    }

	/**
	 * Start the response timer before WordPress looks up the email or checks the password.
	 *
	 * @param WP_User|WP_Error|null $user Existing authentication result.
	 */
	public static function start_branded_email_login( $user ) {
		if ( '1' === ( $_POST['dg_branded_email'] ?? '' ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- WordPress sign-in POST.
			self::$email_attempt_started = microtime( true );
		}
		return $user;
	}

	/**
	 * Check the email domain at password submission without exposing account existence.
	 *
	 * @param WP_User|WP_Error|null $user     Existing authentication result.
	 * @param string               $identity Submitted identity.
	 * @return WP_User|WP_Error|null
	 */
	public static function validate_branded_email_login( $user, string $identity ) {
		if ( '1' !== ( $_POST['dg_branded_email'] ?? '' ) || ! is_wp_error( $user ) // phpcs:ignore WordPress.Security.NonceVerification.Missing -- WordPress sign-in POST.
			|| ! in_array( $user->get_error_code(), array( 'invalid_username', 'invalid_email', 'incorrect_password', 'authentication_failed' ), true ) ) {
			return $user;
		}

		$started = self::$email_attempt_started > 0.0 ? self::$email_attempt_started : microtime( true );
		$email   = strtolower( $identity );
		$valid   = filter_var( $email, FILTER_VALIDATE_EMAIL ) && self::email_domain_accepts_mail( substr( strrchr( $email, '@' ), 1 ) );
		$known   = is_email( $email ) && get_user_by( 'email', $email ) instanceof WP_User;
		$delay   = 700000 - (int) ( ( microtime( true ) - $started ) * 1000000 );
		if ( $delay > 0 ) {
			usleep( $delay );
		}
		return $valid || $known ? $user : new WP_Error( 'authentication_failed', self::failed_login_message() );
	}

	/** Validate a domain without accepting an address or checking for an account. */
	public static function check_email_domain(): void {
		check_ajax_referer( 'digitalogic_email_domain', 'nonce' );
		$domain = isset( $_POST['domain'] ) && is_string( $_POST['domain'] ) ? strtolower( trim( wp_unslash( $_POST['domain'] ) ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Validate the complete domain before using it.
		if ( ! self::is_email_domain_name( $domain ) ) {
			wp_send_json_success( array( 'valid' => false ) );
		}

		$address = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		$key     = 'dg_email_checks_' . hash( 'sha256', $address . ':' . (string) floor( time() / MINUTE_IN_SECONDS ) );
		$count   = (int) get_transient( $key );
		if ( $count >= 45 ) {
			wp_send_json_error( null, 429 );
		}
		set_transient( $key, $count + 1, MINUTE_IN_SECONDS );
		wp_send_json_success( array( 'valid' => self::email_domain_accepts_mail( $domain ) ) );
	}

	/** Require a bounded DNS name with at least two labels. */
	private static function is_email_domain_name( string $domain ): bool {
		return strlen( $domain ) <= 253
			&& (bool) preg_match( '/\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\z/', $domain );
	}

	/**
	 * Accept common providers and require a real MX target for other domains.
	 *
	 * @param string $domain    Lowercase email domain.
	 * @param bool   $allow_dns Whether to perform uncached DNS lookups on this request.
	 */
	public static function email_domain_accepts_mail( string $domain, bool $allow_dns = true ): ?bool {
		if ( in_array( $domain, self::EMAIL_PROVIDERS, true ) ) {
			return true;
		}
		if ( ! function_exists( 'getmxrr' ) || ! self::is_email_domain_name( $domain ) ) {
			return false;
		}
		$cache_key = hash( 'sha256', $domain );
		$cached    = wp_cache_get( $cache_key, 'digitalogic_email_mx' );
		if ( is_int( $cached ) ) {
			return 1 === $cached;
		}
		if ( ! $allow_dns ) {
			return null;
		}
		$hosts = array();
		$valid = getmxrr( $domain . '.', $hosts ) && (bool) array_filter(
			$hosts,
			static function ( string $host ): bool {
				return '' !== rtrim( $host, '.' );
			}
		);
		wp_cache_set( $cache_key, (int) $valid, 'digitalogic_email_mx', $valid ? HOUR_IN_SECONDS : 5 * MINUTE_IN_SECONDS );
		return $valid;
	}

	/** Carry legacy recovery links into the normal sign-in flow. */
	public static function redirect_recovery_entry(): void {
		if ( 'GET' !== ( $_SERVER['REQUEST_METHOD'] ?? '' ) || ! function_exists( 'df_digits_form_login' ) ) {
			return;
		}
		$redirect = isset( $_GET['redirect_to'] ) ? esc_url_raw( wp_unslash( $_GET['redirect_to'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only navigation.
		$locale   = isset( $_GET['wp_lang'] ) ? sanitize_text_field( wp_unslash( $_GET['wp_lang'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only navigation.
		$url      = self::lostpassword_url( '', $redirect );
		wp_safe_redirect( $locale ? add_query_arg( 'wp_lang', $locale, $url ) : $url );
		exit;
	}

	/**
	 * Mark the new WordPress session after Digits accepts a recovery SMS.
	 *
	 * @param string $cookie     Generated cookie.
	 * @param int    $expire     Browser expiration.
	 * @param int    $expiration Session expiration.
	 * @param int    $user_id    Authenticated account.
	 * @param string $scheme     Cookie scheme.
	 * @param string $token      New session token.
	 */
	public static function record_recovery_session( string $cookie, int $expire, int $expiration, int $user_id, string $scheme, string $token ): void {
		// Digits owns OTP validation. This hook runs when it issues the authenticated session.
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Digits validates the authentication request.
		if ( ! wp_doing_ajax() || 'digits_forms_ajax' !== ( $_POST['action'] ?? '' )
			|| '1' !== ( $_POST['dg_recovery'] ?? '' )
			|| ! self::has_submitted_recovery_code()
			|| ! empty( $_POST['password'] ) || ! empty( $_POST['pwd'] ) ) {
			return;
		}
		// phpcs:enable WordPress.Security.NonceVerification.Missing
		set_transient( self::recovery_session_key( $token ), $user_id, 10 * MINUTE_IN_SECONDS );
	}

	/** Recognize either native Digits OTP field. Digits validates the code before issuing the cookie. */
	private static function has_submitted_recovery_code(): bool {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Digits validates the authentication request.
		foreach ( array( 'sms_otp', 'email_otp' ) as $field ) {
			if ( is_string( $_POST[ $field ] ?? null ) && preg_match( '/\A[0-9]{4,8}\z/', sanitize_text_field( wp_unslash( $_POST[ $field ] ) ) ) ) {
				return true;
			}
		}
		// phpcs:enable WordPress.Security.NonceVerification.Missing
		return false;
	}

	/**
	 * Observe only branded Digits verification. Digits owns the OTP and issues the login cookie.
	 */
	public static function begin_otp_response(): void {
		$attempt = self::otp_attempt_id();
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Digits validates the challenge and OTP.
		if ( '' === $attempt || ! self::has_submitted_recovery_code() || isset( $_POST['sub_action'] ) || isset( $_POST['check_status'] ) ) {
			return;
		}
		$issued = null;
		$signed_in_user = 0;
		add_action(
			'wp_login',
			static function ( $_login, $user ) use ( &$signed_in_user ): void {
				$signed_in_user = $user instanceof WP_User ? (int) $user->ID : 0;
			},
			PHP_INT_MAX,
			2
		);
		add_action(
			'set_logged_in_cookie',
			static function ( string $cookie, int $expire, int $expiration, int $user, string $scheme, string $token ) use ( &$issued ): void {
				$issued = array(
					'user'  => $user,
					'token' => $token,
				);
			},
			10,
			6
		);
		// WordPress can inherit an earlier response status when wp_send_json_success()
		// is called without one. Inspect the finished, authenticated Digits result.
		ob_start(
			static function ( string $body ) use ( &$issued, &$signed_in_user, $attempt ): string {
				if ( ! $issued || $issued['user'] !== $signed_in_user || headers_sent() ) {
					return $body;
				}
				$cookie_written = false;
				foreach ( headers_list() as $header ) {
					if ( 0 === stripos( $header, 'Location:' ) ) {
						return $body;
					}
					$cookie_written = $cookie_written || 0 === stripos( $header, 'Set-Cookie: ' . LOGGED_IN_COOKIE . '=' );
				}
				$reply = json_decode( $body, true );
				$data  = $reply['data'] ?? null;
				if ( ! $cookie_written || true !== ( $reply['success'] ?? null ) || ! is_array( $data )
					|| ( empty( $data['process'] ) && empty( $data['redirect'] ) && empty( $data['reload'] ) ) ) {
					return $body;
				}
				$requested   = $data['redirect'] ?? '';
				$destination = Digitalogic_Call_Verification::login_destination( in_array( $requested, array( -1, -2, '-1', '-2' ), true ) ? '' : $requested );
				set_transient(
					self::otp_completion_key( $attempt, $issued['token'] ),
					array(
						'user'     => $issued['user'],
						'redirect' => $destination,
					),
					10 * MINUTE_IN_SECONDS
				);
				if ( in_array( http_response_code(), array( 401, 403 ), true ) ) {
					status_header( 200 );
				}
				return $body;
			}
		);
	}

	/** Return the completion only to the browser that already holds the verified WordPress session. */
	public static function otp_completion(): void {
		nocache_headers();
		wp_send_json_success( self::read_otp_completion( self::otp_attempt_id(), wp_get_session_token(), get_current_user_id() ) );
	}

	/**
	 * Return only a completion bound to the caller's validated session token.
	 *
	 * @param string $attempt Browser attempt ID.
	 * @param string $token   Validated WordPress session token.
	 * @param int    $user    Authenticated WordPress user ID.
	 */
	public static function read_otp_completion( string $attempt, string $token, int $user ): array {
		if ( '' !== $attempt && '' !== $token && $user > 0 ) {
			$completion = get_transient( self::otp_completion_key( $attempt, $token ) );
			if ( is_array( $completion ) && $user === (int) $completion['user'] ) {
				return array( 'redirect' => $completion['redirect'] );
			}
		}
		return array( 'pending' => true );
	}

	/** Read the per-tab correlation ID. It cannot authenticate a request. */
	private static function otp_attempt_id(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- This only identifies a result within an authenticated session.
		$value = $_POST['dg_otp_attempt'] ?? '';
		return is_string( $value ) && wp_is_uuid( $value, 4 ) ? $value : '';
	}

	/**
	 * Bind the completion to the attempt and the existing WordPress session token.
	 *
	 * @param string $attempt Browser attempt ID.
	 * @param string $token   WordPress session token.
	 */
	private static function otp_completion_key( string $attempt, string $token ): string {
		return 'dg_otp_done_' . hash_hmac( 'sha256', $attempt, $token );
	}

	/**
	 * Bind recovery to one WordPress session.
	 *
	 * @param string $token WordPress session token.
	 */
	private static function recovery_session_key( string $token ): string {
		return 'dg_recovery_' . hash( 'sha256', $token );
	}

	/** Issue a nonce only to the session established by the verified SMS. */
	public static function recovery_nonce(): void {
		$user_id = get_current_user_id();
		if ( ! $user_id || $user_id !== (int) get_transient( self::recovery_session_key( wp_get_session_token() ) ) ) {
			wp_send_json_error( null, 403 );
		}
		wp_send_json_success( array( 'nonce' => wp_create_nonce( 'digitalogic_recovery_password' ) ) );
	}

	/** Change the authenticated account's password and preserve its current session. */
	public static function save_recovery_password(): void {
		check_ajax_referer( 'digitalogic_recovery_password', 'nonce' );
		$user_id = get_current_user_id();
		$key     = self::recovery_session_key( wp_get_session_token() );
		if ( ! $user_id || $user_id !== (int) get_transient( $key ) ) {
			wp_send_json_error( null, 403 );
		}
		// Do not sanitize or trim a password supplied by the user.
		$password = isset( $_POST['password'] ) && is_string( $_POST['password'] ) ? wp_unslash( $_POST['password'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		if ( strlen( $password ) < 12 || strlen( $password ) > 4096 || trim( $password ) !== $password || str_contains( $password, "\0" ) ) {
			wp_send_json_error( null, 400 );
		}
		if ( ! delete_transient( $key ) ) {
			wp_send_json_error( null, 409 );
		}
		$result = wp_update_user(
			array(
				'ID'        => $user_id,
				'user_pass' => $password,
			)
		);
		if ( is_wp_error( $result ) ) {
			set_transient( $key, $user_id, MINUTE_IN_SECONDS );
			wp_send_json_error( null, 500 );
		}
		WP_Session_Tokens::get_instance( $user_id )->destroy_others( wp_get_session_token() );
		wp_send_json_success();
	}

	/**
	 * Remember an identity only when the browser opts into a persistent login.
	 *
	 * @param bool $send       Whether WordPress will send authentication cookies.
	 * @param int  $expire     Browser cookie expiration.
	 * @param int  $expiration WordPress authentication expiration.
	 * @param int  $user_id    Authenticated user ID.
	 */
	public static function remember_account( bool $send, int $expire, int $expiration, int $user_id ): bool {
		if ( ! $send || $user_id < 1 || $expire <= time() || headers_sent() || ! is_ssl() ) {
			return $send;
		}
		[ $accounts ] = self::read_account_hint_cookie();
		$accounts     = array_values( array_diff( $accounts, array( $user_id ) ) );
		array_unshift( $accounts, $user_id );
		self::write_account_hint_cookie( $accounts, time() + 30 * DAY_IN_SECONDS );
		return $send;
	}

	/**
	 * Store the signed browser list, or expire it when its last entry is removed.
	 *
	 * @param array $accounts Remembered user IDs.
	 * @param int   $expires  Expiry timestamp.
	 */
	private static function write_account_hint_cookie( array $accounts, int $expires ): bool {
		$value = implode( '-', array_slice( $accounts, 0, self::ACCOUNT_HINT_LIMIT ) ) . '.' . $expires;
		return self::set_hint_cookie(
			self::ACCOUNT_HINT_COOKIE,
			$accounts ? $value . '.' . hash_hmac( 'sha256', $value, wp_salt( 'logged_in' ) ) : '',
			$accounts ? $expires : time() - DAY_IN_SECONDS
		);
	}

	/**
	 * Set a browser-only account hint.
	 *
	 * @param string $name    Hint cookie name.
	 * @param string $value   Signed hint value.
	 * @param int    $expires Expiry timestamp.
	 */
	private static function set_hint_cookie( string $name, string $value, int $expires ): bool {
		return setcookie(
			$name,
			$value,
			array(
				'expires'  => $expires,
				'path'     => '/',
				'secure'   => true,
				'httponly' => true,
				'samesite' => 'Strict',
			)
		);
	}

	/** Return the workstation's preselected identity for a signed-out visitor. */
	public static function remembered_account(): array {
		if ( 'login' !== ( $GLOBALS['action'] ?? '' ) || is_user_logged_in() ) {
			return array();
		}
		$assigned  = self::lan_assigned_user();
		$dismissed = isset( $_COOKIE[ self::ASSIGNED_HINT_COOKIE ] ) ? sanitize_text_field( wp_unslash( $_COOKIE[ self::ASSIGNED_HINT_COOKIE ] ) ) : '';
		if ( $assigned && hash_equals( self::assigned_hint_digest( $assigned ), $dismissed ) ) {
			return array();
		}
		return $assigned ? self::account_hint( $assigned, true ) : array();
	}

	/**
	 * Bind a dismissal to the assigned account, so a new assignment can still appear.
	 *
	 * @param WP_User $user Workstation account.
	 */
	private static function assigned_hint_digest( WP_User $user ): string {
		return hash_hmac( 'sha256', 'workstation-hint:' . $user->ID, wp_salt( 'logged_in' ) );
	}

	/** Remove a suggestion from this browser using only its verified hints. */
	public static function forget_account_hint(): void {
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		if ( 'post' !== $method || ! is_ssl() || headers_sent()
			|| ! check_ajax_referer( 'digitalogic_forget_account_hint', 'nonce', false ) ) {
			wp_send_json_error( null, 403 );
		}
		$login = isset( $_POST['login'] ) && is_string( $_POST['login'] ) ? sanitize_text_field( wp_unslash( $_POST['login'] ) ) : '';
		if ( '' === $login ) {
			wp_send_json_error( null, 400 );
		}
		[ $accounts, $expires ] = self::read_account_hint_cookie();
		$remaining              = array_values(
			array_filter(
				$accounts,
				static function ( int $id ) use ( $login ): bool {
					$user = get_user_by( 'id', $id );
					return ! ( $user instanceof WP_User ) || $login !== $user->user_login;
				}
			)
		);
		if ( $remaining !== $accounts && ! self::write_account_hint_cookie( $remaining, $expires ) ) {
			wp_send_json_error( null, 500 );
		}
		$assigned = self::lan_assigned_user();
		if ( $assigned && $login === $assigned->user_login
			&& ! self::set_hint_cookie( self::ASSIGNED_HINT_COOKIE, self::assigned_hint_digest( $assigned ), time() + 30 * DAY_IN_SECONDS ) ) {
			wp_send_json_error( null, 500 );
		}
		wp_send_json_success();
	}

	/** Match a workstation using the client address resolved by the web server. */
	public static function lan_assigned_user(): ?WP_User {
		$address = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		if ( str_starts_with( $address, '172.16.' ) && filter_var( $address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			// Only trust REMOTE_ADDR after the web server's trusted proxy handling.
			$assignments = defined( 'DIGITALOGIC_LAN_LOGIN_ACCOUNTS' ) && is_array( DIGITALOGIC_LAN_LOGIN_ACCOUNTS ) ? DIGITALOGIC_LAN_LOGIN_ACCOUNTS : array();
			$login       = $assignments[ $address ] ?? '';
			if ( is_string( $login ) && '' !== $login ) {
				$assigned = get_user_by( 'login', $login );
				if ( $assigned instanceof WP_User ) {
					return $assigned;
				}
			}
		}
		return null;
	}

	/** Read the signed browser list, including old single-account cookies. */
	private static function read_account_hint_cookie(): array {
		$hint = isset( $_COOKIE[ self::ACCOUNT_HINT_COOKIE ] ) ? sanitize_text_field( wp_unslash( $_COOKIE[ self::ACCOUNT_HINT_COOKIE ] ) ) : '';
		if ( ! preg_match( '/\A([1-9][0-9]{0,11}(?:-[1-9][0-9]{0,11}){0,4})\.([0-9]{1,12})\.([a-f0-9]{64})\z/', $hint, $matches )
			|| (int) $matches[2] <= time()
			|| ! hash_equals( hash_hmac( 'sha256', $matches[1] . '.' . $matches[2], wp_salt( 'logged_in' ) ), $matches[3] ) ) {
			return array( array(), 0 );
		}
		return array( array_map( 'intval', explode( '-', $matches[1] ) ), (int) $matches[2] );
	}

	/** Return signed-out account suggestions for this browser. */
	public static function remembered_accounts(): array {
		if ( 'login' !== ( $GLOBALS['action'] ?? '' ) || is_user_logged_in() ) {
			return array();
		}
		$accounts = array();
		[ $ids ]  = self::read_account_hint_cookie();
		foreach ( $ids as $id ) {
			$user = get_user_by( 'id', $id );
			if ( $user instanceof WP_User ) {
				$accounts[] = self::account_hint( $user, false );
			}
		}
		return $accounts;
	}

	/**
	 * Serialize only the account chosen for this browser or assigned workstation.
	 *
	 * @param WP_User $user     Account to show.
	 * @param bool    $assigned Whether to preselect the account.
	 */
	private static function account_hint( WP_User $user, bool $assigned ): array {
		$hint = array(
			'login'    => $user->user_login,
			'name'     => $user->display_name,
			'avatar'   => '',
			'assigned' => $assigned,
		);
		if ( $assigned ) {
			$hint['avatar']      = self::workstation_avatar( $user );
			$hint['emailDigest'] = hash( 'sha256', strtolower( $user->user_email ) );
		}
		return $hint;
	}

	/**
	 * Allow an actual site or Gravatar photo for an assigned workstation.
	 *
	 * @param WP_User $user Account assigned to this workstation.
	 */
	private static function workstation_avatar( WP_User $user ): string {
		$avatar = get_avatar_url(
			$user->ID,
			array(
				'size'          => 160,
				'default'       => '404',
				'force_default' => false,
			)
		);
		if ( ! is_string( $avatar ) ) {
			return '';
		}
		$url  = wp_parse_url( $avatar );
		$host = strtolower( $url['host'] ?? '' );
		if ( 'https' !== ( $url['scheme'] ?? '' ) || '' === $host ) {
			return '';
		}
		$local    = strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) ) === $host;
		$gravatar = ( 'gravatar.com' === $host || str_ends_with( $host, '.gravatar.com' ) ) && str_starts_with( $url['path'] ?? '', '/avatar/' );
		return $local || $gravatar ? esc_url_raw( $avatar ) : '';
	}

    public static function redirect_legacy_login_page(): void {
        if (!self::is_legacy_login_page()) {
            return;
        }

        if (self::is_canonical_login_request()) {
            return;
        }

        $redirect_to = isset($_GET['redirect_to']) ? esc_url_raw(wp_unslash($_GET['redirect_to'])) : '';
        wp_safe_redirect(self::login_url(wp_login_url($redirect_to), $redirect_to, false), 301);
        exit;
    }

    public static function redirect_wp_login_to_canonical(): void {
        if (!isset($_SERVER['REQUEST_URI']) || !isset($_SERVER['REQUEST_METHOD'])) {
            return;
        }

        $method = strtoupper((string) $_SERVER['REQUEST_METHOD']);
        if ($method !== 'GET' && $method !== 'HEAD') {
            return;
        }

        $path = (string) wp_parse_url((string) wp_unslash($_SERVER['REQUEST_URI']), PHP_URL_PATH);
        if (basename($path) !== 'wp-login.php') {
            return;
        }

        $action = isset($_GET['action']) ? sanitize_key(wp_unslash($_GET['action'])) : 'login';
        $allowed_actions = ['login', 'register', 'lostpassword', 'rp', 'resetpass'];

        if (!in_array($action, $allowed_actions, true)) {
            return;
        }

        $args = [];
        foreach ( array( 'action', 'redirect_to', 'reauth', 'wp_lang', 'login', 'loggedout', 'interim-login', 'recover' ) as $key ) {
            if (isset($_GET[$key]) && $_GET[$key] !== '') {
                $args[$key] = sanitize_text_field(wp_unslash($_GET[$key]));
            }
        }

        if (($args['action'] ?? '') === 'login') {
            unset($args['action']);
        }

        wp_safe_redirect(add_query_arg($args, self::canonical_login_url()), 302);
        exit;
    }

	/** Serve the public worker from the login path so it only controls the login page. */
	public static function serve_auth_asset_worker(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only route marker with a fixed value.
		if ( ! self::is_canonical_login_request() || 'GET' !== ( $_SERVER['REQUEST_METHOD'] ?? '' ) || 'worker' !== ( $_GET['dg_auth_assets'] ?? '' ) ) {
			return;
		}

		$file = DIGITALOGIC_PLUGIN_DIR . 'assets/js/branding/auth-assets-worker.js';
		if ( ! is_readable( $file ) ) {
			status_header( 404 );
			exit;
		}

		header( 'Content-Type: application/javascript; charset=UTF-8' );
		header( 'X-Content-Type-Options: nosniff' );
		header( 'Cache-Control: no-cache' );
		readfile( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_readfile -- Stream this local script directly.
		exit;
	}

    public static function render_digits_login(): void {
        if (isset($_SERVER['REQUEST_METHOD']) && strtoupper((string) $_SERVER['REQUEST_METHOD']) !== 'GET') {
            return;
        }

        if (!function_exists('df_digits_form_login')) {
            return;
        }

		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only sign-in entry and notice.
		$redirect_to = isset( $_REQUEST['redirect_to'] ) && is_string( $_REQUEST['redirect_to'] )
			? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) )
			: '';

		nocache_headers();
		$federated_resume    = class_exists( Digitalogic_Federated_Login::class ) && Digitalogic_Federated_Login::resume_after_redirect();
		$session_destination = $federated_resume ? '' : self::existing_session_destination( $redirect_to, $_GET );
		if ( '' !== $session_destination && wp_safe_redirect( $session_destination ) ) {
			exit;
		}

		$logged_out = 'true' === sanitize_key( wp_unslash( $_GET['loggedout'] ?? '' ) ) && ! is_user_logged_in();
		// phpcs:enable WordPress.Security.NonceVerification.Recommended
		Digitalogic_Auth_Realtime::bind_browser();
		login_header( __( 'Log In' ) ); // phpcs:ignore WordPress.WP.I18n.MissingArgDomain -- Intentionally reuses the WordPress core translation.

        if (isset($_GET['login']) && sanitize_key(wp_unslash($_GET['login'])) === 'failed') {
            echo '<div id="login_error" class="notice notice-error"><p>';
            echo esc_html(self::failed_login_message());
            echo '</p></div>';
        }

		echo '<div class="dg-digits-login-shell dg-digits-auto-identity">';
        echo '<div class="dg-auth-preloader" aria-hidden="true"><span></span></div>';
        echo self::digits_login_form_html($redirect_to); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		do_action( 'digitalogic_branded_login_content' );
        echo '</div>';

        self::render_login_footer( $logged_out );
        exit;
    }

	/**
	 * Resume a verified WordPress session on an ordinary sign-in GET.
	 *
	 * @param string $redirect_to Requested return URL.
	 * @param array  $query       Query parameters used to recognize explicit sign-in flows.
	 * @return string Validated destination, or an empty string to show sign-in.
	 */
	private static function existing_session_destination( string $redirect_to, array $query ): string {
		if ( ! is_user_logged_in() ) {
			return '';
		}
		foreach ( array( 'reauth', 'interim-login', 'recover', 'loggedout' ) as $explicit_flow ) {
			if ( isset( $query[ $explicit_flow ] ) ) {
				return '';
			}
		}

		$fallback    = current_user_can( 'edit_posts' ) ? admin_url() : home_url( '/' );
		$destination = '' === $redirect_to ? $fallback : wp_validate_redirect( $redirect_to, $fallback );
		$path        = untrailingslashit( (string) wp_parse_url( $destination, PHP_URL_PATH ) );

		return untrailingslashit( self::CANONICAL_LOGIN_PATH ) === $path || 'wp-login.php' === basename( $path )
			? $fallback
			: $destination;
	}

    public static function redirect_failed_login(string $username): void {
        if (wp_doing_ajax()) {
            return;
        }

        $redirect_to = isset($_REQUEST['redirect_to']) ? esc_url_raw(wp_unslash($_REQUEST['redirect_to'])) : '';
        $args = ['login' => 'failed'];

        if ($redirect_to !== '') {
            $args['redirect_to'] = $redirect_to;
        }

        if (isset($_REQUEST['wp_lang']) && $_REQUEST['wp_lang'] !== '') {
            $args['wp_lang'] = sanitize_text_field(wp_unslash($_REQUEST['wp_lang']));
        }

        wp_safe_redirect(add_query_arg($args, self::canonical_login_url()), 302);
        exit;
    }

    private static function digits_login_form_html(string $redirect_to): string {
        if (function_exists('digits_render_new_form')) {
            $details = [
                'page_type' => 'login',
                'login_title' => __('Log In'), // phpcs:ignore WordPress.WP.I18n.MissingArgDomain -- Intentionally reuses the WordPress core translation.
                'login_details' => [
                    'dig_login_email' => 1,
                    'dig_login_mobilenumber' => 1,
                    'dig_login_username' => 1,
                    'dig_login_captcha' => '0',
                ],
            ];

            if ($redirect_to !== '') {
                $details['login_redirect'] = $redirect_to;
            }

            try {
                ob_start();
                digits_render_new_form($details);
                $html = trim((string) ob_get_clean());

                if ($html !== '') {
                    return self::add_login_http_fallback($html); // phpcs:ignore
                }
            } catch (Throwable $error) {
                if (ob_get_level() > 0) {
                    ob_end_clean();
                }
            }
        }

        return self::add_login_http_fallback((string) df_digits_form_login()); // phpcs:ignore
    }

// phpcs:disable -- Keep the focused Digits HTML transformation neutral to the legacy-file baseline.
    private static function digits_register_form_html(): string {
        return self::add_login_http_fallback((string) df_digits_form_signup());
    }

    private static function add_login_http_fallback(string $html): string {
        if (
            $html === ''
            || strpos($html, 'digits-form_toggle_login_register') === false
            || strpos($html, 'show_login') === false
        ) {
            return $html;
        }

        $login_url = esc_attr(esc_url(self::canonical_login_url()));
        $rewritten = preg_replace_callback(
            '/<a\b(?=[^>]*\bdigits-form_toggle_login_register\b)(?=[^>]*\bshow_login\b)[^>]*>/i',
            static function(array $matches) use ($login_url): string {
                $tag = $matches[0];
                $href_pattern = '/\shref\s*=\s*(["\'])(.*?)\1/i';

                if (!preg_match($href_pattern, $tag, $href)) {
                    return substr($tag, 0, -1) . ' href="' . $login_url . '">';
                }

                $current = trim(html_entity_decode($href[2], ENT_QUOTES | ENT_HTML5, 'UTF-8'));
                if ($current !== '' && $current !== '#' && stripos($current, 'javascript:') !== 0) {
                    return $tag;
                }

                $replacement = preg_replace(
                    $href_pattern,
                    ' href="' . $login_url . '"',
                    $tag,
                    1
                );

                return is_string($replacement) ? $replacement : $tag;
            },
            $html
        );

        return is_string($rewritten) ? $rewritten : $html;
    }
// phpcs:enable

    public static function render_digits_register(): void {
		self::render_digits_login();
    }

	/** Keep the core language selector optional and local to this footer render. */
	private static function render_login_footer( bool $logged_out = false ): void {
		$show_language = (bool) apply_filters( 'digitalogic_login_show_language_switcher', true );
		$hook          = $show_language ? 'login_language_dropdown_args' : 'login_display_language_dropdown';
		$callback      = $show_language ? self::installed_login_languages( ... ) : '__return_false';
		add_filter( $hook, $callback, PHP_INT_MAX );
		add_filter( 'login_site_html_link', array( self::class, 'auth_footer_link' ) );

		if ( $logged_out ) {
			add_action(
				'login_footer',
				static function (): void {
					echo '<div class="dg-toast-stack"><div class="dg-toast dg-toast--success" data-dg-toast-on-load>';
					echo '<p class="dg-toast__message" role="status">' . esc_html__( 'You are now logged out.' ) . '</p>'; // phpcs:ignore WordPress.WP.I18n.MissingArgDomain -- Intentionally reuses the WordPress core translation.
					echo '</div></div>';
				}
			);
		}

		try {
			login_footer( 'user_login' );
		} finally {
			remove_filter( $hook, $callback, PHP_INT_MAX );
			remove_filter( 'login_site_html_link', array( self::class, 'auth_footer_link' ) );
		}
	}

	/**
	 * Supply translation metadata without triggering a WordPress.org request.
	 *
	 * @param array $args Core language dropdown arguments.
	 */
	private static function installed_login_languages( array $args ): array {
		$cached = get_site_transient( 'available_translations' );
		// Core fetches remote metadata if this array is empty, even when only installed languages are shown.
		$args['translations']                = ( is_array( $cached ) ? $cached : array() ) + array(
			'fa_IR' => array(
				'language'    => 'fa_IR',
				'native_name' => 'فارسی',
				'iso'         => array( 'fa' ),
			),
		);
		$args['languages']                   = get_available_languages();
		$args['show_available_translations'] = false;
		return $args;
	}

	/** Render the exit link in the WordPress footer, including without JavaScript. */
	public static function auth_footer_link(): string {
		$persian     = str_starts_with( strtolower( determine_locale() ), 'fa' );
		$home        = home_url( '/' );
		$requested   = isset( $_GET['redirect_to'] ) && is_string( $_GET['redirect_to'] ) ? esc_url_raw( wp_unslash( $_GET['redirect_to'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only navigation.
		$destination = self::auth_exit_destination( $requested );
		$label       = $persian ? 'صفحه اصلی' : 'Home';
		$icon        = 'home';
		if ( '' !== $destination ) {
			$icon  = 'back';
			$label = $persian ? 'بازگشت به صفحهٔ قبلی' : 'Back to previous page';
			if ( 'git.digitalogic.ir' === wp_parse_url( $destination, PHP_URL_HOST ) ) {
				$label = $persian ? 'بازگشت به گیت' : 'Back to Git';
			}
		}
		return sprintf(
			'<a class="dg-auth-home" data-dg-exit-icon="%s" href="%s">%s</a>',
			esc_attr( $icon ),
			esc_url( $destination ?: $home ),
			esc_html( $label )
		);
	}

	/** Allow a same-site return or the first-party Git site, without restarting sign-in. */
	private static function auth_exit_destination( string $requested ): string {
		if ( '' === $requested || str_contains( $requested, '\\' ) ) {
			return '';
		}
		$target = wp_parse_url( $requested );
		$home   = wp_parse_url( home_url( '/' ) );
		if ( ! is_array( $target ) || isset( $target['user'] ) || isset( $target['pass'] ) ) {
			return '';
		}
		$path = rawurldecode( (string) ( $target['path'] ?? '/' ) );
		if ( 'git.digitalogic.ir' === ( $target['host'] ?? '' ) && 'https' === ( $target['scheme'] ?? '' ) && ! isset( $target['port'] ) ) {
			return $requested;
		}
		if ( isset( $target['host'] ) ) {
			if ( $target['host'] !== $home['host'] || ( $target['scheme'] ?? '' ) !== $home['scheme'] || ( $target['port'] ?? null ) !== ( $home['port'] ?? null ) ) {
				return '';
			}
		} elseif ( isset( $target['scheme'] ) || ! str_starts_with( $requested, '/' ) || str_starts_with( $requested, '//' ) ) {
			return '';
		}
		if ( '/wp-login.php' === rtrim( $path, '/' ) ) {
			parse_str( $target['query'] ?? '', $query );
			$callback = isset( $query['redirect_uri'] ) && is_string( $query['redirect_uri'] ) ? wp_parse_url( $query['redirect_uri'] ) : array();
			if ( 'openid-authenticate' === ( $query['action'] ?? '' ) && 'git.digitalogic.ir' === ( $callback['host'] ?? '' ) && 'https' === ( $callback['scheme'] ?? '' )
				&& ! isset( $callback['user'] ) && ! isset( $callback['pass'] ) && ! isset( $callback['port'] ) ) {
				return 'https://git.digitalogic.ir/';
			}
			return '';
		}
		if ( '/login' === rtrim( $path, '/' ) ) {
			return '';
		}
		return wp_validate_redirect( $requested, '' );
	}

    public static function register_url(string $url): string {
        return add_query_arg('action', 'register', self::canonical_login_url());
    }

    public static function lostpassword_url(string $url, string $redirect = ''): string {
		$args = array( 'recover' => '1' );

        if ($redirect !== '') {
            $args['redirect_to'] = $redirect;
        }

        return add_query_arg($args, self::canonical_login_url());
    }

    public static function login_url(string $login_url, string $redirect = '', bool $force_reauth = false): string {
        $args = [];

        if ($redirect !== '') {
            $args['redirect_to'] = $redirect;
        }

        if ($force_reauth) {
            $args['reauth'] = '1';
        }

        return add_query_arg($args, self::canonical_login_url());
    }

    public static function authenticate_phone_user($user, $username, $password) {
        if ($user instanceof WP_User) {
            return $user;
        }

        $username = is_string($username) ? trim($username) : '';
        $password = is_string($password) ? $password : '';

        if ($username === '' || $password === '') {
            return $user;
        }

        $phone = self::normalize_phone($username, self::DEFAULT_COUNTRY_CODE);
        if (!preg_match('/^9\d{9}$/', $phone)) {
            return $user;
        }

        $phone_user = self::find_user_by_phone($phone, self::DEFAULT_COUNTRY_CODE);
        if (!$phone_user instanceof WP_User) {
            return $user;
        }

        if (!wp_check_password($password, $phone_user->user_pass, $phone_user->ID)) {
            return new WP_Error(
                'incorrect_password',
                __('<strong>Error:</strong> The password you entered for the phone number is incorrect.') // phpcs:ignore WordPress.WP.I18n.MissingArgDomain -- Intentionally reuses the WordPress core translation.
            );
        }

        return $phone_user;
    }

    public static function bypass_wordfence_captcha_for_digits($required) {
        if (!wp_doing_ajax()) {
            return $required;
        }

        $action = isset($_REQUEST['action']) ? sanitize_key(wp_unslash($_REQUEST['action'])) : '';

        if (str_starts_with($action, 'digits_')) {
            return false;
        }

        return $required;
    }

    private static function is_legacy_login_page(): bool {
        if (is_admin() || wp_doing_ajax()) {
            return false;
        }

        if (is_singular('digits-forms-page')) {
            return true;
        }

        $queried_id = (int) get_queried_object_id();
        return $queried_id === self::AUTH_PAGE_ID || is_page('login');
    }

    private static function find_user_by_phone(string $phone, string $country_code): ?WP_User {
        $normalized = self::normalize_phone($phone, $country_code);
        if ($normalized === '') {
            return null;
        }

        $global = '+' . $country_code . $normalized;
        $local = '0' . $normalized;

        $users = get_users([
            'number' => 1,
            'fields' => 'all',
            'meta_query' => [
                'relation' => 'OR',
                [
                    'key' => 'digits_phone_no',
                    'value' => $normalized,
                ],
                [
                    'key' => 'digits_phone',
                    'value' => $global,
                ],
                [
                    'key' => 'billing_phone',
                    'value' => $local,
                ],
            ],
        ]);

        if (empty($users) || !$users[0] instanceof WP_User) {
            return null;
        }

        return $users[0];
    }

    private static function normalize_phone(string $phone, string $country_code): string {
        $digits = preg_replace('/\D+/', '', self::normalize_digits($phone)) ?? '';

        if ($digits === '') {
            return '';
        }

        if (str_starts_with($digits, '00')) {
            $digits = substr($digits, 2);
        }

        if (str_starts_with($digits, $country_code) && strlen($digits) > 10) {
            $digits = substr($digits, strlen($country_code));
        }

        if (strlen($digits) === 11 && str_starts_with($digits, '0')) {
            $digits = substr($digits, 1);
        }

        return $digits;
    }

    public static function canonical_login_url(): string {
        return home_url(self::CANONICAL_LOGIN_PATH);
    }

    private static function failed_login_message(): string {
        $locale = strtolower(determine_locale());

        if (str_starts_with($locale, 'fa')) {
            return 'نام کاربری، ایمیل، شماره موبایل یا رمز عبور نادرست است.';
        }

        return 'The username, email, phone number, or password is incorrect.';
    }

    private static function is_canonical_login_request(): bool {
        $path = isset($_SERVER['REQUEST_URI'])
            ? (string) wp_parse_url((string) wp_unslash($_SERVER['REQUEST_URI']), PHP_URL_PATH)
            : '';

        return untrailingslashit($path) === untrailingslashit(self::CANONICAL_LOGIN_PATH);
    }

    private static function normalize_digits(string $value): string {
        return strtr($value, [
            '۰' => '0',
            '۱' => '1',
            '۲' => '2',
            '۳' => '3',
            '۴' => '4',
            '۵' => '5',
            '۶' => '6',
            '۷' => '7',
            '۸' => '8',
            '۹' => '9',
            '٠' => '0',
            '١' => '1',
            '٢' => '2',
            '٣' => '3',
            '٤' => '4',
            '٥' => '5',
            '٦' => '6',
            '٧' => '7',
            '٨' => '8',
            '٩' => '9',
        ]);
    }
}
