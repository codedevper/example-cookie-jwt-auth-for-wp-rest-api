<?php

namespace App\auth;

use WP_REST_Request;
use WP_REST_Response;
use WP_Error;
use Exception;

class CookieAuth
{
    private $rest_url = 'rest-api/v1/cookie-auth';

    public function __construct()
    {
        add_action('rest_api_init', array($this, 'register_routes'));
    }

    public function register_routes()
    {
        register_rest_route($this->rest_url, '/register', array(
            'methods'  => 'POST',
            'callback' => array($this, 'create_user'),
            'args'     => array(
                'username' => array(
                    'required'          => true,
                    'validate_callback' => array($this, 'validate_username')
                ),
                'email' => array(
                    'required' => true,
                    'validate_callback' => array($this, 'validate_email')
                ),
                'password' => array(
                    'required'          => true,
                    'validate_callback' => array($this, 'validate_password')
                ),
            ),
        ));

        register_rest_route($this->rest_url, '/login', array(
            'methods'  => 'POST',
            'callback' => array($this, 'login_user'),
            'args'     => array(
                'username' => array(
                    'required'          => true,
                    'validate_callback' => array($this, 'validate_username')
                ),
                'password' => array(
                    'required'          => true,
                    'validate_callback' => array($this, 'validate_password')
                ),
            ),
        ));

        register_rest_route($this->rest_url, '/user-info', array(
            'methods'  => 'GET',
            'callback' => array($this, 'get_user_info'),
            'permission_callback' => array($this, 'check_cookie_auth'),
        ));
    }

    public function validate_username($param, $request, $key)
    {
        return is_string($param);
    }

    public function validate_email($param, $request, $key)
    {
        return is_email($param);
    }

    public function validate_password($param, $request, $key)
    {
        return is_string($param);
    }

    public function create_user(WP_REST_Request $request)
    {
        $username = sanitize_text_field($request->get_param('username'));
        $email = sanitize_email($request->get_param('email'));
        $password = $request->get_param('password');

        // Check if the username already exists
        if (username_exists($username)) {
            return new WP_Error('username_exists', 'Username already exists', array('status' => 400));
        }

        // Check if the email already exists
        if (email_exists($email)) {
            return new WP_Error('email_exists', 'Email already exists', array('status' => 400));
        }

        // Create the user
        $user_id = wp_create_user($username, $password, $email);

        // Check for errors
        if (is_wp_error($user_id)) {
            return $user_id;
        }

        // Optionally, update user meta or role
        wp_update_user(array(
            'ID' => $user_id,
            'role' => 'subscriber' // Set the desired role
        ));

        return new WP_REST_Response(array(
            'user_id' => $user_id,
            'username' => $username,
            'email' => $email,
            'role' => 'subscriber'
        ), 201);
    }

    public function login_user(WP_REST_Request $request)
    {
        $username = sanitize_text_field($request->get_param('username'));
        $password = $request->get_param('password');

        $user = wp_authenticate($username, $password);

        if (is_wp_error($user)) {
            return new WP_Error('invalid_credentials', 'Invalid username or password', array('status' => 401));
        }

        // Generate authentication cookie
        $secure = is_ssl();
        $expiration = time() + apply_filters('auth_cookie_expiration', 2 * DAY_IN_SECONDS, $user->ID, $secure);
        $cookie = wp_generate_auth_cookie($user->ID, $expiration, 'logged_in');
        wp_set_auth_cookie($user->ID); // Set the auth cookie for the user
        wp_set_current_user($user->ID);
        do_action('wp_login', $user->user_login, $user);

        return new WP_REST_Response(array(
            'message' => 'User logged in successfully',
            'cookie' => $cookie
        ), 200);
    }

    public function get_user_info(WP_REST_Request $request)
    {
        $user = wp_get_current_user();

        if (0 === $user->ID) {
            return new WP_Error('no_user', 'User not found', array('status' => 404));
        }

        return new WP_REST_Response(array(
            'user_id' => $user->ID,
            'username' => $user->user_login,
            'email' => $user->user_email
        ), 200);
    }

    public function check_cookie_auth()
    {
        return is_user_logged_in();
    }
}