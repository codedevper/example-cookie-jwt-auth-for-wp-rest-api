<?php

namespace App\Auth;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

use WP_REST_Request;
use WP_REST_Response;
use WP_Error;
use Exception;

class JWTAuth
{
    //private $secret_key = 'your_secret_key'; // Change this to your secret key
    //private $refresh_token_key = 'your_refresh_secret_key'; // Change this to your refresh token secret key
    private $alg = 'HS256';

    public function __construct()
    {
        add_action('rest_api_init', array($this, 'register_routes'));
    }

    public function register_routes()
    {
        register_rest_route('jwt-auth/v1', '/register', array(
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

        register_rest_route('jwt-auth/v1', '/login', array(
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

        register_rest_route('jwt-auth/v1', '/refresh', array(
            'methods'  => 'POST',
            'callback' => array($this, 'refresh_token'),
            'permission_callback' => array($this, 'check_jwt_token'),
            'args'     => array(
                'refresh_token' => array(
                    'required'          => true,
                    'validate_callback' => array($this, 'validate_refresh_token')
                ),
            ),
        ));

        register_rest_route('jwt-auth/v1', '/invoke', array(
            'methods'  => 'POST',
            'callback' => array($this, 'invoke_token'),
            'permission_callback' => array($this, 'check_jwt_token'),
            'args'     => array(
                'refresh_token' => array(
                    'required'          => true,
                    'validate_callback' => array($this, 'validate_refresh_token')
                ),
            ),
        ));

        register_rest_route('jwt-auth/v1', '/user-info', array(
            'methods'  => 'GET',
            'callback' => array($this, 'get_user_info'),
            'permission_callback' => array($this, 'check_jwt_token'),
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

    public function validate_refresh_token($param, $request, $key)
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

        unset($user->user_pass);

        $access_token = $this->generate_access_token($user);
        $refresh_token = $this->generate_refresh_token($user);

        return new WP_REST_Response(array(
            'access_token' => $access_token,
            'refresh_token' => $refresh_token,
            'iss' => get_bloginfo('url'),
            'iat' => time(),
            'expired_at' => time() + (60 * 15), // Token expires in 15 minutes
            'user_profile' => array(
                'user_id' => $user->ID,
                'username' => $user->user_login,
                'email' => $user->user_email,
                'user_nicename' => $user->user_nicename,
                'display_name' => $user->display_name,
                'user_status' => $user->user_status,
                'roles' => $user->roles[0]
            ),
            'user_data' => $user
        ), 200);
    }

    public function refresh_token(WP_REST_Request $request)
    {
        $secret_key = defined('JWT_AUTH_SECRET_KEY') ? 'JWT_AUTH_SECRET_KEY' : false;

        // First thing, check the secret key if not exist return a error.
        if (!$secret_key) {
            return new WP_REST_Response(
                array(
                    'success'    => false,
                    'statusCode' => 500,
                    'code'       => 'jwt_auth_bad_config',
                    'message'    => __('JWT is not configured properly.', 'jwt-auth'),
                    'data'       => array(),
                ),
                500
            );
        }

        $refresh_token = $request->get_param('refresh_token');

        try {
            $decoded = JWT::decode($refresh_token, new Key($secret_key, $this->alg));
        } catch (Exception $e) {
            return new WP_Error('invalid_refresh_token', 'Invalid refresh token', array('status' => 403));
        }

        $user_id = $decoded->data->user_id;
        $user = get_user_by('ID', $user_id);

        if (!$user) {
            return new WP_Error('user_not_found', 'User not found', array('status' => 404));
        }

        $access_token = $this->generate_access_token($user);

        return new WP_REST_Response(array(
            'access_token' => $access_token
        ), 200);
    }

    public function invoke_token(WP_REST_Request $request)
    {
        $secret_key = defined('JWT_AUTH_SECRET_KEY') ? 'JWT_AUTH_SECRET_KEY' : false;

        // First thing, check the secret key if not exist return a error.
        if (!$secret_key) {
            return new WP_REST_Response(
                array(
                    'success'    => false,
                    'statusCode' => 500,
                    'code'       => 'jwt_auth_bad_config',
                    'message'    => __('JWT is not configured properly.', 'jwt-auth'),
                    'data'       => array(),
                ),
                500
            );
        }

        $refresh_token = $request->get_param('refresh_token');

        try {
            $decoded = JWT::decode($refresh_token, new Key($secret_key, $this->alg));
        } catch (Exception $e) {
            return new WP_Error('invalid_refresh_token', 'Invalid refresh token', array('status' => 403));
        }

        $user_id = $decoded->data->user_id;
        $user = get_user_by('ID', $user_id);

        if (!$user) {
            return new WP_Error('user_not_found', 'User not found', array('status' => 404));
        }

        $access_token = $this->generate_access_token($user);

        return new WP_REST_Response(array(
            'access_token' => $access_token
        ), 200);
    }

    public function get_user_info(WP_REST_Request $request)
    {
        $secret_key = defined('JWT_AUTH_SECRET_KEY') ? 'JWT_AUTH_SECRET_KEY' : false;

        // First thing, check the secret key if not exist return a error.
        if (!$secret_key) {
            return new WP_REST_Response(
                array(
                    'success'    => false,
                    'statusCode' => 500,
                    'code'       => 'jwt_auth_bad_config',
                    'message'    => __('JWT is not configured properly.', 'jwt-auth'),
                    'data'       => array(),
                ),
                500
            );
        }

        $auth_header = $request->get_header('Authorization');
        list($token) = sscanf($auth_header, 'Bearer %s');
        $decoded = JWT::decode($token, new Key($secret_key, $this->alg));

        $user_id = $decoded->data->user_id;
        $user = get_user_by('ID', $user_id);

        if (!$user) {
            return new WP_Error('user_not_found', 'User not found', array('status' => 404));
        }

        return new WP_REST_Response(array(
            'user_id' => $user->ID,
            'username' => $user->user_login,
            'email' => $user->user_email,
            'user_nicename' => $user->user_nicename,
            'display_name' => $user->display_name,
            'user_status' => $user->user_status,
            'roles' => $user->roles[0]
        ), 200);
    }

    public function check_jwt_token($request)
    {
        $secret_key = defined('JWT_AUTH_SECRET_KEY') ? 'JWT_AUTH_SECRET_KEY' : false;

        // First thing, check the secret key if not exist return a error.
        if (!$secret_key) {
            return new WP_REST_Response(
                array(
                    'success'    => false,
                    'statusCode' => 500,
                    'code'       => 'jwt_auth_bad_config',
                    'message'    => __('JWT is not configured properly.', 'jwt-auth'),
                    'data'       => array(),
                ),
                500
            );
        }

        $auth_header = $request->get_header('Authorization');
        if (!$auth_header) {
            return new WP_Error('no_auth_header', 'Authorization header not found', array('status' => 403));
        }

        list($token) = sscanf($auth_header, 'Bearer %s');

        if (!$token) {
            return new WP_Error('bad_auth_header', 'Authorization header format is invalid', array('status' => 403));
        }

        try {
            $decoded = JWT::decode($token, new Key($secret_key, $this->alg));
            return $decoded;
        } catch (Exception $e) {
            return new WP_Error('invalid_token', 'Invalid token', array('status' => 403));
        }
    }

    private function generate_access_token($user)
    {
        $secret_key = defined('JWT_AUTH_SECRET_KEY') ? 'JWT_AUTH_SECRET_KEY' : false;

        // First thing, check the secret key if not exist return a error.
        if (!$secret_key) {
            return new WP_REST_Response(
                array(
                    'success'    => false,
                    'statusCode' => 500,
                    'code'       => 'jwt_auth_bad_config',
                    'message'    => __('JWT is not configured properly.', 'jwt-auth'),
                    'data'       => array(),
                ),
                500
            );
        }

        $token = array(
            'iss' => get_bloginfo('url'),
            'iat' => time(),
            'exp' => time() + (60 * 15), // Token expires in 15 minutes
            'data' => array(
                'user_id' => $user->ID,
                'username' => $user->user_login,
                'email' => $user->user_email
            )
        );

        return JWT::encode($token, $secret_key, $this->alg);
    }

    private function generate_refresh_token($user)
    {
        $secret_key = defined('JWT_AUTH_SECRET_KEY') ? 'JWT_AUTH_SECRET_KEY' : false;

        // First thing, check the secret key if not exist return a error.
        if (!$secret_key) {
            return new WP_REST_Response(
                array(
                    'success'    => false,
                    'statusCode' => 500,
                    'code'       => 'jwt_auth_bad_config',
                    'message'    => __('JWT is not configured properly.', 'jwt-auth'),
                    'data'       => array(),
                ),
                500
            );
        }

        $token = array(
            'iss' => get_bloginfo('url'),
            'iat' => time(),
            'exp' => time() + (60 * 60 * 24 * 7), // Token expires in 1 week
            'data' => array(
                'user_id' => $user->ID,
                'username' => $user->user_login,
                'email' => $user->user_email
            )
        );

        return JWT::encode($token, $secret_key, $this->alg);
    }

    private function generate_invoke_token($user)
    {
        $secret_key = defined('JWT_AUTH_SECRET_KEY') ? 'JWT_AUTH_SECRET_KEY' : false;

        // First thing, check the secret key if not exist return a error.
        if (!$secret_key) {
            return new WP_REST_Response(
                array(
                    'success'    => false,
                    'statusCode' => 500,
                    'code'       => 'jwt_auth_bad_config',
                    'message'    => __('JWT is not configured properly.', 'jwt-auth'),
                    'data'       => array(),
                ),
                500
            );
        }

        $token = array(
            'iss' => get_bloginfo('url'),
            'iat' => time(),
            'exp' => time() + (60 * 1), // Token expires in 1 minutes
            'data' => array(
                'user_id' => $user->ID,
                'username' => $user->user_login,
                'email' => $user->user_email
            )
        );

        return JWT::encode($token, $secret_key, $this->alg);
    }
}
