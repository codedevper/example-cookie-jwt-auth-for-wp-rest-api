<?php

namespace App\JWT;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

use WP_REST_Request;
use WP_REST_Response;
use WP_Error;
use Exception;

class Auth
{
    public function __construct()
    {
        add_action('rest_api_init', array($this, 'register_routes'));
    }

    public function register_routes()
    {
        register_rest_route('jwt-auth/v1', '/register', array(
            'methods'  => 'POST',
            'callback' => array($this, 'create_user_callback'),
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
            'callback' => array($this, 'create_token_callback'),
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

        register_rest_route('jwt-auth/v1', '/user', array(
            'methods'  => 'GET',
            'callback' => array($this, 'get_user_callback'),
            'permission_callback' => array($this, 'check_token_callback'),
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

    public function create_user_callback(WP_REST_Request $request)
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

    public function create_token_callback(WP_REST_Request $request)
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

        $username = sanitize_text_field($request->get_param('username'));
        $password = $request->get_param('password');

        $user = wp_authenticate($username, $password);

        if (is_wp_error($user)) {
            return new WP_Error('invalid_credentials', 'Invalid username or password', array('status' => 401));
        }

        unset($user->user_pass);

        $token = array(
            'iss' => get_bloginfo('url'),
            'iat' => time(),
            'exp' => time() + (60 * 60), // Token expires in 1 hour
            'data' => array($user)
        );

        $jwt = JWT::encode($token, $secret_key, 'HS256');

        return new WP_REST_Response(array(
            'token' => $jwt,
        ), 200);
    }

    public function check_token_callback($request)
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
            //$decoded = JWT::decode($token, new Key($secret_key, 'HS256'));
            $alg     = 'HS256';
            $payload = JWT::decode($token, new Key($secret_key, $alg));

            // The Token is decoded now validate the iss.
            if ($payload->iss !== $this->get_iss()) {
                // The iss do not match, return error.
                return new WP_REST_Response(
                    array(
                        'success'    => false,
                        'statusCode' => 401,
                        'code'       => 'jwt_auth_bad_iss',
                        'message'    => __('The iss do not match with this server.', 'jwt-auth'),
                        'data'       => array(),
                    ),
                    401
                );
            }

            // Check the user id existence in the token.
            if (!isset($payload->data->user->id)) {
                // No user id in the token, abort!!
                return new WP_REST_Response(
                    array(
                        'success'    => false,
                        'statusCode' => 401,
                        'code'       => 'jwt_auth_bad_request',
                        'message'    => __('User ID not found in the token.', 'jwt-auth'),
                        'data'       => array(),
                    ),
                    401
                );
            }

            // So far so good, check if the given user id exists in db.
            $user = get_user_by('id', $payload->data->user->id);

            if (!$user) {
                // No user id in the token, abort!!
                return new WP_REST_Response(
                    array(
                        'success'    => false,
                        'statusCode' => 401,
                        'code'       => 'jwt_auth_user_not_found',
                        'message'    => __("User doesn't exist", 'jwt-auth'),
                        'data'       => array(),
                    ),
                    401
                );
            }

            // Check extra condition if exists.
            $failed_msg = apply_filters('jwt_auth_extra_token_check', '', $user, $token, $payload);

            if (!empty($failed_msg)) {
                // No user id in the token, abort!!
                return new WP_REST_Response(
                    array(
                        'success'    => false,
                        'statusCode' => 401,
                        'code'       => 'jwt_auth_obsolete_token',
                        'message'    => __('Token is obsolete', 'jwt-auth'),
                        'data'       => array(),
                    ),
                    401
                );
            }

            // Everything looks good, return the payload if $return_response is set to false.
            if (!$request) {
                return $payload;
            }

            $response = array(
                'success'    => true,
                'statusCode' => 200,
                'code'       => 'jwt_auth_valid_token',
                'message'    => __('Token is valid', 'jwt-auth'),
                'data'       => array(),
            );

            $response = apply_filters('jwt_auth_valid_token_response', $response, $user, $token, $payload);

            // Otherwise, return success response.
            return new WP_REST_Response($response);
        } catch (Exception $e) {
            return new WP_Error('invalid_token', 'Invalid token', array('status' => 403));
        }

        return true;
    }

    public function get_user_callback(WP_REST_Request $request)
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
        $decoded = JWT::decode($token, new Key($secret_key, 'HS256'));

        return new WP_REST_Response(array(
            'user' => $decoded->data
        ), 200);
    }
}
