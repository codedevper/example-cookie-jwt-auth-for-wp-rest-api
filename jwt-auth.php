<?php

/**
 * Plugin Name: JWT Authentication
 * Plugin URI:  https://github.com/codedevper/wordpress-jwt-auth-rest-api
 * Description: JWT Authentication for WordPress.
 * Version:     1.0.0
 * Author:      CodeDevper
 * Author URI:  https://github.com/codedevper/wordpress-jwt-auth-rest-api
 * License:     GPL-3.0
 * License URI: 
 * Text Domain: wp-jwt-auth-rest-api
 * Domain Path: /languages
 *
 * @package wp-jwt-auth-rest-api
 */

defined('ABSPATH') || die("Can't access directly");

// Helper constants.
define('JWT_AUTH_PLUGIN_DIR', rtrim(plugin_dir_path(__FILE__), '/'));
define('JWT_AUTH_PLUGIN_URL', rtrim(plugin_dir_url(__FILE__), '/'));
define('JWT_AUTH_PLUGIN_VERSION', '1.0.0');

// Require composer.
require __DIR__ . '/vendor/autoload.php';

// Require classes.
require __DIR__ . '/class-auth.php';
