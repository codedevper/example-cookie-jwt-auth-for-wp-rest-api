<?php

/**
 * Plugin Name: Example Cookie & JWT - WordPress Authentication
 * Plugin URI:  https://github.com/codedevper/example-cookie-jwt-auth-for-wp-rest-api
 * Description: Example Cookie & JWT - WordPress Authentication REST API Plugin.
 * Version:     1.0.0
 * Author:      CodeDevper
 * Author URI:  https://github.com/codedevper/example-cookie-jwt-auth-for-wp-rest-api
 * License:     GPL-3.0
 * License URI: https://github.com/codedevper/example-cookie-jwt-auth-for-wp-rest-api
 * Text Domain: example-cookie-jwt-auth-for-wp-rest-api
 * Domain Path: /languages
 *
 * @package example-cookie-jwt-auth-for-wp-rest-api
 */

defined('ABSPATH') || die("Can't access directly");

// Helper constants.
define('PLUGIN_DIR', rtrim(plugin_dir_path(__FILE__), '/'));
define('PLUGIN_URL', rtrim(plugin_dir_url(__FILE__), '/'));
define('PLUGIN_VERSION', '1.0.0');

// Require composer.
require_once __DIR__ . '/vendor/autoload.php';

// Require classes.
require __DIR__ . '/src/class-setup.php';
