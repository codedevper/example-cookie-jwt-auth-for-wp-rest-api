=== Cookie & JWT - WordPress Authentication ===

Contributors: contactjavas, tha_sun, dominic_ks
Tags: jwt, jwt-auth, token-authentication, json-web-token, cookie-auth
Requires at least: 5.2
Tested up to: 8.3.9
Stable tag: trunk
Requires PHP: 7.2
License: GPLv3
License URI: https://github.com/codedevper/example-cookie-jwt-auth-for-wp-rest-api

Create JSON Web Token Authentication in WordPress.

== Description ==
WordPress Cookie & JSON Web Token Authentication allows you to do REST API authentication via token. It is a simple, non-complex, and easy to use. This plugin probably is the most convenient way to do JWT Authentication in WordPress. 

== JSON Web Token ==
## Create User
http://wp.test/wp-json/rest-api/v1/jwt-auth/register

## Create Token
http://wp.test/wp-json/rest-api/v1/jwt-auth/login

## Refresh Token
http://wp.test/wp-json/rest-api/v1/jwt-auth/refresh

## Invoke Token
http://wp.test/wp-json/rest-api/v1/jwt-auth/invoke

## Get User
http://wp.test/wp-json/rest-api/v1/jwt-auth/user-info


== Cookies ==
## Create User
http://wp.test/wp-json/rest-api/v1/cookie-auth/register

## Create Token
http://wp.test/wp-json/rest-api/v1/cookie-auth/login

## Get User
http://wp.test/wp-json/rest-api/v1/cookie-auth/user-info
