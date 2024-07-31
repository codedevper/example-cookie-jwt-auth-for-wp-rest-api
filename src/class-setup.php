<?php

// Require classes.
require __DIR__ . '/auth/class-jwt-auth.php';
require __DIR__ . '/auth/class-cookie-auth.php';

use App\auth\JWTAuth
use App\auth\CookieAuth

new JWTAuth();
new CookieAuth();