<?php

// Generar un secreto para 2FA
function wp_2fa_generate_secret($length = 16) {
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $secret = '';
    for ($i = 0; $i < $length; $i++) {
        $secret .= $chars[random_int(0, strlen($chars) - 1)];
    }
    return $secret;
}

// Verificar el código de 2FA
function wp_2fa_verify_code($secret, $code) {
    require_once(plugin_dir_path(__FILE__) . 'GoogleAuthenticator.php');
    $ga = new GoogleAuthenticator();
    return $ga->verifyCode($secret, $code, 2); // 2 = 2*30sec de tolerancia
}
