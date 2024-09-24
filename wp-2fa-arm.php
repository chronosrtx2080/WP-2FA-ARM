<?php
/**
 * Plugin Name: WP 2FA ARM
 * Description: A simple 2FA plugin using TOTP for ARM-based servers.
 * Version: 1.0
 * Author: Tu Nombre
 */

// Asegurarnos de que no se acceda directamente al archivo
if (!defined('ABSPATH')) {
    exit;
}

// Cargar las funciones necesarias para el plugin
require_once plugin_dir_path(__FILE__) . 'includes/wp-2fa-functions.php';

// Agregar un campo de configuración para el perfil de usuario
function wp_2fa_user_profile($user) {
    $enabled = get_option('wp_2fa_arm_enabled');
    $secret = get_user_meta($user->ID, 'wp_2fa_secret', true);

    if ($enabled) {
        // Si el usuario no tiene un secreto, generar uno
        if (!$secret) {
            $secret = wp_2fa_generate_secret();
            update_user_meta($user->ID, 'wp_2fa_secret', $secret);
        }

        ?>
        <h3>Configuración de 2FA</h3>
        <table class="form-table">
            <tr>
                <th><label for="wp_2fa">Código QR para 2FA</label></th>
                <td>
                    <p>Escanea el código QR con tu aplicación de autenticación (Google Authenticator, Authy, etc.).</p>
                    <img src="https://api.qrserver.com/v1/create-qr-code/?data=otpauth://totp/<?php echo urlencode(get_bloginfo('name')); ?>?secret=<?php echo $secret; ?>&size=150x150" />
                    <p><strong>Clave Secreta:</strong> <?php echo $secret; ?></p>
                    <p><i>Asegúrate de configurar tu autenticador antes de salir de esta página.</i></p>
                </td>
            </tr>
            <tr>
                <th><label for="wp_2fa_initial_code">Código de Verificación 2FA</label></th>
                <td>
                    <input type="text" name="wp_2fa_initial_code" id="wp_2fa_initial_code" value="" class="regular-text" />
                    <p class="description">Ingresa un código generado por tu aplicación de autenticación para confirmar la configuración de 2FA.</p>
                </td>
            </tr>
        </table>
        <?php
    }
}
add_action('show_user_profile', 'wp_2fa_user_profile');
add_action('edit_user_profile', 'wp_2fa_user_profile');

// Guardar la configuración de 2FA y validar el código inicial
function wp_2fa_save_user_profile($user_id) {
    if (!current_user_can('edit_user', $user_id)) {
        return false;
    }

    if (isset($_POST['wp_2fa_initial_code']) && !empty($_POST['wp_2fa_initial_code'])) {
        $initial_code = sanitize_text_field($_POST['wp_2fa_initial_code']);
        $secret = get_user_meta($user_id, 'wp_2fa_secret', true);

        if (wp_2fa_verify_code($secret, $initial_code)) {
            update_user_meta($user_id, 'wp_2fa_verified', true);
            add_action('admin_notices', function () {
                echo '<div class="notice notice-success is-dismissible"><p>2FA configurado y verificado correctamente.</p></div>';
            });
        } else {
            delete_user_meta($user_id, 'wp_2fa_secret');
            delete_user_meta($user_id, 'wp_2fa_verified');
            add_action('admin_notices', function () {
                echo '<div class="notice notice-error is-dismissible"><p>El código 2FA ingresado es incorrecto. Intenta nuevamente.</p></div>';
            });
        }
    }
}
add_action('personal_options_update', 'wp_2fa_save_user_profile');
add_action('edit_user_profile_update', 'wp_2fa_save_user_profile');

// Verificar el código 2FA al iniciar sesión
function wp_2fa_check_login($user, $username, $password) {
    // Si hay un error previo en la autenticación, registrar más detalles y salir
    if (is_wp_error($user)) {
        error_log('WP 2FA: Error previo detectado en la autenticación. Detalles: ' . print_r($user->get_error_messages(), true));
        return $user;
    }

    // Verificar si los campos de nombre de usuario y contraseña están vacíos
    if (empty($username) || empty($password)) {
        error_log('WP 2FA: Los campos de nombre de usuario o contraseña están vacíos.');
        return $user;
    }

    // Verificar si 2FA está habilitado a nivel global
    $enabled = get_option('wp_2fa_arm_enabled');
    if (!$enabled) {
        error_log('WP 2FA: El plugin está deshabilitado a nivel global.');
        return $user;
    }

    // Verificar si el usuario tiene 2FA configurado y verificado
    $secret = get_user_meta($user->ID, 'wp_2fa_secret', true);
    $is_verified = get_user_meta($user->ID, 'wp_2fa_verified', true);

    if (empty($secret) || !$is_verified) {
        error_log('WP 2FA: El usuario no tiene 2FA configurado o no está verificado.');
        return $user;
    }

    // Verificar que el código 2FA haya sido ingresado
    if (!isset($_POST['wp_2fa_code']) || empty(trim($_POST['wp_2fa_code']))) {
        error_log('WP 2FA: El código 2FA no fue ingresado.');
        return new WP_Error('authentication_failed', __('<strong>ERROR</strong>: Se requiere el código 2FA para iniciar sesión.'));
    }

    // Verificar el código 2FA ingresado
    $code = sanitize_text_field($_POST['wp_2fa_code']);
    if (!wp_2fa_verify_code($secret, $code)) {
        error_log('WP 2FA: El código 2FA ingresado es incorrecto.');
        return new WP_Error('authentication_failed', __('<strong>ERROR</strong>: El código 2FA es incorrecto.'));
    }

    // Si todo es correcto, permitir el inicio de sesión
    error_log('WP 2FA: El código 2FA es correcto. Inicio de sesión permitido.');
    return $user;
}
add_filter('authenticate', 'wp_2fa_check_login', 50, 3);

// Agregar un campo para el código 2FA en la página de inicio de sesión
function wp_2fa_login_field() {
    $enabled = get_option('wp_2fa_arm_enabled');
    if ($enabled) {
        ?>
        <p>
            <label for="wp_2fa_code">Código 2FA<br />
                <input type="text" name="wp_2fa_code" id="wp_2fa_code" class="input" value="" size="20" /></label>
        </p>
        <?php
    }
}
add_action('login_form', 'wp_2fa_login_field');

// Agregar un menú de configuración al panel de administración
function wp_2fa_add_admin_menu() {
    add_menu_page('Configuración de WP 2FA ARM', 'WP 2FA ARM', 'manage_options', 'wp-2fa-arm', 'wp_2fa_settings_page', 'dashicons-shield-alt', 100);
}
add_action('admin_menu', 'wp_2fa_add_admin_menu');

// Crear la página de configuración
function wp_2fa_settings_page() {
    ?>
    <div class="wrap">
        <h1>Configuración de WP 2FA ARM</h1>
        <form method="post" action="options.php">
            <?php
            settings_fields('wp_2fa_arm_settings');
            do_settings_sections('wp-2fa-arm');
            submit_button();
            ?>
        </form>
    </div>
    <?php
}

// Registrar los ajustes
function wp_2fa_settings_init() {
    register_setting('wp_2fa_arm_settings', 'wp_2fa_arm_enabled');

    add_settings_section(
        'wp_2fa_arm_section',
        'Configuración General',
        null,
        'wp-2fa-arm'
    );

    add_settings_field(
        'wp_2fa_arm_enabled_field',
        'Habilitar 2FA',
        'wp_2fa_enabled_render',
        'wp-2fa-arm',
        'wp_2fa_arm_section'
    );
}
add_action('admin_init', 'wp_2fa_settings_init');

// Renderizar el campo de habilitación de 2FA
function wp_2fa_enabled_render() {
    $enabled = get_option('wp_2fa_arm_enabled');
    ?>
    <input type="checkbox" name="wp_2fa_arm_enabled" value="1" <?php checked(1, $enabled, true); ?> />
    <label for="wp_2fa_arm_enabled">Marque para habilitar 2FA</label>
    <?php
}
