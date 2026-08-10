<?php
session_start();

require '../assets/includes/auth_functions.php';
check_logged_in();

// Regenera o ID da sessão para evitar fixation
session_regenerate_id(true);

/**
 * Sanitização de dados vindos da sessão e cookies
 */
$userEmail = filter_var($_SESSION['email'] ?? '', FILTER_SANITIZE_EMAIL);
$sessionCookie = filter_var($_COOKIE[session_name()] ?? '', FILTER_SANITIZE_STRING);
$rememberCookie = filter_var($_COOKIE['rememberme'] ?? '', FILTER_SANITIZE_STRING);

/**
 * Remove cookie de sessão, se existir
 */
if (!empty($sessionCookie)) {
    setcookie(session_name(), '', [
        'expires'  => time() - 7000000,
        'path'     => '/',
        'secure'   => true,
        'httponly' => true,
        'samesite' => 'Strict'
    ]);
}

/**
 * Remove cookie de remember me e apaga token no banco
 */
if (!empty($rememberCookie)) {

    setcookie('rememberme', '', [
        'expires'  => time() - 7000000,
        'path'     => '/',
        'secure'   => true,
        'httponly' => true,
        'samesite' => 'Strict'
    ]);

    require '../assets/setup/db.inc.php';

    $sql = "DELETE FROM auth_tokens 
            WHERE user_email = ? AND auth_type = 'remember_me'";

    if ($stmt = mysqli_prepare($conn, $sql)) {
        mysqli_stmt_bind_param($stmt, "s", $userEmail);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_close($stmt);

        if (isset($_SESSION['auth'])) {
            $_SESSION['auth'] = 'verified';
        }
    }
}

/**
 * Finaliza sessão com segurança
 */
$_SESSION = [];
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', [
        'expires'  => time() - 42000,
        'path'     => $params["path"],
        'domain'   => $params["domain"],
        'secure'   => $params["secure"],
        'httponly' => $params["httponly"],
        'samesite' => 'Strict'
    ]);
}

session_destroy();

/**
 * Redireciona para login
 */
header("Location: ../login/");
exit;
