<?php

declare(strict_types=1);

session_start();

require_once '../assets/includes/auth_functions.php';

check_logged_in();

/*
 * Remove o cookie da sessão.
 */
if (isset($_COOKIE[session_name()])) {
    setcookie(
        session_name(),
        '',
        [
            'expires'  => time() - 3600,
            'path'     => '/',
            'secure'   => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
            'httponly' => true,
            'samesite' => 'Lax'
        ]
    );
}

/*
 * Se existir o cookie "rememberme", invalida também
 * o token persistente no banco de dados.
 */
if (isset($_COOKIE['rememberme'])) {

    setcookie(
        'rememberme',
        '',
        [
            'expires'  => time() - 3600,
            'path'     => '/',
            'secure'   => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
            'httponly' => true,
            'samesite' => 'Lax'
        ]
    );

    /*
     * Nunca confiar diretamente em valores da sessão.
     * A sessão também pode conter dados originalmente provenientes
     * de entrada externa.
     */
    $email = $_SESSION['email'] ?? null;

    if (
        is_string($email)
        && strlen($email) <= 254
        && filter_var($email, FILTER_VALIDATE_EMAIL) !== false
    ) {
        require_once '../assets/setup/db.inc.php';

        /*
         * CWE-89:
         * Nenhum dado dinâmico é concatenado na instrução SQL.
         */
        $sql = "
            DELETE FROM auth_tokens
            WHERE user_email = ?
              AND auth_type = 'remember_me'
        ";

        $stmt = mysqli_prepare($conn, $sql);

        if ($stmt !== false) {

            /*
             * Tipagem explícita:
             *
             * s = string
             *
             * $email é garantidamente string devido à validação acima.
             */
            mysqli_stmt_bind_param($stmt, 's', $email);

            mysqli_stmt_execute($stmt);

            mysqli_stmt_close($stmt);
        }
    }

    if (isset($_SESSION['auth'])) {
        $_SESSION['auth'] = 'verified';
    }
}

/*
 * Limpa todos os dados da sessão antes de destruí-la.
 */
$_SESSION = [];

session_unset();
session_destroy();

/*
 * Não há conteúdo HTML sendo renderizado neste script.
 * Portanto, htmlspecialchars() não deve ser aplicado artificialmente.
 *
 * Caso algum valor dinâmico venha a ser renderizado em HTML:
 *
 * echo htmlspecialchars($valor, ENT_QUOTES, 'UTF-8');
 */

header('Location: ../login/');
exit;
