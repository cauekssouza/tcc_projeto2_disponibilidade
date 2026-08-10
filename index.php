<?php

declare(strict_types=1);

session_start();

require_once '../assets/includes/auth_functions.php';

check_logged_in();

/**
 * Codificação segura para qualquer dado dinâmico que venha
 * a ser renderizado em contexto HTML.
 */
function escapeHtml(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

/*
 * Remove o cookie da sessão.
 *
 * Os atributos devem ser compatíveis com os utilizados
 * originalmente na criação do cookie.
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
 * Se existe um cookie "rememberme", revoga no servidor
 * qualquer token persistente associado à sessão autenticada.
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
     * Nunca utilizar diretamente $_SESSION['email'] em uma operação
     * de banco de dados sem validação prévia.
     */
    $sessionEmail = $_SESSION['email'] ?? null;

    if (
        is_string($sessionEmail)
        && strlen($sessionEmail) <= 254
        && filter_var($sessionEmail, FILTER_VALIDATE_EMAIL) !== false
    ) {
        /*
         * FILTER_VALIDATE_EMAIL valida o dado.
         *
         * Não é necessário utilizar addslashes(),
         * mysqli_real_escape_string() ou qualquer sanitização SQL,
         * pois a proteção contra SQL Injection é feita pelo
         * Prepared Statement parametrizado.
         */
        $validatedEmail = $sessionEmail;

        require '../assets/setup/db.inc.php';

        if (!isset($conn) || !($conn instanceof mysqli)) {
            error_log('Logout: conexão com o banco de dados indisponível.');
        } else {

            /*
             * CWE-89:
             * Todos os valores variáveis são enviados como parâmetros.
             *
             * Até auth_type foi parametrizado para evitar que dados e
             * comandos SQL sejam misturados.
             */
            $sql = '
                DELETE FROM auth_tokens
                WHERE user_email = ?
                  AND auth_type = ?
            ';

            $stmt = mysqli_stmt_init($conn);

            if ($stmt === false) {
                error_log('Logout: não foi possível inicializar o statement.');
            } elseif (!mysqli_stmt_prepare($stmt, $sql)) {
                error_log('Logout: falha ao preparar a revogação do token.');
                mysqli_stmt_close($stmt);
            } else {

                $authType = 'remember_me';

                /*
                 * Tipagem explícita:
                 *
                 * s = string ($validatedEmail)
                 * s = string ($authType)
                 */
                if (!mysqli_stmt_bind_param(
                    $stmt,
                    'ss',
                    $validatedEmail,
                    $authType
                )) {
                    error_log('Logout: falha ao vincular parâmetros.');
                } elseif (!mysqli_stmt_execute($stmt)) {
                    error_log('Logout: falha ao revogar token persistente.');
                }

                mysqli_stmt_close($stmt);
            }
        }
    } else {
        /*
         * O valor inválido não é utilizado nem enviado ao banco.
         * Também não é exibido ao usuário.
         */
        error_log('Logout: e-mail inválido encontrado na sessão.');
    }
}

/*
 * Destrói os dados da sessão somente depois das operações
 * que dependem das informações nela armazenadas.
 */
$_SESSION = [];

session_unset();
session_destroy();

/*
 * Redirect fixo: não recebe entrada controlável pelo usuário,
 * evitando também problemas de Open Redirect.
 */
header('Location: ../login/', true, 302);
exit;
