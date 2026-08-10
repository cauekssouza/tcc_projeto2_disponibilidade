<?php

declare(strict_types=1);

session_start();

require_once '../assets/includes/auth_functions.php';

check_logged_in();

/**
 * Codificação segura para qualquer dado que futuramente
 * seja enviado para um contexto HTML.
 */
function escapeHtml(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

/*
 * Remove o cookie da sessão.
 *
 * O nome do cookie vem da configuração interna do PHP,
 * não de uma entrada controlada diretamente pelo usuário.
 */
$sessionCookieName = session_name();

if (isset($_COOKIE[$sessionCookieName])) {
    setcookie(
        $sessionCookieName,
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
 * Caso exista um token "remember me", remove-o também
 * do navegador e do banco de dados.
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
     * A aplicação espera que $_SESSION['email'] contenha
     * exclusivamente um endereço de e-mail válido.
     *
     * Não confiamos no conteúdo da sessão sem validação,
     * pois sessões também podem ser corrompidas ou
     * manipuladas por falhas em outras partes da aplicação.
     */
    $email = $_SESSION['email'] ?? null;

    if (
        is_string($email)
        && strlen($email) <= 254
        && filter_var($email, FILTER_VALIDATE_EMAIL) !== false
    ) {

        require '../assets/setup/db.inc.php';

        /*
         * O valor do e-mail e o tipo de autenticação são
         * enviados ao banco exclusivamente como parâmetros.
         *
         * Nenhum dado variável é concatenado na instrução SQL.
         */
        $sql = '
            DELETE FROM auth_tokens
            WHERE user_email = ?
              AND auth_type = ?
        ';

        $stmt = mysqli_stmt_init($conn);

        if ($stmt === false) {
            error_log('Falha ao inicializar Prepared Statement.');
        } elseif (!mysqli_stmt_prepare($stmt, $sql)) {
            error_log('Falha ao preparar exclusão de auth_tokens.');
            mysqli_stmt_close($stmt);
        } else {

            $authType = 'remember_me';

            /*
             * Tipagem explícita:
             *
             * s = string -> $email
             * s = string -> $authType
             */
            if (!mysqli_stmt_bind_param(
                $stmt,
                'ss',
                $email,
                $authType
            )) {
                error_log('Falha no bind de parâmetros.');
            } elseif (!mysqli_stmt_execute($stmt)) {
                error_log('Falha ao excluir token remember_me.');
            }

            mysqli_stmt_close($stmt);
        }
    } else {
        /*
         * Não utilizar um valor de sessão inválido em uma
         * operação de banco.
         *
         * Evita também revelar o conteúdo do e-mail em logs.
         */
        error_log(
            'Logout executado com e-mail de sessão ausente ou inválido.'
        );
    }
}

/*
 * Não há necessidade de alterar $_SESSION['auth'] para
 * "verified" imediatamente antes de destruir a sessão.
 *
 * Isso não produz efeito persistente e foi removido para
 * reduzir estados desnecessários.
 */
session_unset();
session_destroy();

/*
 * URL estática: nenhum dado do usuário é incorporado
 * ao cabeçalho Location.
 */
header('Location: ../login/');
exit;
