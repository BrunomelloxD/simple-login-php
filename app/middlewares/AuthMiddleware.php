<?php

namespace app\middlewares;

use Exception;
use PDO;

class AuthMiddleware
{
    private $pdo;

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
    }

    public function handle($email): bool | Exception
    {
        try {
            $sql = "SELECT roles.id
            FROM users
            JOIN user_roles ON users.id = user_roles.user_id
            JOIN roles ON user_roles.role_id = roles.id
            WHERE users.email = :email";

            $stmt = $this->pdo->prepare($sql);
            $stmt->bindValue(':email', $email);
            $stmt->execute();
            $response = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($response['id'] === 1) {
                return true;
            }

            return false;
        } catch (\Throwable $th) {
            throw new \RuntimeException('Error:', 0, $th);
        }
    }
}