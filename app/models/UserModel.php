<?php

namespace app\models;

use app\repositories\UserRepository;
use app\infra\Database\Connection;
use app\utils\GenerateToken;
use app\middlewares\AuthMiddleware;
use Exception;
use PDO;

class UserModel implements UserRepository
{
    private PDO $conn;
    private $authMiddleware;
    public function __construct(Connection $database)
    {
        $this->conn = $database->getConnection();
        $this->authMiddleware = new AuthMiddleware($this->conn);
    }

    public function create($params): array | Exception
    {
        try {
            $username = $params->name;
            $email = $params->email;
            $password = password_hash($params->password, PASSWORD_BCRYPT);
            $role_id = $params->role_id;

            // Creating the user
            $sql = "INSERT INTO users (username, email, password) VALUES (:username, :email, :password)";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindValue(':username', $username);
            $stmt->bindValue(':email', $email);
            $stmt->bindValue(':password', $password);
            $stmt->execute();
            $user_id = $this->conn->lastInsertId();

            // Creating the user role
            $sql = "INSERT INTO user_roles (user_id, role_id) VALUES (:user_id, :role_id)";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindParam(':user_id', $user_id);
            $stmt->bindParam(':role_id', $role_id);
            $stmt->execute();

            $data = [
                'code' => 201,
                'response' => [
                    'user_id' => $user_id,
                    'message' => 'User created successfully!',
                ],
            ];

            return $data;
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException('Error:', 0, $th);
        }
    }

    public function getUser($params): array | Exception
    {
        try {
            $user_id = $params->user_id;

            $sql = "SELECT id, username, email, created_at FROM users WHERE id = :user_id";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindValue(':user_id', $user_id);
            $stmt->execute();
            $response = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$response) {
                $data = [
                    'code' => 404,
                    'response' => [
                        'code' => 404,
                        'message' => 'User not found',
                    ],
                ];
                return $data;
            }

            $data = [
                'code' => 200,
                'response' => $response,
            ];

            return $data;
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException('Error:', 0, $th);
        }
    }

    public function getAll($params): array | Exception
    {
        try {
            $email = $params->email;

            $auth = $this->authMiddleware->handleCheckPermissionAdmin($email);

            if (!$auth) {
                $data = [
                    'code' => 401,
                    'response' => 'Unauthorized',
                ];
                return $data;
            }

            $sql = "SELECT users.id, users.username, users.email, users.created_at, roles.role_name FROM users JOIN user_roles ON users.id = user_roles.user_id JOIN roles ON user_roles.role_id = roles.id";
            $stmt = $this->conn->prepare($sql);
            $stmt->execute();
            $response = $stmt->fetchAll(PDO::FETCH_ASSOC);

            $data = [
                'code' => 200,
                'response' => $response,
            ];

            return $data;
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException('Error:', 0, $th);
        }
    }

    public function login($params): array | Exception
    {
        try {
            $email = $params->email;
            $password = $params->password;

            $sql = "SELECT * FROM users WHERE email = :email";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindValue(':email', $email);
            $stmt->execute();
            $response = $stmt->fetch(PDO::FETCH_ASSOC);

            // User not found in database
            if (!$response) {
                $data = [
                    'code' => 404,
                    'response' => 'User not found',
                ];
            }

            // Verify password
            if (!password_verify($password, $response['password'])) {
                $data = [
                    'code' => 401,
                    'response' => [
                        'code' => 401,
                        'message' => 'Invalid credentials',
                    ],
                ];

                return $data;
            }

            // Token time in hours
            $time = 24;
            [$token, $tokenTime] = GenerateToken::handle($time);

            // Update token and token time in database
            $user_id = $response['id'];
            $sql = "UPDATE users SET login_token = :token, login_token_expires_at = :token_time WHERE id = :user_id";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindValue(':token', $token);
            $stmt->bindValue(':token_time', $tokenTime);
            $stmt->bindValue(':user_id', $user_id);

            if ($stmt->execute()) {
                $response = [
                    'user' => [
                        'id' => $response['id'],
                        'name' => $response['username'],
                        'email' => $response['email'],
                        'created_at' => $response['created_at']
                    ],
                    'token' => $token,
                    'expires_at' => $tokenTime
                ];

                $data = [
                    'code' => 200,
                    'response' => $response,
                ];

                return $data;
            }
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException('Error:', 0, $th);
        }
    }

    public function delete($params): array | Exception
    {
        try {
            $email = $params->email;
            $user_id = $params->user_id;
            $token = $params->auth_token;

            $auth = $this->authMiddleware->handleCheckPermissionAdmin($email);
            $validateToken = $this->authMiddleware->handleValidateLoginToken($email, $token);

            if (!$validateToken) {
                $data = [
                    'code' => 401,
                    'response' => [
                        'code' => 401,
                        'message' => 'Token expired',
                    ],
                ];
                return $data;
            }

            if (!$auth) {
                $data = [
                    'code' => 401,
                    'response' => [
                        'code' => 401,
                        'message' => 'User not authorized',
                    ],
                ];
                return $data;
            }

            $sql = "SELECT * FROM users WHERE id = :user_id";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindParam(':user_id', $user_id);
            $stmt->execute();
            $user = $stmt->fetch();

            // User not found in database or is not same user
            if ($email === $user['email'] || !$user) {
                $data = [
                    'code' => 401,
                    'response' => [
                        'code' => 401,
                        'message' => 'Unauthorized',
                    ],
                ];
                return $data;
            }

            $deleteSql = "DELETE FROM users WHERE id = :user_id";
            $deleteStmt = $this->conn->prepare($deleteSql);
            $deleteStmt->bindParam(':user_id', $user_id);
            $deleteStmt->execute();

            $data = [
                'code' => 200,
                'response' => [
                    'code' => 200,
                    'message' => 'User deleted successfully!',
                ],
            ];

            return $data;
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException('Error:', 0, $th);
        }
    }

    public function update($params): array | Exception
    {
        try {
            $user_id = $params->user_id;
            $username = $params->name;
            $email = $params->email;

            $sql = "UPDATE users SET username = :username, email = :email WHERE id = :user_id";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindValue(':username', $username);
            $stmt->bindValue(':email', $email);
            $stmt->bindValue(':user_id', $user_id);
            $stmt->execute();

            $data = [
                'code' => 200,
                'response' => [
                    'code' => 200,
                    'message' => 'User updated successfully!',
                ],
            ];

            return $data;
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException('Error:', 0, $th);
        }
    }
}