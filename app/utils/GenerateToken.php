<?php

namespace App\utils;

class GenerateToken
{
    public static function handle($time)
    {
        try {
            $token = bin2hex(openssl_random_pseudo_bytes(16));
            $currentDate = date('Y-m-d H:i:s');
            $tokenTime = date('Y-m-d H:i:s', strtotime($currentDate . ' + ' . $time . ' hours'));

            return [$token, $tokenTime];
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException('Error:', 0, $th);
        }
    }
}