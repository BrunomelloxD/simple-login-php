<?php

namespace App\Repositories;

interface UserRepository
{
    public function create($params);
    public function getUser($params);
    public function getAll($params);
}