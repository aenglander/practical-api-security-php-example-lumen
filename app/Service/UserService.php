<?php

namespace App\Service;


class UserService
{
    public $currentUser;
    private $users;
    private $currentKeyId;

    public function __construct()
    {
        $this->users = [
            'valid-user' => (object)[
                'name' => 'Valid User',
                'id' => 'valid-user',
                'keys' => [
                    'key1' => 'bc926745ef6c8dda6ed2689d08d5793d7525cb81',
                    'key2' => 'bc926745ef6c8dda6ed2689d08d5793d7525cb82'
                ],
            ],
        ];
        $this->currentUser = null;
    }

    public function getUserById(string $id)
    {
        return $this->users[$id] ?? null;
    }

    public function setCurrentUser($user)
    {
        $this->currentUser = $user;
    }

    public function getCurrentUser()
    {
        return $this->currentUser;
    }

    public function setCurrentKeyId($keyId)
    {
        $this->currentKeyId = $keyId;
    }

    public function getCurrentKeyId()
    {
        return $this->currentKeyId;
    }
}