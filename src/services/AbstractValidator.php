<?php

namespace levinriegner\craftcognitoauth\services;

use Craft;
use craft\base\Component;
use levinriegner\craftcognitoauth\events\UserCreateEvent;

abstract class AbstractValidator extends Component{
    
    const EVENT_AFTER_CREATE_USER = 'afterCreateUser';

    protected abstract function getTokenFromRequest();

    protected abstract function parseToken(string $accessToken);
    protected abstract function verifyToken($accessToken);

    protected abstract function getIssuerByToken($token);
    protected abstract function getUserByToken($token);
    protected abstract function createUserByToken($token);

    public function parseTokenAndCreateUser($accessToken = null)
    {
        if(!$accessToken)
            $accessToken = $this->getTokenFromRequest();

        if(!$accessToken)
            return;

        $token = $this->parseAndVerifyToken($accessToken);

        // If the token passes verification...
        if ($token) {
            // Look for the user
            $user = $this->getUserByToken($token);

            // If we don't have a user, but we're allowed to create one...
            if (!$user) {
                $user = $this->createUserByToken($token);
            }

            // Attempt to login as the user we have found or created
            if ($user && $user->id) {
                $event = new UserCreateEvent(['user' => $user, 'issuer' => $this->getIssuerByToken($token)]);

                if ($this->hasEventHandlers(self::EVENT_AFTER_CREATE_USER)) {
                    $this->trigger(self::EVENT_AFTER_CREATE_USER, $event);
                }

                Craft::$app->user->loginByUserId($user->id);
            }
        }
    }

    private function parseAndVerifyToken($accessToken)
    {
        $token = $this->parseToken($accessToken);

        if ($token && $this->verifyToken($token)) {
            return $token;
        }

        return null;
    }
}