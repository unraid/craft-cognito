<?php

namespace edenspiekermann\craftjwtauth\services;

use Craft;
use craft\base\Component;
use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use edenspiekermann\craftjwtauth\CraftJwtAuth;

class AWSCognitoService extends Component
{
    private $region;
    private $client_id;
    private $userpool_id;

    private $client = null;

    public function __construct()
    {
        $this->region = CraftJwtAuth::getInstance()->getSettings()->region;
        $this->client_id = CraftJwtAuth::getInstance()->getSettings()->clientId;
        $this->userpool_id = CraftJwtAuth::getInstance()->getSettings()->userpoolId;

        $this->initialize();
    }

    public function initialize() : void
    {
        $this->client = new CognitoIdentityProviderClient([
          'version' => '2016-04-18',
          'region' => $this->region
        ]);
        
    }

    public function authenticate(string $username, string $password) : array
    {
        try {
            $result = $this->client->adminInitiateAuth([
                'AuthFlow' => 'ADMIN_NO_SRP_AUTH',
                'ClientId' => $this->client_id,
                'UserPoolId' => $this->userpool_id,
                'AuthParameters' => [
                    'USERNAME' => $username,
                    'PASSWORD' => $password,
                ],
            ]);
        } catch (\Exception $e) {
            return ["error" => $e->getMessage()];
        }

        return ["token" => $result->get('AuthenticationResult')['IdToken']];
    }

    public function signup(string $username, string $email, string $password) : string
    {
        try {
            $result = $this->client->signUp([
                'ClientId' => $this->client_id,
                'Username' => $username,
                'Password' => $password,
                'UserAttributes' => [
                    [
                        'Name' => 'name',
                        'Value' => $username
                    ],
                    [
                        'Name' => 'email',
                        'Value' => $email
                    ]
                ],
            ]);
        } catch (\Exception $e) {
            return $e->getMessage();
        }

        return '';
    }

    public function confirmSignup(string $username, string $code) : string
    {
        try {
            $result = $this->client->confirmSignUp([
                'ClientId' => $this->client_id,
                'Username' => $username,
                'ConfirmationCode' => $code,
            ]);
        } catch (\Exception $e) {
            return $e->getMessage();
        }

        return '';
    }

    public function sendPasswordResetMail(string $username) : string
    {
        try {
            $this->client->forgotPassword([
                'ClientId' => $this->client_id,
                'Username' => $username
            ]);
        } catch (Exception $e) {
            return $e->getMessage();
        }

        return '';
    }

    public function resetPassword(string $code, string $password, string $username) : string
    {
        try {
            $this->client->confirmForgotPassword([
                'ClientId' => $this->client_id,
                'ConfirmationCode' => $code,
                'Password' => $password,
                'Username' => $username
            ]);
        } catch (Exception $e) {
            return $e->getMessage();
        }

        return '';
    }
}