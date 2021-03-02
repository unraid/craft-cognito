<?php

/**
 * Craft JWT Auth plugin for Craft CMS 3.x
 *
 * Enable authentication to Craft through the use of JSON Web Tokens (JWT)
 *
 * @link      https://edenspiekermann.com
 * @copyright Copyright (c) 2019 Mike Pierce
 */

namespace levinriegner\craftcognitoauth\models;

use Craft;
use craft\base\Model;
use craft\behaviors\EnvAttributeParserBehavior;

/**
 * @author    Mike Pierce
 * @package   CraftJwtAuth
 * @since     0.1.0
 */
class Settings extends Model
{
    // Public Properties
    // =========================================================================

    /**
     * @var string
     */
    public $autoCreateUser = '';
    public $region = '';
    public $clientId = '';
    public $userpoolId = '';
    public $jwks = '';
    public $samlCert = '';

    /**
     * If empty, the nameId will be the SAML Subject nameId
     * If not, the given attribute name will be used
     */
    public $samlNameId;  

    //Login URL of the SAML IdP
    public $samlIdPLogin;
    
    // Public Methods
    // =========================================================================
    public function behaviors()
    {
        return [
            'parser' => [
                'class' => EnvAttributeParserBehavior::class,
                'attributes' => ['autoCreateUser','region','clientId','userpoolId','jwks','samlCert', 'samlIdPLogin'],
            ],
        ];
    }

    /**
     * @inheritdoc
     */
    public function rules()
    {
        return [
            ['autoCreateUser', 'boolean'],
            ['region', 'string'],
            ['clientId', 'string'],
            ['userpoolId', 'string'],
            ['jwks', 'string'],
            ['samlCert', 'string'],
            ['samlIdPLogin', 'string'],
        ];
    }

    public function getAutoCreateUser(): bool
    {
        return boolval(Craft::parseEnv($this->autoCreateUser));
    }

    public function getRegion(): string
    {
        return Craft::parseEnv($this->region);
    }

    public function getClientId(): string
    {
        return Craft::parseEnv($this->clientId);
    }

    public function getUserPoolId(): string
    {
        return Craft::parseEnv($this->userpoolId);
    }

    public function getJwks(): string
    {
        return Craft::parseEnv($this->jwks);
    }

    public function getSamlCert(): string
    {
        return Craft::parseEnv($this->samlCert);
    }

    public function getSamlIdpLogin(): string
    {
        return Craft::parseEnv($this->samlIdPLogin);
    }
}
