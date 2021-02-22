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

    /**
     * An array map with the Response attribute names as the array keys and the
     * array values as the user element field. The array value can also be a callable.
     *
     * Simple mapping works by matching the Response name in the array with the user's
     * property, and setting what is found in the Response's value to the user element.
     * "IDP Attribute Name" => "Craft Property Name"
     * 
     * With more complex user fields, you can set the array value to a callable
     * "IDP Attribute Name" => function($attribute) {...}
     * */
    public $samlAttributesMap = [
        
        'email' => 'email',
        'firstname' => 'firstName',
        'lastname' => 'lastName'
    ];
    
    // Public Methods
    // =========================================================================
    public function behaviors()
    {
        return [
            'parser' => [
                'class' => EnvAttributeParserBehavior::class,
                'attributes' => ['autoCreateUser','region','clientId','userpoolId','jwks','samlCert'],
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
}
