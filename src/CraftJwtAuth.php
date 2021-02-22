<?php

/**
 * Craft JWT Auth plugin for Craft CMS 3.x
 *
 * Enable authentication to Craft through the use of JSON Web Tokens (JWT)
 *
 * @link      https://edenspiekermann.com
 * @copyright Copyright (c) 2019 Mike Pierce
 */

namespace levinriegner\craftcognitoauth;

use levinriegner\craftcognitoauth\models\Settings;
use levinriegner\craftcognitoauth\services\AWSCognitoService;

use Craft;
use craft\base\Plugin;
use levinriegner\craftcognitoauth\helpers\ValidatorsHelper;
use levinriegner\craftcognitoauth\services\AbstractValidator;

/**
 * Class CraftJwtAuth
 *
 * @author    Mike Pierce
 * @package   CraftJwtAuth
 * @since     0.1.0
 *
 * @property  AWSCognitoService $cognito
 * @property  Settings $settings
 * @method    Settings getSettings()
 */
class CraftJwtAuth extends Plugin
{
    // Static Properties
    // =========================================================================

    /**
     * @var CraftJwtAuth
     */
    public static $plugin;

    // Public Properties
    // =========================================================================

    /**
     * @var string
     */
    public $schemaVersion = '0.1.0';

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     */
    public function init()
    {
        parent::init();
        self::$plugin = $this;
        foreach(ValidatorsHelper::getAllTypes() as $name => $validator){
            /**
             * @var AbstractValidator
             */
            $this->set($name, $validator);
        }

        if(Craft::$app instanceof craft\web\Application){
            foreach(ValidatorsHelper::getAllTypes() as $name => $validator){
                $this->get($name)->parseTokenAndCreateUser();
            }
        }

        Craft::info(
            Craft::t(
                'craft-cognito-auth',
                '{name} plugin loaded',
                ['name' => $this->name]
            ),
            __METHOD__
        );
    }

    // Protected Methods
    // =========================================================================

    /**
     * @inheritdoc
     */
    protected function createSettingsModel()
    {
        return new Settings();
    }

    /**
     * @inheritdoc
     */
    protected function settingsHtml(): string
    {
        return Craft::$app->view->renderTemplate(
            'craft-cognito-auth/settings',
            [
                'settings' => $this->getSettings()
            ]
        );
    }
}
