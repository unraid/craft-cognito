<?php

/**
 * Craft JWT Auth plugin for Craft CMS 3.x
 *
 * Enable authentication to Craft through the use of JSON Web Tokens (JWT)
 *
 * @link      https://edenspiekermann.com
 * @copyright Copyright (c) 2019 Mike Pierce
 */

namespace edenspiekermann\craftjwtauth;

use edenspiekermann\craftjwtauth\services\JWT as JWTService;
use edenspiekermann\craftjwtauth\models\Settings;

use Craft;
use craft\base\Plugin;
use craft\web\Application;

use yii\base\Event;

/**
 * Class CraftJwtAuth
 *
 * @author    Mike Pierce
 * @package   CraftJwtAuth
 * @since     0.1.0
 *
 * @property  JWTService $jWT
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

        // Components
        $this->setComponents([
            'cognito' => services\AWSCognitoService::class,
            'jwt' => services\JWT::class
        ]);

        Craft::$app->on(Application::EVENT_INIT, function (Event $event) {
            self::$plugin->jWT->parseJWTAndCreateUser(self::$plugin->jWT->getJWTFromRequest());
        });

        Craft::info(
            Craft::t(
                'craft-jwt-auth',
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
            'craft-jwt-auth/settings',
            [
                'settings' => $this->getSettings()
            ]
        );
    }
}
