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
use levinriegner\craftcognitoauth\services\SettingsService;

use Craft;
use craft\base\Plugin;
use craft\events\RegisterUrlRulesEvent;
use craft\web\Application;
use craft\web\UrlManager;
use levinriegner\craftcognitoauth\helpers\ValidatorsHelper;
use levinriegner\craftcognitoauth\services\AbstractValidator;
use yii\base\Event;

/**
 * Class CraftJwtAuth
 *
 * @author    Mike Pierce
 * @package   CraftJwtAuth
 * @since     0.1.0
 *
 * @property  AWSCognitoService $cognito
 * @property  SettingsService $settingsService
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
            $this->set($name, $validator);
        }

        Craft::$app->on(Application::EVENT_INIT, function() {
            if(Craft::$app instanceof craft\web\Application){
                foreach(ValidatorsHelper::getAllTypes() as $name => $validator){
                    /**
                     * @var AbstractValidator
                     */
                    $validator = $this->get($name);
                    if($validator->isEnabled())
                        $this->get($name)->parseTokenAndCreateUser();
                }
            }
        });

        // Register our CP routes
        Event::on(
            UrlManager::class,
            UrlManager::EVENT_REGISTER_CP_URL_RULES,
            function (RegisterUrlRulesEvent $event) {
                // Merge so that settings controller action comes first (important!)
                $event->rules = array_merge([
                        'settings/plugins/craft-cognito' => 'craft-cognito/settings/edit',
                    ],
                    $event->rules
                );
            }
        );

        Craft::info(
            Craft::t(
                'craft-cognito',
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
            'craft-cognito/settings',
            [
                'settings' => $this->getSettings()
            ]
        );
    }
}
