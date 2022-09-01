<?php

/**
 * Craft JWT Auth plugin for Craft CMS 3.x
 *
 * Enable authentication to Craft through the use of JSON Web Tokens (JWT)
 *
 * @link      https://edenspiekermann.com
 * @copyright Copyright (c) 2019 Mike Pierce
 */

namespace levinriegner\craftcognitoauth\controllers;

use Craft;
use craft\web\Controller;
use levinriegner\craftcognitoauth\CraftJwtAuth;
use levinriegner\craftcognitoauth\events\UserLoginEvent;

/**
 * @author    Mike Pierce
 * @package   CraftJwtAuth
 * @since     0.1.0
 */
class AuthController extends Controller
{
    const EVENT_BEFORE_LOGIN_COGNITO = 'beforeLoginCognito';
    const EVENT_AFTER_LOGIN_COGNITO = 'afterLoginCognito';

    protected $allowAnonymous = [
        'register',
        'confirm',
        'confirmrequest',
        'login',
        'forgotpasswordrequest',
        'forgotpassword',
        'refresh',
    ];

    public function beforeAction($action)
	{

        $this->enableCsrfValidation = false;

		return parent::beforeAction($action);
	}

    public function actionRegister()
    {
        $this->requirePostRequest();

        $email      = Craft::$app->getRequest()->getRequiredBodyParam('email');
        $password   = Craft::$app->getRequest()->getRequiredBodyParam('password');
        $firstname  = Craft::$app->getRequest()->getBodyParam('firstname');
        $lastname   = Craft::$app->getRequest()->getBodyParam('lastname');
        $phone      = Craft::$app->getRequest()->getBodyParam('phone');
        $username   = Craft::$app->getRequest()->getBodyParam('username');

        $cognitoResponse = CraftJwtAuth::getInstance()->cognito->signup($email, $password, $firstname, $lastname, $phone, $username);
        if(array_key_exists('UserSub', $cognitoResponse)){
            return $this->_handleResponse(['status' => 0, 'userId' => $cognitoResponse['UserSub']], 200);
        }else{
            return $this->_handleResponse(['status' => 1, 'error' => $cognitoResponse['error']], 500);
        }
    }

    public function actionConfirm()
    {
        $email = Craft::$app->getRequest()->getRequiredBodyParam('email');
        $code = Craft::$app->getRequest()->getRequiredBodyParam('code');

        $cognitoError = CraftJwtAuth::getInstance()->cognito->confirmSignup($email, $code);
        if(strlen($cognitoError) == 0){
            return $this->_handleResponse(['status' => 0], 200);
        }else{
            return $this->_handleResponse(['status' => 1, 'error' => $cognitoError], 500);
        }
    }

    public function actionConfirmrequest()
    {
        $email = Craft::$app->getRequest()->getRequiredBodyParam('email');

        $cognitoError = CraftJwtAuth::getInstance()->cognito->resendConfirmationCode($email);
        if(strlen($cognitoError) == 0){
            return $this->_handleResponse(['status' => 0], 200);
        }else{
            return $this->_handleResponse(['status' => 1, 'error' => $cognitoError], 500);
        } 
    }

    public function actionLogin()
    {
        $email = Craft::$app->getRequest()->getRequiredBodyParam('email');
        $password = Craft::$app->getRequest()->getRequiredBodyParam('password');

        $event = new UserLoginEvent(['email' => $email]);

        if ($this->hasEventHandlers(self::EVENT_BEFORE_LOGIN_COGNITO)) {
            $this->trigger(self::EVENT_BEFORE_LOGIN_COGNITO, $event);
        }

        $cognitoResponse = CraftJwtAuth::getInstance()->cognito->authenticate($email, $password);
        if(array_key_exists('token', $cognitoResponse)){
            if ($this->hasEventHandlers(self::EVENT_AFTER_LOGIN_COGNITO)) {
                $this->trigger(self::EVENT_AFTER_LOGIN_COGNITO, $event);
            }

            return $this->_handleResponse(['status' => 0, 
                    'token' => $cognitoResponse['token'],
                    'accessToken' => $cognitoResponse['accessToken'],
                    'refreshToken' => $cognitoResponse['refreshToken'],
                    'expiresIn' => $cognitoResponse['expiresIn']
                ], 200, true);
        }else{
            return $this->_handleResponse(['status' => 1, 'error' => $cognitoResponse['error']], 500);
        }
    }

    public function actionForgotpasswordrequest()
    {
        $email = Craft::$app->getRequest()->getRequiredBodyParam('email');

        $cognitoError = CraftJwtAuth::getInstance()->cognito->sendPasswordResetMail($email);
        if(strlen($cognitoError) == 0){
            return $this->_handleResponse(null, 200);
        }else{
            return $this->_handleResponse(['status' => 1, 'error' => $cognitoError], 500);
        }
    }

    public function actionForgotpassword()
    {
        $email = Craft::$app->getRequest()->getRequiredBodyParam('email');
        $password = Craft::$app->getRequest()->getRequiredBodyParam('password');
        $code = Craft::$app->getRequest()->getRequiredBodyParam('code');

        $cognitoError = CraftJwtAuth::getInstance()->cognito->resetPassword($code, $password, $email);
        if(strlen($cognitoError) == 0){
            return $this->_handleResponse(null, 200);
        }else{
            return $this->_handleResponse(['status' => 1, 'error' => $cognitoError], 500);
        }
    }

    public function actionRefresh()
    {
        $email = Craft::$app->getRequest()->getRequiredBodyParam('email');
        $token = Craft::$app->getRequest()->getRequiredBodyParam('token');

        $cognitoResponse = CraftJwtAuth::getInstance()->cognito->refreshAuthentication($email, $token);
        if(array_key_exists('token', $cognitoResponse)){
            return $this->_handleResponse(['status' => 0, 
                    'token' => $cognitoResponse['token'],
                    'accessToken' => $cognitoResponse['accessToken'],
                    'expiresIn' => $cognitoResponse['expiresIn']
                ], 200);
        }else{
            return $this->_handleResponse(['status' => 1, 'error' => $cognitoResponse['error']], 500);
        }
    }

    public function actionUpdate()
    {
        $username   = Craft::$app->getRequest()->getRequiredBodyParam('username');
        $email      = Craft::$app->getRequest()->getBodyParam('email');
        $firstname  = Craft::$app->getRequest()->getBodyParam('firstname');
        $lastname   = Craft::$app->getRequest()->getBodyParam('lastname');
        $phone      = Craft::$app->getRequest()->getBodyParam('phone');

        $user = $this->getCurrentUser();
        if(!$user->admin && $user->username != $username){
            return $this->_handleResponse(['status' => 1, 'error' => 'No admin rights'], 401);
        }

        $cognitoError = CraftJwtAuth::getInstance()->cognito->updateUserAttributes($username, $firstname, $lastname, $phone, $email);
        if(strlen($cognitoError) == 0){
            $existingUser = Craft::$app->users->getUserByUsernameOrEmail($username);
            if($existingUser){
                if($firstname)
                    $existingUser->firstName = $firstname;
                if($lastname)
                    $existingUser->lastName = $lastname;
                if($email)
                    $existingUser->email = $email;

                Craft::$app->getElements()->saveElement($existingUser);
            }
            return $this->_handleResponse(['status' => 0], 200);
        }else{
            return $this->_handleResponse(['status' => 1, 'error' => $cognitoError], 500);
        }
    }

    public function actionDelete()
    {
        $email = Craft::$app->getRequest()->getRequiredBodyParam('email');

        $user = $this->getCurrentUser();
        if(!$user->admin && $user->email != $email){
            return $this->_handleResponse(['status' => 1, 'error' => 'No admin rights'], 401);
        }
        
        $cognitoError = CraftJwtAuth::getInstance()->cognito->deleteUser($email);
        if(strlen($cognitoError) == 0){
            $existingUser = Craft::$app->users->getUserByUsernameOrEmail($email);
            if($existingUser)
                Craft::$app->getElements()->deleteElement($existingUser);

            return $this->_handleResponse(['status' => 0], 200);
        }else{
            return $this->_handleResponse(['status' => 1, 'error' => $cognitoError], 500);
        }
    }

    public function actionDisable()
    {
        $email = Craft::$app->getRequest()->getRequiredBodyParam('email');

        $user = $this->getCurrentUser();
        if(!$user->admin && $user->email != $email){
            return $this->_handleResponse(['status' => 1, 'error' => 'No admin rights'], 401);
        }
        
        $cognitoError = CraftJwtAuth::getInstance()->cognito->disableUser($email);
        if(strlen($cognitoError) == 0){
            return $this->_handleResponse(['status' => 0], 200);
        }else{
            return $this->_handleResponse(['status' => 1, 'error' => $cognitoError], 500);
        }
    }

    private function _handleResponse($response, $responseCode, $startSession = false){
        $request = Craft::$app->getRequest();
        if($responseCode == 200 && $startSession)
            CraftJwtAuth::getInstance()->jwt->parseTokenAndCreateUser($response['token']);

        if ($request->getAcceptsJson()) {
            Craft::$app->getResponse()->setStatusCode($responseCode);
            return $this->asJson($response);
        }else{
            if($responseCode == 200){
                // Get the return URL
                $userSession = Craft::$app->getUser();

                $returnUrl = $request->getParam('redirectUrl') ? 
                                $request->getParam('redirectUrl') : $userSession->getReturnUrl();

                return $this->redirectToPostedUrl($userSession->getIdentity(), $returnUrl);
            }else{
                Craft::$app->getUrlManager()->setRouteParams([
                    'errorMessage' => $response['error'],
                ]);

                return null;
            }
        }
    }

    private function getCurrentUser() {
        return Craft::$app->getUser()->getIdentity();
    }
}