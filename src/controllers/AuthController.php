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

/**
 * @author    Mike Pierce
 * @package   CraftJwtAuth
 * @since     0.1.0
 */
class AuthController extends Controller
{
    protected $allowAnonymous = ['register','confirm','login',
            'forgotpasswordrequest','forgotpassword','refresh'];

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
        $firstname  = Craft::$app->getRequest()->getRequiredBodyParam('firstname');
        $lastname   = Craft::$app->getRequest()->getRequiredBodyParam('lastname');

        $cognitoError = CraftJwtAuth::getInstance()->cognito->signup($email, $password, $firstname, $lastname);
        if(strlen($cognitoError) == 0){
            return $this->_handleResponse(['status' => 0], 200);
        }else{
            return $this->_handleResponse(['status' => 1, 'error' => $cognitoError], 500);
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

    public function actionLogin()
    {
        $email = Craft::$app->getRequest()->getRequiredBodyParam('email');
        $password = Craft::$app->getRequest()->getRequiredBodyParam('password');

        $cognitoResponse = CraftJwtAuth::getInstance()->cognito->authenticate($email, $password);
        if(array_key_exists('token', $cognitoResponse)){
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
        $username = Craft::$app->getRequest()->getRequiredBodyParam('username');
        $token = Craft::$app->getRequest()->getRequiredBodyParam('token');

        $cognitoResponse = CraftJwtAuth::getInstance()->cognito->refreshAuthentication($username, $token);
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
        $email = Craft::$app->getRequest()->getRequiredBodyParam('email');
        $firstname = Craft::$app->getRequest()->getBodyParam('firstname');
        $lastname = Craft::$app->getRequest()->getBodyParam('lastname');

        $token = CraftJwtAuth::getInstance()->jwt->parseJWT(CraftJwtAuth::getInstance()->jwt->getJWTFromRequest());
        $cognitoEmail = CraftJwtAuth::getInstance()->cognito->getEmail($token);
        $isAdmin = CraftJwtAuth::getInstance()->cognito->isAdmin($token);
        if(!$isAdmin && $cognitoEmail != $email){
            return $this->_handleResponse(['status' => 1, 'error' => 'No admin rights'], 401);
        }

        $cognitoError = CraftJwtAuth::getInstance()->cognito->updateUserAttributes($email, $firstname, $lastname);
        if(strlen($cognitoError) == 0){
            $existingUser = Craft::$app->users->getUserByUsernameOrEmail($email);
            if($existingUser){
                if($firstname)
                    $existingUser->firstName = $firstname;
                if($lastname)
                    $existingUser->lastName = $lastname;

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

        $token = CraftJwtAuth::getInstance()->jwt->parseJWT(CraftJwtAuth::getInstance()->jwt->getJWTFromRequest());
        $cognitoEmail = CraftJwtAuth::getInstance()->cognito->getEmail($token);
        $isAdmin = CraftJwtAuth::getInstance()->cognito->isAdmin($token);
        if(!$isAdmin && $cognitoEmail != $email){
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

        $token = CraftJwtAuth::getInstance()->jwt->parseJWT(CraftJwtAuth::getInstance()->jwt->getJWTFromRequest());
        $cognitoEmail = CraftJwtAuth::getInstance()->cognito->getEmail($token);
        $isAdmin = CraftJwtAuth::getInstance()->cognito->isAdmin($token);
        if(!$isAdmin && $cognitoEmail != $email){
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
            CraftJwtAuth::getInstance()->jwt->parseJWTAndCreateUser($response['token']);

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
}