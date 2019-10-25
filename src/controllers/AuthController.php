<?php

/**
 * Craft JWT Auth plugin for Craft CMS 3.x
 *
 * Enable authentication to Craft through the use of JSON Web Tokens (JWT)
 *
 * @link      https://edenspiekermann.com
 * @copyright Copyright (c) 2019 Mike Pierce
 */

namespace edenspiekermann\craftjwtauth\controllers;

use Craft;
use craft\web\Controller;
use edenspiekermann\craftjwtauth\CraftJwtAuth;

/**
 * @author    Mike Pierce
 * @package   CraftJwtAuth
 * @since     0.1.0
 */
class AuthController extends Controller
{
    protected $allowAnonymous = true;

    public function beforeAction($action)
	{

        $this->enableCsrfValidation = false;

		return parent::beforeAction($action);
	}

    public function actionRegister()
    {
        $this->requirePostRequest();
        
        $username = Craft::$app->getRequest()->getRequiredBodyParam('username');
        $password = Craft::$app->getRequest()->getRequiredBodyParam('password');
        $email = Craft::$app->getRequest()->getRequiredBodyParam('email');

        $cognitoError = CraftJwtAuth::getInstance()->cognito->signup($username, $email, $password);
        if(strlen($cognitoError) == 0){
            return $this->_handleResponse(['status' => 0], 200);
        }else{
            return $this->_handleResponse(['status' => 1, 'error' => $cognitoError], 500);
        }
    }

    public function actionConfirm()
    {
        $username = Craft::$app->getRequest()->getRequiredBodyParam('username');
        $code = Craft::$app->getRequest()->getRequiredBodyParam('code');

        $cognitoError = CraftJwtAuth::getInstance()->cognito->confirmSignup($username, $code);
        if(strlen($cognitoError) == 0){
            return $this->_handleResponse(['status' => 0], 200);
        }else{
            return $this->_handleResponse(['status' => 1, 'error' => $cognitoError], 500);
        } 
    }

    public function actionLogin()
    {
        $username = Craft::$app->getRequest()->getRequiredBodyParam('username');
        $password = Craft::$app->getRequest()->getRequiredBodyParam('password');

        $cognitoResponse = CraftJwtAuth::getInstance()->cognito->authenticate($username, $password);
        if(array_key_exists('token', $cognitoResponse)){
            return $this->_handleResponse(['status' => 0, 'token' => $cognitoResponse['token']], 200, true);
        }else{
            return $this->_handleResponse(['status' => 1, 'error' => $cognitoResponse['error']], 500);
        }
    }

    public function actionForgotpasswordrequest()
    {
        $username = Craft::$app->getRequest()->getRequiredBodyParam('username');

        $cognitoError = CraftJwtAuth::getInstance()->cognito->sendPasswordResetMail($username);
        if(strlen($cognitoError) == 0){
            return $this->_handleResponse(null, 200);
        }else{
            return $this->_handleResponse(['status' => 1, 'error' => $cognitoResponse], 500);
        }
    }

    public function actionForgotpassword()
    {
        $username = Craft::$app->getRequest()->getRequiredBodyParam('username');
        $password = Craft::$app->getRequest()->getRequiredBodyParam('password');
        $code = Craft::$app->getRequest()->getRequiredBodyParam('code');

        $cognitoError = CraftJwtAuth::getInstance()->cognito->resetPassword($code, $password, $username);
        if(strlen($cognitoError) == 0){
            return $this->_handleResponse(null, 200);
        }else{
            return $this->_handleResponse(['status' => 1, 'error' => $cognitoResponse], 500);
        }
    }

    private function _handleResponse($response, $responseCode, $startSession = false){
        $request = Craft::$app->getRequest();
        if ($request->getAcceptsJson()) {
            Craft::$app->getResponse()->setStatusCode($responseCode);
            return $this->asJson($response);
        }else{
            if($responseCode == 200){
                if($startSession){
                    $token = CraftJwtAuth::getInstance()->jwt->parseAndVerifyJWT($response['token']);
        
                    // If the token passes verification...
                    if ($token) {
                        // Look for the user
                        $user = CraftJwtAuth::getInstance()->jwt->getUserByJWT($token);
        
                        // If we don't have a user, but we're allowed to create one...
                        if (!$user) {
                            $user = CraftJwtAuth::getInstance()->jwt->createUserByJWT($token);
                        }
        
                        // Attempt to login as the user we have found or created
                        if ($user && $user->id) {
                            Craft::$app->user->loginByUserId($user->id);
                        }
                    }
                }

                // Get the return URL
                $userSession = Craft::$app->getUser();
                $returnUrl = $userSession->getReturnUrl($request->getParam('redirectUrl'));

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