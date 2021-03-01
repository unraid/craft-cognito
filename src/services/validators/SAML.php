<?php

namespace levinriegner\craftcognitoauth\services\validators;

use Craft;
use craft\base\Component;
use craft\base\Field;
use craft\elements\User;
use craft\helpers\StringHelper;
use levinriegner\craftcognitoauth\CraftJwtAuth;
use levinriegner\craftcognitoauth\services\AbstractValidator;
use LightSaml\Credential\X509Certificate;
use LightSaml\Model\Assertion\Assertion;
use LightSaml\Model\Context\DeserializationContext;
use LightSaml\Model\Protocol\Response;

/**
 * @author    Levin-riegner
 * @package   CraftJwtAuth
 * @since     0.5.0
 */
class SAML extends AbstractValidator
{
 
    private $samlCert;
    private $attributesMap;

    public function __construct()
    {
        $this->samlCert = CraftJwtAuth::getInstance()->getSettings()->getSamlCert();
        $this->attributesMap = CraftJwtAuth::getInstance()->settingsService->get()->extra->samlAttributesMap;
    }

    /*
     * @return mixed
     */
    protected function getTokenFromRequest()
    {
        // Look for an access token in the settings
        $accessToken = Craft::$app->request->headers->get('authorization') ?: Craft::$app->request->headers->get('x-access-token');

        // If "Bearer " is present, strip it to get the token.
        if (StringHelper::startsWith($accessToken, 'SAML ')) {
            $accessToken = StringHelper::substr($accessToken, 5);
        }

        // If we find one, and it looks like a JWT...
        if ($accessToken) {
            return $accessToken;
        }

        return null;
    }

    /*
    * @return mixed
    */
    protected function parseToken($accessToken): Response
    {
        $accessToken = base64_decode($accessToken);
        $deserializationContext = new DeserializationContext();
        $deserializationContext->getDocument()->loadXML($accessToken);
        
        $samlResponse = new Response();
        $samlResponse->deserialize($deserializationContext->getDocument()->firstChild, $deserializationContext);

        return $samlResponse;
    }

    /*
    * @return mixed
    */
    protected function verifyToken($token)
    {
        $key = \LightSaml\Credential\KeyHelper::createPublicKey(
            X509Certificate::fromFile($this->samlCert)
        );

        $signatureReader = $token->getFirstAssertion()->getSignature();
        return $signatureReader->validate($key);
    }

    /*
    * @return mixed
    */
    protected function getUserByToken($token)
    {
        if ($this->verifyToken($token)) {
            $userName = $token->getFirstAssertion()->getSubject()->getNameID()->getValue();

            // Look for the user with email
            $user = Craft::$app->users->getUserByUsernameOrEmail($userName);

            return $user;
        }

        return null;
    }

    /*
    * @return mixed
    */
    protected function createUserByToken($token)
    {
        // Get relevant settings
        $autoCreateUser = CraftJwtAuth::getInstance()->getSettings()->getAutoCreateUser();

        if ($autoCreateUser) {
            // Create a new user and populate with claims
            $user = new User();
            foreach($this->attributesMap as $attributeKey => $attributeValue){
                foreach($token->getAllAssertions() as $assertion){
                    $this->assignProperty($user,
                    $attributeKey,
                    $attributeValue,
                    $assertion);
                }
            }

            $user->username = $this->lookupSamlNameId($token);

            // Attempt to save the user
            $success = Craft::$app->getElements()->saveElement($user);

            // If user saved ok...
            if ($success) {
                // Assign the user to the default public group
                Craft::$app->users->assignUserToDefaultGroup($user);

                return $user;
            }else
                Craft::dd($user->errors);
        }
        

        return null;
    }

    private function assignProperty(
        User $user,
        $craftProperty,
        $attributeValue,
        Assertion $assertion
    ) {


        if (is_callable($attributeValue)) {
            $attributeValue = call_user_func($attributeValue, $assertion);
        }else{
            Craft::warning($attributeValue);
            //Lookup in the current assertion
            $attributeValue = $this->lookupSamlProperty($assertion, $attributeValue);
        }

        if (is_string($attributeValue) && in_array($craftProperty, $user->attributes())) {
            $this->setSimpleProperty($user, $craftProperty, $attributeValue);
        }
    }

    private function lookupSamlNameId(Response $token){
        return $token->getFirstAssertion()->getSubject()->getNameID()->getValue();
    }

    private function lookupSamlProperty(Assertion $assertion, $attributeValue){
        foreach($assertion->getAllAttributeStatements() as $attrStatement){
            $attrValue = $attrStatement->getFirstAttributeByName($attributeValue) ? $attrStatement->getFirstAttributeByName($attributeValue)->getFirstAttributeValue() : null;
            if($attrValue){
                return $attrValue;
            }
        }
    }

    private function setSimpleProperty(User $user, $name, $value)
    {
        $field = $this->getFieldLayoutField($user, $name);

        Craft::warning(
            sprintf(
                '%s as %s. Is custom field? %s',
                $name,
                $value,
                $field instanceof Field ? $field->id : 'Nope'
            )
        );

        if (! is_null($field)) {
            //Custom field
            $user->setFieldValue($name, $value);
        } else {
            //Native field
            $user->{$name} = $value;
        }
    }

    protected function getFieldLayoutField(User $user, $fieldHandle)
    {
        $fieldLayout = $user->getFieldLayout();
        if (is_null($fieldLayout)) {
            return null;
        }

        return $fieldLayout->getFieldByHandle($fieldHandle);
    }
}
