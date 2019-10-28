# Craft Cognito Auth plugin

Enable authentication to Craft through the use of [AWS Cognito](https://aws.amazon.com/cognito/).

![Screenshot](resources/img/plugin-logo.png)

## Requirements

This plugin requires Craft CMS 3.3 or later.

## Installation

To install the plugin, follow these instructions.

1.  Open your terminal and go to your Craft project:

    cd /path/to/project

2.  Then tell Composer to load the plugin:

    composer require levinriegner/craft-cognito-auth

3.  In the Control Panel, go to Settings → Plugins and click the “Install” button for Craft Cognito Auth.

## Craft Cognito Auth Overview

From the [official website](https://jwt.io/):

    JSON Web Tokens are an open, industry standard RFC 7519 method for representing claims securely between two parties.

This plugin enables requests to Craft to be securely authenticated in the presence of a Cognito JWT that can be successfully verified as matching a JWKS signature.

## Configuring Craft Cognito Auth

Once installed, naviate to the settings page of the plugin and enter required settings to activate the plugin:

| Setting                    | Description                                                                                 |
| -------------------------- | ------------------------------------------------------------------------------------------- |
| `Auto create user`         | Optional. Activate to enable auto-creation of a public user when provided a verifiable JWT. |
| `AWS Cognito region`       | Mandatory. AWS cognito region.                                                              |
| `AWS Cognito app client id`| Mandatory. AWS Cognito app client id (under App integration -> app client settings).        |
| `AWS Cognito user pool id` | Mandatory. AWS Cognito user pool id (under General settings).                               |
| `JSON Web Key Set URL`     | Mandatory. JSON Web Key Set URL (JWKS), used for verifying incoming Cognito JWTs.           |

## Configuring AWS Cognito

This plugin asumes AWS Cognito is configured so that [users sign up / sign in with email instead of username](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html#user-pool-settings-aliases-settings-option-2) and that the App client being used has the sign-in API for server-based authentication (ADMIN_NO_SRP_AUTH) enabled as stated in the [AWS docs](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-authentication-flow.html?icmpid=docs_cognito_console#amazon-cognito-user-pools-server-side-authentication-flow)

## Using Craft Cognito Auth

The plugin will attempt to verify any incoming requests with a JWT present in the `Authentication` header with a `Bearer` prefix, or with the simpler `X-Access-Token` header value. An example:

```shell
# With Authorization: Bearer
curl --header "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o" MYCRAFTSITE.com

# With X-Access-Token
curl --header "X-Access-Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o" MYCRAFTSITE.com
```

The plugin will attempt to verify the token using the [lcobucci/jwt](https://github.com/lcobucci/jwt) package for PHP. The package adheres to the [IANA specifications](https://www.iana.org/assignments/jwt/jwt.xhtml) for JWTs.

If a provided token can be verified AND can be match to a user account with a username matching the provided `sub` key, the user will be authenticated and the request allowed to continue.

If the token is verifiable but a matching user account does NOT exist, but the `Auto create user` setting is enabled AND public registration is enabled in the Craft settings, a new user account will be created on-the-fly and the new user then logged in.

This plugin provides example templates for you to use as a reference when building out your authentication solution. The example templates can by found in the vendor/levinriegner/craft-cognito-auth/templates/ folder, and can be copied to your projects top level templates/ folder.
