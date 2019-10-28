# Changelog

All notable changes to this project will be documented in this file, in reverse chronological order by release.

## 0.1.0 - 2019-10-28

### Added

- Initial release

- Integrate cognito's user registation/confirmation, login, forgot password operations with Craft.

- Validate incoming requests with a Cognito JWT present in the Authentication headers.

- Match a validated Cognito JWT to a user account in Craft CMS and login as that user.

- Optionally create a new account if no existing account can be found.
