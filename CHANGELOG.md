## Changelog

### 0.2 (2024-12-11)

* Add new config options `userCookieName`, `sessionCookieName`, `cookieSecure` to customize cookie names.
* Update Go version, alpine and all dependencies.

### 0.1 (2024-04-17)

* Upgrade Go version to 1.22.2, alpine to 3.19 and other dependencies.
* Disable unnecessary 1Password auto-filling.

### 0.0.4 (2023-02-22)

* Upgrade Go version to 1.19.6, alpine to 3.16 and other dependencies.
* Switch from `github.com/duo-labs/webauthn` to `github.com/go-webauthn/webauthn`
* Implement better logging.
* Build multiarch Docker image including ARM now.
* Make cookie secrets configurable in credentials.yml so sessions can persist proxy restarts.
* Static files are now only served from `/webauthn/static/` and no directory index available.
* Add cmd flags to generate cookie secrets, enable debug logging etc.
* Credentials are now stored in `credentials.yml` by default in the same folder as `config.yml`.
  Remove config variable for it. Both, `config.yml` and `credentials.yml` are expected in the relative
  `config/` dir or the dir defined as the env var `WEBAUTHN_PROXY_CONFIGPATH` as previously.
* Better usability to quickly run w/o any config changes.
* Forbid storing credentials under the wrong user. Email should match credentials login name.
* Endpoint `/webauthn/auth` will now return `X-Authenticated-User` header to know who authenticated and
  to use that information further in nginx config for whatever purpose.
* Add `/webauthn/logout` endpoint, basically deletes the session cookie.
* Add `/webauthn/verify` endpoint to perform user authentication verification.
* Improve login page and redirect from any invalid path to the login page including /
  Useful as a 2FA check for external systems.
  For example, call to `http://localhost:8080/webauthn/verify?username=email@example.com&ip=127.0.0.1`
  returns ok if user is authenticated within the past 5 min. Also you need to specify IP address from where user did that. It doesn't have anything to do with the cookie session. It can be called from an external system.
  Once verified it can't be verified again. If IP mismatches nothing will happen but the result fails to verify.
* Store last logged username into a separate cookie, other minor tweaks for convenience.
* Fix session expiration by the hard limit.
* Fix JS decoding error after switching to `github.com/go-webauthn/webauthn` and messages for other JS errors.
* Compatibility with Chrome, Firefox and Safari. However, Touch ID only works in Chrome.

### 0.0.3 (2022-06-30)

* Initial public version.
