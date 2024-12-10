![WebAuthn Proxy Login Page](/assets/images/login.gif)

A standalone reverse-proxy to enforce Webauthn authentication. It can be inserted in front of sensitive services or even chained with other proxies (e.g. OAuth, MFA) to enable a layered security model.

Webauthn is a passwordless, public key authentication mechanism that allows the use of hardware-based authenticators such as Yubikey, Apple Touch ID or Windows Hello. You can learn more about Webauthn [here](https://webauthn.guide/).

## Goals
We specifically built this proxy to fit into our ecosystem and we hope that it might be useful for other teams. Our aim was to make a Webauthn module that was configurable and manageable using standard DevOps tools (in our case Docker and Ansible) and which could be easily inserted into our existing service deployments behind a reverse proxy like NGinx/OpenResty, and chained with other similar security proxies that we use such as [OAuth2 Proxy](https://github.com/oauth2-proxy/).


## Getting Started
First thing you will need to do is build the project. See instructions [below](#building) for building the Go code directly, or using Docker. It is also available on [on Dockerhub](https://hub.docker.com/r/quiq/webauthn_proxy) if you don't want to build it yourself.

By default the proxy will look for the config file `config.yml` and credentials file `credentials.yml` in
`config/`, which is `/opt/config` in the Docker image but you can also override this by setting the `WEBAUTHN_PROXY_CONFIGPATH` environment variable to another directory.

`credentials.yml` file is a simple YAML file with key-value pairs of username to credential. The credential is a base64 encoded JSON object which is output during the registration process. You can start with an empty credentials file until you've registered your first user.

Now you can start the proxy. See instructions [below](#running) for running it directly, or using Docker. Once it's started you can register a user by going to _http://localhost:8080/webauthn/register_ (assuming you used 8080 as the server port). Enter a username and then click _Register_. You will be prompted to select an authenticator to register, which is a browser dependent operation (see below). After following the prompts, you will be given a username/credential combination. You should add this entry to the credentials file and restart the proxy.

![WebAuthn Proxy Registration](/assets/images/register.gif)

After registration you can go to _http://localhost:8080/webauthn/login_ to log in. Enter the same username you registered and click _Login_. You will be prompted to provide your authenticator device. Again follow the prompts and you should be successfully authenticated.

At this point you have it running locally. To configure it to work in your environment you will need to configure your webserver or reverse-proxy to make calls to it in order to authenticate. You can use the `/webauthn/auth` endpoint to check if the caller is currently authenticated, and `/webauthn/login` (with optional `redirect_url` and `default_username` URL parameters) for the the user to login. See instructions [below](#using) for examples of configuration with NGinx and OpenResty.


## Supported Browsers and Authenticators
Firefox and Chrome have been tested and work well, there is some differences in their supported authentication methods. You can some helpful info [here](https://webauthn.me/browser-support) and [here](https://help.okta.com/en/prod/Content/Topics/Security/mfa-webauthn.htm). Note that you can register multiple different authenticators for a single user, which can be helpful for contingencies such as lost or broken devices.

Other browsers have not been tested but likely will function just fine if they support Webauthn; please feel free to open a pull request to this document with your own testing details.

## Running
#### Golang
```
go run .
WEBAUTHN_PROXY_CONFIGPATH=/path/to/config/ go run .
```

#### Docker
```
docker run --rm -ti -p 8080:8080 quiq/webauthn_proxy:latest
docker run --rm -ti -p 8080:8080 -v /path/to/config:/opt/config:ro quiq/webauthn_proxy:latest
```
To generate cookie secret to add to `credentials.yml`:
```
docker run --rm -ti quiq/webauthn_proxy:latest -generate-secret
<secret>
```

## Building yourself
#### Golang
```
go build -o webauthn_proxy . && chmod +x webauthn_proxy
./webauthn_proxy -v
```
Note, to run it elsewhere you will also need `config/` and `static/` dirs.

#### Docker
```
docker build -t webauthn_proxy:custom .
```

## Using
You can configure this as an authentication reverse-proxy using the sample configuration for NGinx or Openresty below. Other proxies and webservers haven't been tested currently but they should work and if you have done so please feel free to open a pull request to this document with details.

#### NGinx
```
location / {
        auth_request /webauthn/auth;
        error_page 401 = /webauthn/login?redirect_url=$uri;

        # ...
}

# WebAuthn Proxy.
location /webauthn/ {
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Host $host;
        proxy_pass http://127.0.0.1:8080;
}
```

#### OpenResty (example of chaining WebAuthn proxy with [OAuth2 Proxy](https://github.com/oauth2-proxy/oauth2-proxy))
```
location / {
        auth_request /oauth2/auth;

        # Get the email from oauth2 proxy to prepolulate with the redirect below
        auth_request_set $email $upstream_http_x_auth_request_email;
        error_page 401 = /oauth2/start?rd=$uri;
        access_by_lua_block {
                local http = require "resty.http"
                local h = http.new()
                h:set_timeout(5 * 1000)
                local url = "http://127.0.0.1:8080/webauthn/auth"
                ngx.req.set_header("X-Forwarded-Proto", ngx.var.scheme)
                ngx.req.set_header("Host", ngx.var.host)
                local res, err = h:request_uri(url, {method = "GET", headers = ngx.req.get_headers()})
                if err or not res or res.status ~= 200 then
                        # Redirect to webauthn login, with email as the default username
                        ngx.redirect("/webauthn/login?redirect_url=" .. ngx.var.request_uri .. "&default_username=" .. ngx.var.email)
                        ngx.exit(ngx.HTTP_OK)
                end
        }

        # ...
}

# OAuth2 Proxy.
location = /oauth2/auth {
        internal;
        proxy_pass http://127.0.0.1:4180;
}
location /oauth2/ {
        proxy_pass http://127.0.0.1:4180;
}

# WebAuthn Proxy.
location /webauthn/ {
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Host $host;
        proxy_pass http://127.0.0.1:8080;
}
```

## Important Configuration Options
All configuration options have a sensible default value and thus can be left off except `rpID` and `rpDisplayName`, which you must provide. There are a few important options that you should be aware though:

`rpDisplayName`: Can be anything you want, a descriptive name of the "relying party", usually organization name.

`rpID`: Should be set to the domain that your services operate under, for example if you want to secure your CI system and code repositories at _https://ci.example.com_ and _https://code.example.com_, you should set `rpID` to simply `example.com`. This will allow both sites to share the same set of credentials. **Note:** Credentials created while running the proxy with one `rpID` are not usable under another.

`rpOrigins`: If left empty, the proxy will dynamically allow requests to any origin, otherwise it will only allow the configured origins. For example, if you only want this proxy to support _https://ci.example.com_ and _https://code.example.com_, use the following configuration:
```
rpOrigins:
  - https://ci.example.com
  - https://code.example.com
```

Otherwise, if you wanted it to work for any service under _example.com_, you could simply leave `rpOrigins` out of your config.

`serverAddress`: The address the proxy should listen on. Typically this would be _127.0.0.1_ if you are running it locally or behind another webserver or proxy, or _0.0.0.0_ if you are running in Docker or wanted to expose it directly to the world.

`testMode`: By setting this value to `true`, a user will be able to authenticate immediately after they have registered without any intervention from a system administrator, until the proxy is restarted. This is useful for testing, but we highly recommend you set this property to `false` in production, otherwise users will be able to register themselves and then immediately authenticate.


## All Configuration Options
| Option | Description | Default |
| ------ | ----------- | ------- |
| **rpDisplayName** | Display name of relying party | MyCompany |
| **rpID** | ID of the relying party, usually the domain the proxy and callers live under | localhost |
| rpOrigins | Array of full origins used for accessing the proxy, including port if not 80/443, e.g. http://service.example.com:8080. | All Origins |
| serverAddress | Address the proxy server should listen on (usually 127.0.0.1 or 0.0.0.0) | 0.0.0.0 |
| serverPort | Port the proxy server should listen on | 8080 |
| sessionSoftTimeoutSeconds | Length of time logins are valid for, in seconds | 28800 (8 hours) |
| sessionHardTimeoutSeconds | Max length of logged in session, as calls to /webauthn/auth reset the session timeout | 86400 (24 hours) |
| sessionCookieName | Change the name of the session cookie | webauthn-proxy-session |
| userCookieName | Change the name of the username cookie | webauthn-proxy-username |
| testMode | When set to **_true_**, users can authenticate immediately after registering. Useful for testing, but generally not safe for production. | false |
| usernameRegex | Regex for validating usernames | ^.+$ |
| cookieSecure | When set to **_true_**, enables the Secure flag for cookies. Useful when running behind a TLS reverse proxy. | false |


## Thanks!
- Duo Labs: https://duo.com/labs
- Herbie Bolimovsky: https://www.herbie.dev/blog/webauthn-basic-web-client-server/
- Paul Hankin / icza:  https://stackoverflow.com/questions/22892120/how-to-generate-a-random-string-of-a-fixed-length-in-go
