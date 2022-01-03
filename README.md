## Goals
The goal of this project is to create a standalone proxy to enforce Webauthn authentication. It can be inserted in front of sensitive services or even chained with other proxies (e.g. OAuth, MFA) to enable a layered security model. 

Webauthn is a passwordless, public key authentication mechanism that allows the use of hardware-based authenticators such as Yubikey, Apple Touch ID or Windows Hello. You can learn more about Webauthn [here](https://webauthn.guide/). 

We specifically built this proxy to fit into our ecosystem and we hope that it might be useful for other teams. Our aim was to make a Webauthn module that was configurable and manageable using standard DevOps tools (in our case Docker and Ansible) and which could be easily inserted into our existing service deployments behind a reverse proxy like NGinx/OpenResty, and chained with other similar security proxies that we use.


## Getting Started
First thing you will need to do is build the project. You can use the provided dockerfile to build an image, or directly in Go using the instructions below.

Next, copy the `config.yml` file from the `sample_config` directory and modify it to meet your needs. By default the proxy will look for this file in `/opt/webauthn_proxy` but you can override this by setting the `WEBAUTHN_PROXY_CONFIGPATH` environment variable to the directory where you've stored the file. 

You will also need a `credentials.yml` file, which is a simple YAML file with key-value pairs of username to credential. The credential is a base64 encoded JSON object which is output during the registration process. You can start with an empty credentials file until you've registered your first user, the path to this file is one of the values in `config.yml`. 

_**Important Note**_: One of the most critical properties in the config is `enableFullRegistration`. By setting this value to `true`, a user will be able to authenticate immediately after they have registered without any intervention from a system administrator (until the proxy is restarted). This is useful for testing, but we highly recommend you set this property to `false` in production.

Once the proxy is started you can register a user by going to _http://localhost:8080/register.html_ (assuming you used 8080 as the server port). Enter a username and then click _Register_. You will be prompted to authenticate, which is a browser dependent operation (see below). After following the prompts, you will be given a username and credential combination to add to your credentials file. You should add this entry and then restart the proxy, there is no way to hot-reload it at the moment.

You can configure this as an authentication proxy using the sample configuration for NGinx or Openresty below. Other proxies and webservers haven't been tested currently but they should work and if you have done so please feel free to open a pull request to this document with details.


## Supported Browsers and Authenticators
Currently, Chrome supports Yubikey, Apple Touch ID, Android Phones via push notification, and potentially other mechanisms such as Windows Hello. Firefox only supports Yubikey at the current time. Other browsers have not been tested but likely will function just fine if they support Webauthn; please feel free to open a pull request to this document with your own testing details.


## Building 
### Golang
`go build -o webauthn_proxy && chmod +x webauthn_proxy`

### Docker
`docker build -t webauthn_proxy:latest .`


## Running 
### Golang 
`WEBAUTHN_PROXY_CONFIGPATH=${PWD} ./webauthn_proxy`

### Docker
`docker run -p 8080:8080 -it -v /path/to/webauthn_proxy/config.yml:/opt/webauthn_proxy/config.yml -v /path/to/webauthn_proxy/credentials.yml:/opt/webauthn_proxy/credentials.yml webauthn_proxy:latest`


## Authentication Proxy
### NGinx
```
location / {
        auth_request /webauthn/auth;
        error_page 401 = /webauthn/login?redirect_url=$uri;

        # ... 
}

# WebAuthn Proxy.
location = /webauthn/auth {
        internal;
        proxy_pass http://127.0.0.1:8080;
}
location /webauthn/ {
        proxy_pass http://127.0.0.1:8080;
}
```

### OpenResty (example of chaining WebAuthn proxy with [OAuth2 Proxy](https://github.com/oauth2-proxy/oauth2-proxy))
```
location / {
        auth_request /oauth2/auth;
        error_page 401 = /oauth2/start?rd=$uri;  
        access_by_lua_block {
                local http = require "resty.http"
                local h = http.new()
                h:set_timeout(5 * 1000)
                local url = "http://127.0.0.1:8080/webauthn/auth"
                local res, err = h:request_uri(url, {method = "GET", headers = ngx.req.get_headers()})
                if err or not res or res.status ~= 200 then
                        ngx.log(ngx.ERR, "Webauthn status: " .. res.status .. " ... redirecting.")
                        ngx.redirect("/webauthn/login?redirect_url=" .. ngx.var.request_uri)
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
```


## Configuration Elements
| Element | Description |
| ------- | ----------- |
| credentialFile | Path and filename for where credentials are stored |
| enableFullRegistration | Whether registered users can authenticate immediately or if admin needs to copy credential to the cred file and restart proxy first |
| rpDisplayName | Display name of relying party |
| rpID | ID of relying party, should be set to the hostname used for accessing the proxy |
| serverAddress | Address the proxy server should listen on (usually localhost or 0.0.0.0) |
| serverPort | Port the proxy server should listen on |
| sessionLengthSeconds | Length of time logins are valid for, in seconds | 
| staticPath | Path on disk to static assets | 
| usernameRegex | Regex for validating usernames | 


## Thanks! 
- Herbie Bolimovsky: https://www.herbie.dev/blog/webauthn-basic-web-client-server/
- Paul Hankin / icza:  https://stackoverflow.com/questions/22892120/how-to-generate-a-random-string-of-a-fixed-length-in-go

