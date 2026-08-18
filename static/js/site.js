// Bootstrap 5 Theme Switcher - Simple Light/Dark Toggle
(() => {
  'use strict';

  const getStoredTheme = () => localStorage.getItem('theme');
  const setStoredTheme = theme => localStorage.setItem('theme', theme);

  const getPreferredTheme = () => {
    try {
      const storedTheme = getStoredTheme();
      if (storedTheme) {
        return storedTheme;
      }
    } catch (e) {
      if (e instanceof DOMException && e.name === "SecurityError") {
        // Safely ignore if access to localStorage is denied.
      } else {
        throw e;
      }
    }
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  };

  const setTheme = theme => {
    document.documentElement.setAttribute('data-bs-theme', theme);
  };

  setTheme(getPreferredTheme());

  window.addEventListener('DOMContentLoaded', () => {
    const themeToggle = document.querySelector('#theme-toggle');
    if (!themeToggle) return;

    const updateToggleIcon = (theme) => {
      const icon = themeToggle.querySelector('i');
      if (icon) {
        if (theme === 'dark') {
          icon.className = 'bi bi-moon-stars-fill';
        } else {
          icon.className = 'bi bi-sun-fill';
        }
      }
    };

    updateToggleIcon(getPreferredTheme());

    themeToggle.addEventListener('click', () => {
      const currentTheme = getStoredTheme() || getPreferredTheme();
      const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
      setStoredTheme(newTheme);
      setTheme(newTheme);
      updateToggleIcon(newTheme);
    });
  });
})();

// Message display functions for Bootstrap alerts
let errorMessage = message => {
    $('#errorMessages').text(message).removeClass('d-none');
    $('#successMessages').addClass('d-none');
};

let successMessage = message => {
    $('#successMessages').text(message).removeClass('d-none');
    $('#errorMessages').addClass('d-none');
};

let preformattedMessage = message => {
    $('#preformattedMessages').val(message);
};

// Browser WebAuthn support check
let browserCheck = () => {
    if (!window.PublicKeyCredential) {
        errorMessage('This browser does not support WebAuthn :(');
        return false;
    }

    return true;
};

// Base64url encoding/decoding utilities
// base64url > base64 > Uint8Array > ArrayBuffer
let bufferDecode = value => Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0))
    .buffer;

// ArrayBuffer > Uint8Array > base64 > base64url
let bufferEncode = value => btoa(String.fromCharCode.apply(null, new Uint8Array(value)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");

// Format registration parameters for API
let formatFinishRegParams = cred => JSON.stringify({
    id: cred.id,
    rawId: bufferEncode(cred.rawId),
    type: cred.type,
    response: {
        attestationObject: bufferEncode(cred.response.attestationObject),
        clientDataJSON: bufferEncode(cred.response.clientDataJSON),
    },
});

// Format login parameters for API
let formatFinishLoginParams = assertion => JSON.stringify({
    id: assertion.id,
    rawId: bufferEncode(assertion.rawId),
    type: assertion.type,
    response: {
        authenticatorData: bufferEncode(assertion.response.authenticatorData),
        clientDataJSON: bufferEncode(assertion.response.clientDataJSON),
        signature: bufferEncode(assertion.response.signature),
        userHandle: bufferEncode(assertion.response.userHandle),
    }
});

// WebAuthn registration flow
let registerUser = () => {
    let username = $('#username').val();

    if (username === '') {
        errorMessage('Please enter a valid username');
	    return;
    }

	$.get(
        '/webauthn/register/get_credential_creation_options?username=' + encodeURIComponent(username),
        null,
        data => data,
        'json')
        .then(credCreateOptions => {
            credCreateOptions.publicKey.challenge = bufferDecode(credCreateOptions.publicKey.challenge);
            credCreateOptions.publicKey.user.id = bufferDecode(credCreateOptions.publicKey.user.id);
            if (credCreateOptions.publicKey.excludeCredentials) {
                for (cred of credCreateOptions.publicKey.excludeCredentials) {
                    cred.id = bufferDecode(cred.id);
                }
            }

            return navigator.credentials.create({
                publicKey: credCreateOptions.publicKey
            });
        })
        .then(cred => $.post(
            '/webauthn/register/process_registration_attestation?username=' + encodeURIComponent(username),
            formatFinishRegParams(cred),
            data => data,
            'json'))
        .then(success => {
            successMessage(success.Message);
            preformattedMessage(success.Data);
        })
        .catch(error => {
            if(error.hasOwnProperty("responseJSON")){
                errorMessage(error.responseJSON.Message);
            } else {
                errorMessage(error);
            }
        });
};

// WebAuthn authentication flow
let authenticateUser = () => {
    let username = $('#username').val();
    if (username === '') {
        errorMessage('Please enter a valid username');
        return;
    }

    $.get(
        '/webauthn/login/get_credential_request_options?username=' + encodeURIComponent(username),
        null,
        data => data,
        'json')
        .then(credRequestOptions => {
            credRequestOptions.publicKey.challenge = bufferDecode(credRequestOptions.publicKey.challenge);
            credRequestOptions.publicKey.allowCredentials.forEach(listItem => {
              listItem.id = bufferDecode(listItem.id)
            });

            return navigator.credentials.get({
              publicKey: credRequestOptions.publicKey
            });
        })
        .then(assertion => $.post(
            '/webauthn/login/process_login_assertion?username=' + encodeURIComponent(username),
            formatFinishLoginParams(assertion),
            data => data,
            'json'))
        .then(success => {
            successMessage(success.Message);
            window.location.reload();
        })
        .catch(error => {
            if(error.hasOwnProperty("responseJSON")){
                errorMessage(error.responseJSON.Message);
            } else {
                errorMessage(error);
            }
        });
};
