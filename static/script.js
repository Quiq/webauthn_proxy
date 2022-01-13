let errorMessage = message => {
    $('#errorMessages').text(message);
    $('#successMessages').text('');
};

let successMessage = message => {
    $('#errorMessages').text('');
    $('#successMessages').text(message);
};

let preformattedMessage = message => {
    $('#preformattedMessages').text(message);
};

let browserCheck = () => {
    if (!window.PublicKeyCredential) {
        errorMessage('This browser doesn\'t support WebAuthn');
        return false;
    }

    return true;
};

let bufferDecode = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));

let bufferEncode = value => btoa(String.fromCharCode.apply(null, new Uint8Array(value)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");

let formatFinishRegParams = cred => JSON.stringify({
    id: cred.id,
    rawId: bufferEncode(cred.rawId),
    type: cred.type,
    response: {
        attestationObject: bufferEncode(cred.response.attestationObject),
        clientDataJSON: bufferEncode(cred.response.clientDataJSON),
    },
});

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
            errorMessage(error.responseJSON.Message);
        });
};

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
            errorMessage(error.responseJSON.Message);
        });
};