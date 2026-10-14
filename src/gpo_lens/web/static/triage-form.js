// Save a triage decision without leaving the page, so a refused note (for
// example one that carries a GPP cpassword) stays in the form to be edited:
// the server never echoes refused text back. Kept as an external script
// because the CSP forbids inline JS. Without JavaScript the form posts
// normally and a refusal is a plain 400 page.
(function () {
    if (!window.fetch || !window.FormData || !window.URLSearchParams) {
        return;
    }
    var GENERIC = 'The decision could not be saved. Try again.';

    function show(form, message) {
        var box = form.querySelector('.gp-triage-error');
        if (!box) {
            return;
        }
        box.textContent = message;
        box.hidden = false;
    }

    function messageFrom(resp, text) {
        var type = resp.headers.get('content-type') || '';
        var body = (text || '').trim();
        // Plain-text refusals are shown as sent; anything else (an HTML error
        // page, an empty body) gets a generic line with the status.
        if (!body || body.charAt(0) === '<' || type.indexOf('json') !== -1) {
            return GENERIC + ' (HTTP ' + resp.status + ')';
        }
        return body;
    }

    var forms = document.querySelectorAll('form.gp-triage-form');
    for (var i = 0; i < forms.length; i++) {
        forms[i].addEventListener('submit', function (event) {
            event.preventDefault();
            var form = this;
            var button = form.querySelector('button[type="submit"]');
            var box = form.querySelector('.gp-triage-error');
            if (box) {
                box.hidden = true;
                box.textContent = '';
            }
            if (button) {
                button.disabled = true;
            }
            fetch(form.action, {
                method: 'POST',
                body: new URLSearchParams(new FormData(form)),
                credentials: 'same-origin',
                redirect: 'follow'
            }).then(function (resp) {
                if (resp.ok) {
                    window.location.assign(resp.url);
                    return null;
                }
                return resp.text().then(function (text) {
                    show(form, messageFrom(resp, text));
                });
            }).catch(function () {
                show(form, GENERIC);
            }).then(function () {
                if (button) {
                    button.disabled = false;
                }
            });
        });
    }
})();
