(() => {
    'use strict';
    const root = document.getElementById('emergency');
    if (!root) return;
    const base = root.dataset.base;
    const csrf = root.querySelector('input[name="__RequestVerificationToken"]').value;
    const message = text => { document.getElementById('message').textContent = text; };
    const decode = text => Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - text.length % 4) % 4)), c => c.charCodeAt(0));
    const encode = buffer => btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    async function api(path, body = {}) {
        const response = await fetch(base + '/' + path, { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-Emergency-CSRF': csrf }, body: JSON.stringify(body), redirect: 'error' });
        const data = response.status === 204 ? {} : await response.json();
        if (!response.ok) throw new Error(data.error || 'Request failed');
        return data;
    }
    const safe = action => async event => {
        if (event) event.preventDefault();
        try { message('Working…'); await action(); } catch (error) { message(error.name === 'NotAllowedError' ? 'Key check cancelled. Preparation is not complete.' : error.message || 'Operation failed.'); }
    };
    function bind(id, action, event = 'click') { const element = document.getElementById(id); if (element) element.addEventListener(event, safe(action)); }
    async function database() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open('oidc-emergency-v1', 1);
            request.onupgradeneeded = () => request.result.createObjectStore('credentials', { keyPath: 'ec_id' });
            request.onsuccess = () => resolve(request.result); request.onerror = () => reject(new Error('Browser storage is unavailable.'));
        });
    }
    async function stored(write, record) {
        const db = await database();
        try {
            return await new Promise((resolve, reject) => {
                const tx = db.transaction('credentials', write ? 'readwrite' : 'readonly');
                const store = tx.objectStore('credentials');
                const request = write ? store.put(record) : store.getAll();
                tx.oncomplete = () => resolve(request.result); tx.onerror = tx.onabort = () => reject(new Error('Browser storage failed. Credential is not ready.'));
            });
        } finally { db.close(); }
    }
    function assertionOptions(options) {
        options.challenge = decode(options.challenge);
        options.allowCredentials.forEach(credential => credential.id = decode(credential.id));
        return options;
    }
    function assertionResponse(credential) {
        return { id: credential.id, rawId: encode(credential.rawId), type: credential.type, response: { clientDataJSON: encode(credential.response.clientDataJSON), authenticatorData: encode(credential.response.authenticatorData), signature: encode(credential.response.signature), userHandle: credential.response.userHandle ? encode(credential.response.userHandle) : null }, clientExtensionResults: credential.getClientExtensionResults() };
    }
    async function possession(record, login) {
        const prefix = login ? 'login' : 'possession';
        const challenge = await api(prefix + '/options', { emergency_credential: record.emergency_credential });
        const credential = await navigator.credentials.get({ publicKey: assertionOptions(challenge.publicKey) });
        const result = await api(prefix + '/complete', { transaction_id: challenge.transaction_id, credential: assertionResponse(credential) });
        if (login) { location.assign(result.redirect); return; }
        message('Ready. This browser and key can be used while emergency acceptance is on.');
        await list();
    }
    async function saveAndActivate(record) {
        const durable = navigator.storage && navigator.storage.persist ? await navigator.storage.persist() : false;
        document.getElementById('storage-warning').textContent = durable ? 'Persistent storage granted. Clearing site data still removes preparation.' : 'Persistent storage was not granted. Browser cleanup or eviction can remove preparation.';
        await stored(true, record);
        const readBack = (await stored(false)).find(item => item.ec_id === record.ec_id);
        if (!readBack || readBack.emergency_credential !== record.emergency_credential) throw new Error('Storage read-back failed. Credential is not ready.');
        message('Stored, pending possession. Check your key again to activate.');
        await possession(readBack, false);
    }
    bind('prepare', async () => {
        let enrollment;
        try {
            enrollment = await api('enrollments');
            const options = enrollment.publicKey;
            options.challenge = decode(options.challenge); options.user.id = decode(options.user.id);
            (options.excludeCredentials || []).forEach(credential => credential.id = decode(credential.id));
            const credential = await navigator.credentials.create({ publicKey: options });
            const record = await api('enrollments/' + encodeURIComponent(enrollment.enrollment_id) + '/complete', { credential: { id: credential.id, rawId: encode(credential.rawId), type: credential.type, response: { clientDataJSON: encode(credential.response.clientDataJSON), attestationObject: encode(credential.response.attestationObject), transports: credential.response.getTransports ? credential.response.getTransports() : [] }, clientExtensionResults: credential.getClientExtensionResults() } });
            enrollment = null;
            await saveAndActivate(record);
        } finally {
            if (enrollment) { try { await api('enrollments/' + encodeURIComponent(enrollment.enrollment_id) + '/cancel'); } catch (_) { } }
        }
    });
    function button(text, action) { const button = document.createElement('button'); button.type = 'button'; button.textContent = text; button.addEventListener('click', safe(action)); return button; }
    async function list() {
        const ul = document.getElementById('credentials');
        if (!ul) return;
        const records = await stored(false);
        const status = root.dataset.mode === 'prepare' ? await api('status') : null;
        ul.replaceChildren();
        for (const record of records) {
            const entry = status && status.credentials.find(item => item.ec_id === record.ec_id);
            if (status && !entry) continue;
            const row = document.createElement('li');
            row.textContent = 'Key ' + record.binding_id.slice(-6) + ' — ' + (entry ? entry.status : 'stored; server checks on use') + ' — expires ' + new Date(record.expires_at * 1000).toLocaleString() + ' ';
            if (root.dataset.mode === 'login') {
                if (record.expires_at * 1000 > Date.now()) row.append(button('Log in with this key', () => possession(record, true)));
            } else {
                if (entry.status === 'pending') row.append(button('Confirm stored credential', () => possession(record, false)));
                if (entry.status === 'active' && status.can_prepare) row.append(button('Renew with this key', async () => saveAndActivate(await api('renewals', { binding_id: record.binding_id }))));
                row.append(button('Remove key locally', async () => { await api('keys/' + encodeURIComponent(record.binding_id) + '/remove'); message('Key blocked locally. Any failed issuer report remains queued.'); await list(); }));
                const binding = document.createElement('p'); binding.textContent = 'Binding ID: ' + record.binding_id; row.append(binding);
            }
            ul.append(row);
        }
        if (!ul.children.length) { const empty = document.createElement('li'); empty.textContent = 'This browser has no matching stored credential. Preparation requires a normal login.'; ul.append(empty); }
    }
    async function operatorStatus() {
        const status = await api('operator/status');
        document.getElementById('operator-controls').hidden = false;
        document.getElementById('operator-state').textContent = 'Acceptance: ' + (status.accepting ? 'on' : 'off') + '. Last successful sync: ' + (status.last_poll ? new Date(status.last_poll * 1000).toLocaleString() : 'never') + '. Queued removals: ' + status.queued_removals;
        const audit = document.getElementById('audit'); audit.replaceChildren();
        status.audit.slice().reverse().forEach(text => { const item = document.createElement('li'); item.textContent = text; audit.append(item); });
    }
    bind('operator-signin', async () => { const input = document.getElementById('operator-secret'); const secret = input.value; input.value = ''; await api('operator/signin', { secret }); location.reload(); }, 'submit');
    bind('accept-on', async () => { await api('operator/acceptance', { enabled: true, minutes: Number(document.getElementById('minutes').value) }); location.reload(); });
    bind('accept-off', async () => { await api('operator/acceptance', { enabled: false, minutes: 0 }); location.reload(); });
    bind('block', async () => { await api('operator/block', { binding_id: document.getElementById('binding').value, whole_account: document.getElementById('whole-account').checked }); message('Blocked locally.'); await operatorStatus(); });
    bind('poll', async () => { await api('operator/poll'); await operatorStatus(); message('Online synchronization completed.'); });
    bind('operator-signout', async () => { await api('operator/signout'); location.reload(); });
    bind('signout', async () => { const result = await api('signout'); location.assign(result.redirect); });
    if (root.dataset.mode === 'prepare' || (root.dataset.mode === 'login' && root.dataset.accepting === 'true')) safe(list)();
    if (root.dataset.mode === 'operator' && !document.getElementById('operator-controls').hidden) safe(operatorStatus)();
})();
