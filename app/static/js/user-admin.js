// Safeguarding lead flag on the Users page (#47, #30). Requests an OTP for the acting
// administrator, then confirms it in a dialog. The server enforces every rule (admin only,
// OTP, never your own account); this script only drives the two JSON calls. The CSRF
// header is added by csrf.js.
(() => {
    const dialog = document.getElementById('safeguarding-dialog');
    const form = document.getElementById('safeguarding-form');
    const otpInput = document.getElementById('safeguarding-otp');
    const cancel = document.getElementById('safeguarding-cancel');
    const messageBox = document.getElementById('user-action-message');
    if (!dialog || !form || !messageBox) {
        return;
    }
    let pending = null;

    const show = (kind, text) => {
        messageBox.hidden = false;
        messageBox.className = `notice ${kind}`;
        messageBox.textContent = text;
    };

    const postJson = async (url, payload) => {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            body: JSON.stringify(payload),
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
            throw new Error(data.error || 'Request failed.');
        }
        return data;
    };

    document.querySelectorAll('[data-safeguarding-user]').forEach((button) => {
        button.addEventListener('click', async () => {
            const userId = button.dataset.safeguardingUser;
            const value = button.dataset.safeguardingValue === 'true';
            button.disabled = true;
            try {
                await postJson(`/admin/users/${userId}/safeguarding-lead/request`, { value });
                pending = { userId, value };
                otpInput.value = '';
                dialog.showModal();
                otpInput.focus();
            } catch (error) {
                show('error', error.message);
            } finally {
                button.disabled = false;
            }
        });
    });

    cancel.addEventListener('click', () => {
        pending = null;
        dialog.close();
    });

    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        if (!pending) {
            dialog.close();
            return;
        }
        try {
            await postJson(`/admin/users/${pending.userId}/safeguarding-lead/confirm`, {
                value: pending.value,
                otp_code: otpInput.value.trim(),
            });
            dialog.close();
            show('success', 'Safeguarding lead updated.');
            window.setTimeout(() => window.location.reload(), 600);
        } catch (error) {
            dialog.close();
            show('error', error.message);
        } finally {
            pending = null;
        }
    });
})();
