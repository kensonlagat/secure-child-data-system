// Record edit form: sends a JSON PATCH with only the fields the user changed.
// Moved out of records/edit.html so the page has no inline script. The logic is
// unchanged, except that each field's original value now comes from the HTML
// value attribute (defaultValue / defaultSelected) instead of a data-initial-value
// attribute, so sensitive values are not duplicated into data-* attributes.
(() => {
    const form = document.getElementById('record-edit-form');
    const messageBox = document.getElementById('form-message');
    if (!form || !messageBox) {
        return;
    }
    const patchUrl = form.dataset.patchUrl;
    const backUrl = form.dataset.backUrl;

    const initialValue = (element) => {
        if (element.tagName === 'SELECT') {
            const option = Array.from(element.options).find((item) => item.defaultSelected);
            return option ? option.value : '';
        }
        return element.defaultValue;
    };

    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        messageBox.className = 'notice';
        messageBox.hidden = false;
        messageBox.textContent = 'Saving...';

        const payload = {};
        for (const element of form.elements) {
            if (!element.name) {
                continue;
            }

            if (element.tagName === 'SELECT' || element.type === 'text' || element.type === 'date' || element.type === 'number') {
                if (element.value === initialValue(element)) {
                    continue;
                }

                if (element.type === 'number') {
                    payload[element.name] = element.value === '' ? null : Number(element.value);
                } else {
                    payload[element.name] = element.value;
                }
            }
        }

        const response = await fetch(patchUrl, {
            method: 'PATCH',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            },
            body: JSON.stringify(payload),
        });

        const data = await response.json().catch(() => ({}));
        if (response.ok) {
            messageBox.className = 'notice success';
            messageBox.hidden = false;
            messageBox.textContent = data.message || 'Record updated successfully.';
            window.setTimeout(() => {
                window.location.href = backUrl;
            }, 500);
            return;
        }

        messageBox.className = 'notice error';
        messageBox.hidden = false;
        messageBox.textContent = data.error || 'Update failed.';
        if (Array.isArray(data.rejected_fields) && data.rejected_fields.length) {
            messageBox.textContent = `${messageBox.textContent} Rejected fields: ${data.rejected_fields.join(', ')}.`;
        }
    });
})();
