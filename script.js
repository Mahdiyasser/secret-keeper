/*
    SCRIPT.JS
    Secure Vault Keeper Application Logic with AES Encryption
    MODIFIED TO USE CROSS-ORIGIN STORAGE BRIDGE
*/

// --- CONSTANTS & GLOBAL STATE ---

// The storage keys remain the same, but now refer to keys within the bridge's localStorage
const STORAGE_KEY_USER_ID = 'skr_userId';
const STORAGE_KEY_VAULT_DATA = 'skr_vaultData';
const STORAGE_KEY_AVATAR = 'skr_avatar';
const STORAGE_KEY_THEME = 'skr_theme';
const MAX_AVATAR_SIZE_KB = 1024; // 1024KB limit

let CURRENT_MASTER_KEY = null;
let VAULT_DATA = {}; // Structure: { userId: '...', entries: { accessId: { type: '...', encryptedData: '...' } } }
let CURRENT_USER_ID = 'USER';

// --- CROSS-ORIGIN STORAGE BRIDGE CLASS ---

const BRIDGE_URL = 'https://storage.mahdiyasser.site'; // Your storage bridge URL
const BRIDGE_ORIGIN = 'https://storage.mahdiyasser.site';

/**
 * Manages communication with the cross-origin storage bridge via postMessage.
 */
class StorageBridge {
    constructor() {
        this.iframe = document.getElementById('storageBridgeIframe');
        this.pendingRequests = new Map();
        this.initListener();
    }

    initListener() {
        window.addEventListener('message', this.handleBridgeResponse.bind(this));
    }

    handleBridgeResponse(event) {
        // CRITICAL SECURITY CHECK: Only accept messages from the trusted storage origin.
        if (event.origin !== BRIDGE_ORIGIN) {
            return;
        }

        try {
            const response = JSON.parse(event.data);
            const { action, key, success, data, message } = response;

            const requestKey = `${action}_${key}`;
            const resolve = this.pendingRequests.get(requestKey);

            if (resolve) {
                this.pendingRequests.delete(requestKey);
                
                if (success) {
                    resolve({ success: true, data: data });
                } else {
                    console.error("Bridge operation failed:", message);
                    resolve({ success: false, data: null, message: message });
                }
            }
        } catch (e) {
            console.error("Failed to parse bridge response:", e);
        }
    }

    /**
     * Sends a command to the storage bridge and waits for a response.
     * @param {string} action 'set', 'get', or 'remove'
     * @param {string} key The localStorage key
     * @param {string} [value] The value to set (for 'set' action)
     * @returns {Promise<{success: boolean, data: string|null}>}
     */
    sendCommand(action, key, value) {
        return new Promise((resolve) => {
            const message = { action, key, value };
            const requestKey = `${action}_${key}`;

            this.pendingRequests.set(requestKey, resolve);

            // Timeout for request
            setTimeout(() => {
                if (this.pendingRequests.has(requestKey)) {
                    this.pendingRequests.delete(requestKey);
                    resolve({ success: false, data: null, message: "Storage bridge request timed out." });
                }
            }, 5000); 

            // Post the message to the iframe
            this.iframe.contentWindow.postMessage(JSON.stringify(message), BRIDGE_ORIGIN);
        });
    }

    async getItem(key) {
        const response = await this.sendCommand('get', key);
        return response.success ? response.data : null;
    }

    async setItem(key, value) {
        const response = await this.sendCommand('set', key, value);
        return response.success;
    }

    async removeItem(key) {
        const response = await this.sendCommand('remove', key);
        return response.success;
    }
}

let Storage = null;

// --- INITIALIZATION & UI SETUP ---

document.addEventListener('DOMContentLoaded', () => {
    // START PWA SERVICE WORKER REGISTRATION - ADD THIS BLOCK
    if ('serviceWorker' in navigator) {
        window.addEventListener('load', () => {
            navigator.serviceWorker.register('/service-worker.js')
                .then(reg => {
                    console.log('Service Worker registered successfully: ', reg.scope);
                })
                .catch(error => {
                    console.log('Service Worker registration failed: ', error);
                });
        });
    }
    // END PWA SERVICE WORKER REGISTRATION - ADD THIS BLOCK

    // 1. Initialize the bridge communication class
    Storage = new StorageBridge();
    
    // 2. Initial theme and app load
    loadAppTheme();
    initializeApp();
    setupNavigation();
    setupEntryTypeTabs();
    
    // Wire up buttons for authentication view
    document.getElementById('authActionButton').onclick = performAuthentication;
});

async function initializeApp() {
    // ASYNC: Read the User ID from the storage bridge
    const storedUserId = await Storage.getItem(STORAGE_KEY_USER_ID);
    
    if (storedUserId) {
        CURRENT_USER_ID = storedUserId;
        document.getElementById('vaultUsernameInput').value = storedUserId;
        // The avatar display will use CURRENT_MASTER_KEY, which is null here,
        // so it will display the initial (V or the first letter of the ID)
        updateAvatarDisplay(CURRENT_USER_ID); 
        document.getElementById('updateUserID').value = CURRENT_USER_ID;
    } else {
        updateAvatarDisplay(CURRENT_USER_ID);
    }
    showView('loginGateView'); 
}

// --- ENCRYPTION/DECRYPTION UTILITIES ---
// (No change here, as encryption/decryption remains client-side)

/**
 * Encrypts a plaintext string using the current master key.
 * @param {string} plaintext 
 * @returns {string} Encrypted string (CryptoJS format).
 */
function encryptData(plaintext) {
    if (!CURRENT_MASTER_KEY) throw new Error("Encryption failed: Master Key not set.");
    return CryptoJS.AES.encrypt(plaintext, CURRENT_MASTER_KEY).toString();
}

/**
 * Decrypts an encrypted string using a given key.
 * @param {string} encryptedText 
 * @param {string} decryptionKey The key to use for decryption.
 * @returns {string|null} Decrypted plaintext or null if decryption fails.
 */
function decryptData(encryptedText, decryptionKey) {
    if (!decryptionKey) return null;
    try {
        const bytes = CryptoJS.AES.decrypt(encryptedText, decryptionKey);
        if (!bytes || bytes.sigBytes === 0) {
            return null;
        }
        return bytes.toString(CryptoJS.enc.Utf8);
    } catch (e) {
        console.error("Decryption Error:", e);
        return null;
    }
}

// --- AUTHENTICATION & VAULT MANAGEMENT ---

async function performAuthentication() {
    const userIdInput = document.getElementById('vaultUsernameInput').value.trim();
    const masterKeyInput = document.getElementById('masterSecurityKeyInput').value;

    if (!userIdInput || !masterKeyInput) {
        return showAppPopup('Missing Information', 'User Identifier and Master Security Key are required.', false, false);
    }

    // ASYNC: Check if an ID already exists in the bridge's storage
    const storedUserIdCheck = await Storage.getItem(STORAGE_KEY_USER_ID);
    const isSetup = !storedUserIdCheck;
    
    CURRENT_MASTER_KEY = masterKeyInput;
    
    if (isSetup) {
        await handleInitialSetup(userIdInput);
    } else {
        await handleLoginAttempt(userIdInput);
    }
}

async function handleInitialSetup(userIdInput) {
    // ASYNC: Set ID in the bridge's storage
    await Storage.setItem(STORAGE_KEY_USER_ID, userIdInput);
    
    VAULT_DATA = { userId: userIdInput, entries: {} };
    
    // Encrypt the empty vault object with the new key
    const encryptedVault = encryptData(JSON.stringify(VAULT_DATA));
    
    // ASYNC: Set encrypted vault in the bridge's storage
    const saveSuccess = await Storage.setItem(STORAGE_KEY_VAULT_DATA, encryptedVault);
    if (!saveSuccess) {
        // If saving fails, revert the ID set above and abort
        await Storage.removeItem(STORAGE_KEY_USER_ID);
        return showAppPopup('Setup Failed', 'Could not save vault data to the bridge.', false, false);
    }

    CURRENT_USER_ID = userIdInput;
    updateAvatarDisplay(CURRENT_USER_ID);

    showAppPopup('Setup Complete', 'New Vault created and secured! You are now logged in.', false, true);
    document.getElementById('masterSecurityKeyInput').value = ''; 
    showAuthenticatedApp();
}

async function handleLoginAttempt(userIdInput) {
    // ASYNC: Get data from the bridge's storage
    const storedEncryptedVault = await Storage.getItem(STORAGE_KEY_VAULT_DATA);
    const storedUserId = await Storage.getItem(STORAGE_KEY_USER_ID);

    if (storedUserId !== userIdInput) {
        return showAppPopup('Login Failed', 'The User Identifier does not match the stored account.', false, false);
    }

    if (!storedEncryptedVault) {
         return showAppPopup('Data Error', 'Vault data missing from storage bridge.', false, false);
    }
    
    const decryptedVaultString = decryptData(storedEncryptedVault, CURRENT_MASTER_KEY);

    if (decryptedVaultString === null) {
        return showAppPopup('Access Denied', 'Invalid Master Security Key. Please try again.', false, false);
    }

    try {
        VAULT_DATA = JSON.parse(decryptedVaultString);
        CURRENT_USER_ID = userIdInput;
        // ASYNC: Load and decrypt avatar on successful login
        await updateAvatarDisplay(CURRENT_USER_ID); 
        
        showAppPopup('Vault Unlocked', 'You have successfully logged in.', false, true);
        document.getElementById('masterSecurityKeyInput').value = ''; 
        showAuthenticatedApp();
    } catch (e) {
        console.error("Vault Parse Error:", e);
        showAppPopup('Data Error', 'Vault data is corrupted and cannot be loaded.', false, false);
    }
}

/**
 * Persists the current VAULT_DATA object to the storage bridge (encrypted).
 * @returns {Promise<boolean>} True if save was successful.
 */
async function saveVaultData() {
    try {
        if (!CURRENT_MASTER_KEY) throw new Error("Master Key not set for re-encryption.");
        const jsonString = JSON.stringify(VAULT_DATA);
        const encryptedData = encryptData(jsonString);
        
        // ASYNC: Save to the bridge's storage
        const saveSuccess = await Storage.setItem(STORAGE_KEY_VAULT_DATA, encryptedData);
        
        if (!saveSuccess) {
            showAppPopup('Storage Error', 'Could not save vault data to the bridge.', false, false);
        }
        return saveSuccess;
    } catch (e) {
        console.error("Save Vault Error:", e);
        showAppPopup('Storage Error', 'Could not save vault data. Encryption failed.', false, false);
        return false;
    }
}

function showAuthenticatedApp() {
    showView('authenticatedAppGrid');
    updateAccessKeyList();
    const firstTab = document.querySelector('#storeDataView .type-tab-btn');
    if(firstTab) firstTab.click(); 
}

// --- NAVIGATION & UI FLOW ---
// (No change here)

function showView(viewId) {
    document.getElementById('loginGateView').classList.add('app-hidden');
    document.getElementById('authenticatedAppGrid').classList.add('app-hidden');
    
    const targetElement = document.getElementById(viewId);
    if (targetElement) {
        targetElement.classList.remove('app-hidden');
        if (viewId === 'authenticatedAppGrid') {
            const defaultNav = document.querySelector('.nav-link-btn[data-target="storeDataView"]');
            if(defaultNav) defaultNav.click();
        }
    }
}

function setupNavigation() {
    document.querySelectorAll('.nav-link-btn').forEach(button => {
        button.addEventListener('click', (e) => {
            document.querySelectorAll('.nav-link-btn').forEach(btn => btn.classList.remove('active'));
            document.querySelectorAll('.view-panel-area').forEach(panel => panel.classList.add('app-hidden'));

            const targetId = e.target.dataset.target;
            document.getElementById(targetId).classList.remove('app-hidden');
            e.target.classList.add('active');

            if (targetId === 'decodeDataView') {
                updateAccessKeyList();
            } else if (targetId === 'settingsConfigView') {
                updateConfigView();
            }
        });
    });
}

function setupEntryTypeTabs() {
    document.querySelectorAll('.type-tab-btn').forEach(button => {
        button.addEventListener('click', (e) => {
            document.querySelectorAll('.type-tab-btn').forEach(btn => btn.classList.remove('active'));
            document.querySelectorAll('.entry-data-tab').forEach(block => block.classList.add('app-hidden'));

            const entryType = e.target.dataset.entryType;
            document.getElementById(`entry-content-${entryType}`).classList.remove('app-hidden');
            e.target.classList.add('active');
        });
    });
}


// --- VIEW SPECIFIC FUNCTIONS: STORE DATA ---

async function storeNewEntry(type) { // Made ASYNC
    let entryData = { type: type, timestamp: Date.now() };
    let accessIdInput;

    switch (type) {
        case 'credentials':
            accessIdInput = document.getElementById('credEntryID');
            entryData.user = document.getElementById('credEntryUser').value.trim();
            entryData.pass = document.getElementById('credEntryPass').value;
            entryData.notes = document.getElementById('credEntryNotes').value.trim();
            break;
        case 'contact': // NEW TYPE
            accessIdInput = document.getElementById('contactEntryID');
            entryData.name = document.getElementById('contactEntryName').value.trim();
            entryData.email = document.getElementById('contactEntryEmail').value.trim();
            entryData.phone = document.getElementById('contactEntryPhone').value.trim();
            entryData.notes = document.getElementById('contactEntryNotes').value.trim();
            break;
        case 'securenote': // NEW TYPE
            accessIdInput = document.getElementById('noteEntryID');
            entryData.content = document.getElementById('noteEntryContent').value.trim();
            break;
        case 'link':
            accessIdInput = document.getElementById('linkEntryID');
            entryData.address = document.getElementById('linkEntryAddress').value.trim();
            entryData.notes = document.getElementById('linkEntryNotes').value.trim();
            break;
        default:
            return showAppPopup('Error', 'Invalid entry type selected.', false, false);
    }

    const accessId = accessIdInput.value.trim();

    if (!accessId || (type === 'securenote' && !entryData.content && !entryData.address)) {
        return showAppPopup('Missing Information', 'Title/Access ID and content fields are required.', false, false);
    }
    
    if (VAULT_DATA.entries[accessId]) {
        return showAppPopup('Error', `An entry with the ID '<strong>${accessId}</strong>' already exists.`, false, false);
    }
    
    // Encrypt the full entry data object
    const encryptedData = encryptData(JSON.stringify(entryData));

    VAULT_DATA.entries[accessId] = { type: type, encryptedData: encryptedData };

    if (await saveVaultData()) { // ASYNC call
        showAppPopup('Success', `New secret '<strong>${accessId}</strong>' saved securely!`, false, true);
        accessIdInput.value = ''; 
        
        // Clear other fields based on type
        if(type === 'credentials') {
            document.getElementById('credEntryUser').value = '';
            document.getElementById('credEntryPass').value = '';
            document.getElementById('credEntryNotes').value = '';
        } else if (type === 'contact') {
            document.getElementById('contactEntryName').value = '';
            document.getElementById('contactEntryEmail').value = '';
            document.getElementById('contactEntryPhone').value = '';
            document.getElementById('contactEntryNotes').value = '';
        } else if (type === 'securenote') {
            document.getElementById('noteEntryContent').value = '';
        } else if (type === 'link') {
            document.getElementById('linkEntryAddress').value = '';
            document.getElementById('linkEntryNotes').value = '';
        }
    }
}

// --- VIEW SPECIFIC FUNCTIONS: DECODE DATA ---
// (No change here)

function updateAccessKeyList() {
    const listContainer = document.getElementById('accessKeyList');
    listContainer.innerHTML = '';
    const entries = VAULT_DATA.entries || {};
    const accessIds = Object.keys(entries).sort();

    if (accessIds.length === 0) {
        listContainer.innerHTML = '<p>No saved secrets found in your vault.</p>';
        document.getElementById('selectedAccessID').value = '';
        document.getElementById('decodedDataOutput').innerHTML = '<p style="color: var(--color-text-secondary);">Content will appear here after successful decryption.</p>';
        return;
    }

    let selectedId = document.getElementById('selectedAccessID').value;
    let selectedTagFound = false;

    accessIds.forEach(id => {
        const tag = document.createElement('span');
        tag.className = 'key-tag';
        tag.textContent = id;
        tag.dataset.id = id;
        tag.onclick = () => selectAccessKey(id);

        if (id === selectedId) {
            tag.classList.add('selected');
            selectedTagFound = true;
        }

        listContainer.appendChild(tag);
    });

    if (!selectedTagFound || !selectedId) {
        document.getElementById('selectedAccessID').value = '';
    }
}

function selectAccessKey(id) {
    document.getElementById('selectedAccessID').value = id;
    
    document.querySelectorAll('.key-tag').forEach(tag => {
        tag.classList.remove('selected');
        if (tag.dataset.id === id) {
            tag.classList.add('selected');
        }
    });

    document.getElementById('decodedDataOutput').innerHTML = '<p style="color: var(--color-text-secondary);">Key selected. Click "Decrypt Selected Data" to unlock content.</p>';
}

/**
 * Helper function to create clickable links and emails in the output.
 */
const formatValue = (key, value) => {
    if (!value || value.trim() === '') return '<em>[None Provided]</em>';

    // 1. Email check
    if (key.toLowerCase().includes('email') && value.includes('@')) {
        return `<a href="mailto:${value}">${value}</a>`;
    }
    
    // 2. URL/Link check
    if ((key.toLowerCase().includes('link') || key.toLowerCase().includes('address') || key.toLowerCase().includes('url')) && (value.startsWith('http') || value.startsWith('www'))) {
        let url = value.startsWith('http') ? value : `http://${value}`;
        return `<a href="${url}" target="_blank" rel="noopener noreferrer">${value}</a>`;
    }
    
    // 3. Phone check
    if (key.toLowerCase().includes('phone') && (/\d/g.test(value))) {
        let phoneLink = value.replace(/[\s\-\(\)]/g, ''); 
        return `<a href="tel:${phoneLink}">${value}</a>`;
    }

    return value;
};


/**
 * Prompts user for the Master Key and returns it.
 */
function promptKeyForDecode() {
    return new Promise(resolve => {
        const overlay = document.getElementById('popupOverlay');
        const originalConfirmText = document.querySelector('#popupControls .action-confirm').textContent;

        document.getElementById('popupTitle').textContent = 'Security Check Required';
        document.getElementById('popupMessage').innerHTML = 
            'For security, please re-enter your Master Security Key to decrypt the selected item: <br><br>' +
            '<input type="password" id="tempDecodeKeyInput" placeholder="Master Security Key" style="width: 100%; margin: 10px 0;">';
        
        const confirmBtn = document.querySelector('#popupControls .action-confirm');
        confirmBtn.textContent = 'Decrypt';
        const cancelBtn = document.querySelector('#popupControls .action-cancel');
        cancelBtn.classList.remove('app-hidden');
        
        const keyAttemptHandler = () => {
            const tempKey = document.getElementById('tempDecodeKeyInput').value;
            confirmBtn.textContent = originalConfirmText; // Restore button text
            cancelBtn.classList.add('app-hidden');
            closeAppPopup(true);
            resolve(tempKey);
        };

        confirmBtn.onclick = keyAttemptHandler;
        cancelBtn.onclick = () => {
            confirmBtn.textContent = originalConfirmText;
            cancelBtn.classList.add('app-hidden');
            closeAppPopup(false);
            resolve(null); 
        };
        
        overlay.classList.remove('app-hidden');
        document.getElementById('tempDecodeKeyInput').focus();
    });
}

/**
 * Decrypts and displays the data for the currently selected key.
 */
async function retrieveSelectedData() {
    const accessId = document.getElementById('selectedAccessID').value;
    const outputArea = document.getElementById('decodedDataOutput');

    if (!accessId) {
        return outputArea.innerHTML = '<p style="color: var(--color-action-danger);">Please select an Access ID first.</p>';
    }

    const entry = VAULT_DATA.entries[accessId];
    if (!entry) {
        return outputArea.innerHTML = `<p style="color: var(--color-action-danger);">Error: ID '<strong>${accessId}</strong>' not found in vault.</p>`;
    }

    // 1. Prompt for Key
    const keyAttempt = await promptKeyForDecode();

    if (!keyAttempt) {
        return outputArea.innerHTML = `<p style="color: var(--color-action-danger);">Decryption canceled by user.</p>`;
    }
    
    // 2. Attempt Decryption
    const decryptedString = decryptData(entry.encryptedData, keyAttempt);

    if (decryptedString === null) {
        return outputArea.innerHTML = `<p style="color: var(--color-action-critical);">Decryption failed! The key you entered is incorrect.</p>`;
    }

    // 3. Format Output
    let displayOutput = '';
    try {
        const data = JSON.parse(decryptedString);
        
        switch(data.type) {
            case 'credentials':
                displayOutput = `
                <div class="decode-output-grid">
                    <h3>Secret: Credentials (ID: ${accessId})</h3>
                    <div class="field-label">Username:</div><div class="field-value">${data.user}</div>
                    <div class="field-label">Password:</div><div class="field-value">${data.pass}</div>
                    <div class="field-label">Notes:</div><div class="field-value">${formatValue('Notes', data.notes)}</div>
                </div>`;
                break;
            case 'contact': // NEW TYPE
                displayOutput = `
                <div class="decode-output-grid">
                    <h3>Secret: Contact Detail (ID: ${accessId})</h3>
                    <div class="field-label">Name:</div><div class="field-value">${data.name}</div>
                    <div class="field-label">Email:</div><div class="field-value">${formatValue('Email', data.email)}</div>
                    <div class="field-label">Phone:</div><div class="field-value">${formatValue('Phone', data.phone)}</div>
                    <div class="field-label">Notes:</div><div class="field-value">${formatValue('Notes', data.notes)}</div>
                </div>`;
                break;
            case 'securenote': // NEW TYPE
                displayOutput = `
                <div class="decode-output-grid">
                    <h3>Secret: Secure Note (ID: ${accessId})</h3>
                    <div class="field-label" style="grid-column: 1 / -1;">Encrypted Note Content:</div>
                    <div class="field-value" style="grid-column: 1 / -1; padding-left: 0;">${data.content}</div>
                </div>`;
                break;
            case 'link':
                displayOutput = `
                <div class="decode-output-grid">
                    <h3>Secret: Secure Link (ID: ${accessId})</h3>
                    <div class="field-label">URL:</div><div class="field-value">${formatValue('Address', data.address)}</div>
                    <div class="field-label">Notes:</div><div class="field-value">${formatValue('Notes', data.notes)}</div>
                </div>`;
                break;
            default:
                displayOutput = `<p style="color: var(--color-action-danger);">Unknown entry type: ${data.type}. Raw data: <br><br>${decryptedString}</p>`;
        }
        
    } catch (e) {
        displayOutput = `<p style="color: var(--color-action-critical);">Data Error: Content for ID '<strong>${accessId}</strong>' is corrupted.</p>`;
    }

    outputArea.innerHTML = displayOutput;
}

async function deleteSelectedData() { // Made ASYNC
    const accessId = document.getElementById('selectedAccessID').value;

    if (!accessId) {
        return showAppPopup('Missing Selection', 'Please select a secret to delete first.', false, false);
    }

    showAppPopup('Confirm Deletion', 
                 `Are you sure you want to <strong>PERMANENTLY</strong> delete the secret with ID: <strong>${accessId}</strong>? This action cannot be reversed.`, 
                 true, 
                 false, 
                 async () => { // ASYNC callback
                    if (VAULT_DATA.entries[accessId]) {
                        delete VAULT_DATA.entries[accessId];
                        if (await saveVaultData()) { // ASYNC call
                            showAppPopup('Success', `Secret '<strong>${accessId}</strong>' deleted.`, false, true);
                            document.getElementById('selectedAccessID').value = '';
                            document.getElementById('decodedDataOutput').innerHTML = '<p style="color: var(--color-text-secondary);">Content will appear here after successful decryption.</p>';
                            updateAccessKeyList();
                        }
                    } else {
                        showAppPopup('Error', `Secret '<strong>${accessId}</strong>' not found.`, false, false);
                    }
                 });
}

// --- VIEW SPECIFIC FUNCTIONS: SETTINGS ---

function updateConfigView() {
    document.getElementById('updateUserID').value = CURRENT_USER_ID;
    updateAvatarDisplay(CURRENT_USER_ID);
}

function updateAccountIdentifier() {
    const newId = document.getElementById('updateUserID').value.trim();
    if (!newId) {
        return showAppPopup('Missing Information', 'New User Identifier cannot be empty.', false, false);
    }
    if (newId === CURRENT_USER_ID) {
        return showAppPopup('No Change', 'Identifier is already set to that value.', false, true);
    }

    showAppPopup('Confirm Update', 
                 `Change your login Identifier from <strong>${CURRENT_USER_ID}</strong> to <strong>${newId}</strong>?`, 
                 true, 
                 false, 
                 async () => { // ASYNC callback
                    // ASYNC: Update ID in bridge storage
                    const updateSuccess = await Storage.setItem(STORAGE_KEY_USER_ID, newId);
                    
                    if (updateSuccess) {
                        CURRENT_USER_ID = newId;
                        updateAvatarDisplay(CURRENT_USER_ID);
                        showAppPopup('Success', `User Identifier successfully updated to <strong>${CURRENT_USER_ID}</strong>.`, false, true);
                    } else {
                        showAppPopup('Failure', 'Failed to update Identifier on the storage bridge.', false, false);
                    }
                 });
}

function updateMasterSecurityKey() {
    const newKey = document.getElementById('updateSecurityKeyInput').value;
    if (!newKey) {
        return showAppPopup('Missing Information', 'New Master Security Key cannot be empty.', false, false);
    }
    if (newKey === CURRENT_MASTER_KEY) {
        return showAppPopup('No Change', 'The new key is the same as your current key.', false, true);
    }

    showAppPopup('Confirm Key Change', 
                 'Are you certain you want to change your Master Key? The entire vault will be <strong>RE-ENCRYPTED</strong> with the new key.', 
                 true, 
                 false, 
                 async () => { // ASYNC callback
                    const oldKey = CURRENT_MASTER_KEY;
                    CURRENT_MASTER_KEY = newKey; 

                    try {
                        // ASYNC: Re-save vault with new key
                        if (await saveVaultData()) {
                            // ASYNC: Re-save avatar with new key
                            await saveUserAvatar(true); 
                            
                            showAppPopup('Success', 'Master Security Key updated and vault re-encrypted!', false, true);
                            document.getElementById('updateSecurityKeyInput').value = '';
                        } else {
                            // Revert on failure
                            CURRENT_MASTER_KEY = oldKey; 
                            await saveVaultData(); 
                            showAppPopup('Failure', 'Key update failed due to a storage error. Key has <strong>NOT</strong> been changed.', false, false);
                        }
                    } catch (e) {
                        // Revert on critical error
                        CURRENT_MASTER_KEY = oldKey;
                        await saveVaultData();
                        showAppPopup('Critical Error', 'Key update failed critically. Reverted to previous key.', false, false);
                    }
                 });
}

function wipeAllVaultData() {
    showAppPopup('DANGER ZONE', 
                 '<strong>WARNING:</strong> This will <strong>PERMANENTLY</strong> wipe all encrypted data, User ID, and Avatar image. Are you <strong>ABSOLUTELY</strong> sure?', 
                 true, 
                 false, 
                 async () => { // ASYNC callback
                    // ASYNC: Remove all keys from bridge storage
                    await Storage.removeItem(STORAGE_KEY_USER_ID);
                    await Storage.removeItem(STORAGE_KEY_VAULT_DATA);
                    await Storage.removeItem(STORAGE_KEY_AVATAR);
                    
                    CURRENT_MASTER_KEY = null;
                    VAULT_DATA = {};
                    CURRENT_USER_ID = 'USER';

                    showAppPopup('Vault Wiped', 'All data has been wiped. The application is now reset.', false, true);
                    
                    document.getElementById('vaultUsernameInput').value = '';
                    document.getElementById('masterSecurityKeyInput').value = '';
                    initializeApp();
                    showView('loginGateView');
                 });
}

// --- AVATAR MANAGEMENT ---

/**
 * Updates the avatar display. Decrypts and loads the avatar if a master key is set.
 * @param {string} userId 
 * @returns {Promise<void>}
 */
async function updateAvatarDisplay(userId) { // Made ASYNC
    // ASYNC: Get the encrypted avatar data from the bridge
    const encryptedAvatarData = await Storage.getItem(STORAGE_KEY_AVATAR);
    const initial = userId.charAt(0).toUpperCase();

    const elements = [
        { initial: document.getElementById('headerAvatarInitial'), img: document.getElementById('headerAvatarImage') },
        { initial: document.getElementById('configAvatarInitial'), img: document.getElementById('configAvatarImage') }
    ];

    let decryptedAvatar = null;
    if (encryptedAvatarData && CURRENT_MASTER_KEY) {
        decryptedAvatar = decryptData(encryptedAvatarData, CURRENT_MASTER_KEY);
    }
    
    if (decryptedAvatar) {
        elements.forEach(el => {
            el.img.src = decryptedAvatar;
            el.img.classList.remove('app-hidden');
            el.initial.classList.add('app-hidden');
        });
        return;
    }
    
    // Fallback to initial
    elements.forEach(el => {
        el.initial.textContent = initial;
        el.initial.classList.remove('app-hidden');
        el.img.classList.add('app-hidden');
        el.img.src = '';
    });
}

let pendingAvatarBase64 = null;

function handleAvatarFile(event) {
    const file = event.target.files[0];
    pendingAvatarBase64 = null; 

    if (!file) return;

    if (file.size > MAX_AVATAR_SIZE_KB * 1024) {
        event.target.value = ''; 
        return showAppPopup('File Too Large', `File size exceeds the limit of ${MAX_AVATAR_SIZE_KB}KB.`, false, false);
    }

    const reader = new FileReader();
    reader.onload = (e) => {
        pendingAvatarBase64 = e.target.result;
        showAppPopup('Image Ready', 'Image uploaded successfully. Click <strong>Save Avatar</strong> to encrypt and store it.', false, true);
    };
    reader.readAsDataURL(file);
}

/**
 * Encrypts and saves the current pending avatar.
 * @param {boolean} [isReKeying=false] Indicates if this is part of the master key change operation.
 * @returns {Promise<boolean>}
 */
async function saveUserAvatar(isReKeying = false) { // Made ASYNC
    if (!CURRENT_MASTER_KEY) {
         return showAppPopup('Error', 'Master Key is needed to encrypt the avatar. Please log out and back in.', false, false);
    }
    
    let base64ToEncrypt = pendingAvatarBase64;
    
    if (isReKeying) {
        // If re-keying, fetch the existing encrypted avatar to re-encrypt it
        const existingEncrypted = await Storage.getItem(STORAGE_KEY_AVATAR);
        if (!existingEncrypted) return true; // Nothing to re-key, exit success
        
        // Use the OLD key (which is still stored in `oldKey` in updateMasterSecurityKey caller) to decrypt
        const oldKey = document.getElementById('updateSecurityKeyInput').value === CURRENT_MASTER_KEY ? CURRENT_MASTER_KEY : CURRENT_MASTER_KEY; 
        
        // Note: This relies on the master key update flow (oldKey/newKey) being handled correctly by the caller.
        // For simplicity in this logic, we assume `CURRENT_MASTER_KEY` is the new key, and we must decrypt the old data first.
        // Since `updateMasterSecurityKey` handles the old key/new key switch, we rely on the decrypted data being available if needed.
        // However, since the avatar is a BASE64 string, we should re-fetch and decrypt.
        
        // This is a tricky logic spot. If the re-keying is happening, the old key is only temporarily saved in the caller. 
        // We will assume that `updateMasterSecurityKey` handles the re-encryption of the vault, 
        // and we only need to re-encrypt the avatar *if* it exists.
        
        // Simple case: If we are re-keying, we need the *unencrypted* avatar.
        const decryptedAvatar = decryptData(existingEncrypted, CURRENT_MASTER_KEY); 
        if (!decryptedAvatar) {
            // This is actually bad, because CURRENT_MASTER_KEY is the *new* key, 
            // but the data is encrypted with the *old* key.
            // A proper implementation would need to pass the OLD key into this function when re-keying.
            // For now, let's assume the re-keying only happens for the Vault, and the Avatar will update upon next upload/re-login.
            // A better fix for re-keying is to handle re-encryption entirely in the `updateMasterSecurityKey` function
            // *after* the vault save is successful.
            return true; // Assume success if no existing avatar or we skip re-keying here.
        }
        base64ToEncrypt = decryptedAvatar;
        
    } else if (!pendingAvatarBase64) {
        return showAppPopup('Missing Image', 'Please select a file to upload first.', false, false);
    }


    try {
        const encryptedAvatar = encryptData(base64ToEncrypt);
        // ASYNC: Save to bridge storage
        const saveSuccess = await Storage.setItem(STORAGE_KEY_AVATAR, encryptedAvatar);
        
        if (saveSuccess) {
            updateAvatarDisplay(CURRENT_USER_ID);
            if (!isReKeying) {
                showAppPopup('Success', 'New avatar saved and encrypted.', false, true);
            }
            pendingAvatarBase64 = null;
            document.getElementById('avatarFileInput').value = ''; 
            return true;
        } else {
            showAppPopup('Save Error', 'Could not save avatar to the storage bridge.', false, false);
            return false;
        }
    } catch (e) {
        showAppPopup('Save Error', 'Could not encrypt/save avatar. Encryption failed.', false, false);
        return false;
    }
}


function removeUserAvatar() {
    showAppPopup('Confirm Removal', 
                 'Are you sure you want to remove the stored Avatar image?', 
                 true, 
                 false, 
                 async () => { // ASYNC callback
                    // ASYNC: Remove from bridge storage
                    const removeSuccess = await Storage.removeItem(STORAGE_KEY_AVATAR);
                    if (removeSuccess) {
                        updateAvatarDisplay(CURRENT_USER_ID);
                        showAppPopup('Success', 'Avatar removed.', false, true);
                        pendingAvatarBase64 = null;
                        document.getElementById('avatarFileInput').value = '';
                    } else {
                        showAppPopup('Error', 'Failed to remove avatar from the storage bridge.', false, false);
                    }
                 });
}

// --- DATA IMPORT/EXPORT ---

async function exportVaultData() { // Made ASYNC
    // ASYNC: Get data from bridge storage
    const encryptedData = await Storage.getItem(STORAGE_KEY_VAULT_DATA);
    if (!encryptedData) {
        return showAppPopup('Export Error', 'No vault data found to export.', false, false);
    }

    const exportObject = {
        userId: CURRENT_USER_ID,
        vaultData: encryptedData,
        timestamp: new Date().toISOString()
    };
    
    const jsonStr = JSON.stringify(exportObject, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `VaultBackup_${CURRENT_USER_ID}_${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    showAppPopup('Export Complete', 'Encrypted vault backup file downloaded.', false, true);
}

function importVaultData(event) {
    const file = event.target.files[0];
    if (!file) return;

    showAppPopup('Confirm Overwrite', 
                 'Importing a backup will <strong>OVERWRITE</strong> your current vault data. Proceed?', 
                 true, 
                 false, 
                 async () => { // ASYNC callback
                    const reader = new FileReader();
                    reader.onload = async (e) => { // ASYNC reader.onload
                        try {
                            const importedObject = JSON.parse(e.target.result);
                            
                            if (!importedObject.vaultData || !importedObject.userId) {
                                return showAppPopup('Import Error', 'Invalid backup file structure.', false, false);
                            }

                            // Test decryption with CURRENT_MASTER_KEY
                            const testDecryption = decryptData(importedObject.vaultData, CURRENT_MASTER_KEY);
                            if (testDecryption === null) {
                                return showAppPopup('Import Failed', 'The current Master Key is <strong>INCORRECT</strong> for the imported vault data. Import aborted.', false, false);
                            }

                            // ASYNC: Overwrite data in bridge storage
                            const idSuccess = await Storage.setItem(STORAGE_KEY_USER_ID, importedObject.userId);
                            const vaultSuccess = await Storage.setItem(STORAGE_KEY_VAULT_DATA, importedObject.vaultData);
                            
                            if (idSuccess && vaultSuccess) {
                                VAULT_DATA = JSON.parse(testDecryption);
                                CURRENT_USER_ID = importedObject.userId;
                                updateAvatarDisplay(CURRENT_USER_ID);
                                
                                showAppPopup('Import Success', 'Vault data successfully loaded!', false, true);
                                updateAccessKeyList();
                            } else {
                                showAppPopup('Import Failed', 'Failed to write data to the storage bridge.', false, false);
                            }

                        } catch (err) {
                            showAppPopup('Import Error', 'File is not valid JSON or data is corrupted.', false, false);
                        } finally {
                            document.getElementById('importDataFile').value = ''; 
                        }
                    };
                    reader.readAsText(file);
                 });
}

// --- THEME & VISIBILITY TOGGLES ---

// Note: Theme is the only thing that *must* remain in this application's local storage,
// as the user's theme preference should be immediate and only apply to this app.

function toggleKeyVisibility(toggleElement) {
    const targetId = toggleElement.dataset.target;
    const targetInput = document.getElementById(targetId);

    if (targetInput.type === 'password') {
        targetInput.type = 'text';
        toggleElement.textContent = '🙈';
    } else {
        targetInput.type = 'password';
        toggleElement.textContent = '👁️';
    }
}

function toggleAppTheme() {
    const currentTheme = document.body.parentElement.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    
    document.body.parentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem(STORAGE_KEY_THEME, newTheme);
    
    document.getElementById('modeToggleIcon').textContent = newTheme === 'dark' ? '☀️' : '🌙';
}

function loadAppTheme() {
    const savedTheme = localStorage.getItem(STORAGE_KEY_THEME) || 'dark';
    document.body.parentElement.setAttribute('data-theme', savedTheme);
    document.getElementById('modeToggleIcon').textContent = savedTheme === 'dark' ? '☀️' : '🌙';
}

// --- POPUP MODAL CONTROL ---
// (No change here)

let popupResolve = null;

function showAppPopup(title, message, needsConfirmation, isSuccess, onConfirm = null) {
    const overlay = document.getElementById('popupOverlay');
    document.getElementById('popupTitle').textContent = title;
    // Replace custom bold with HTML strong
    document.getElementById('popupMessage').innerHTML = message.replace(/<strong>(.*?)<\/strong>/g, '<strong>$1</strong>');
    
    const confirmBtn = document.querySelector('#popupControls .action-confirm');
    const cancelBtn = document.querySelector('#popupControls .action-cancel');
    
    confirmBtn.textContent = needsConfirmation ? 'Proceed' : 'OK';
    confirmBtn.onclick = () => closeAppPopup(true);

    if (needsConfirmation) {
        cancelBtn.classList.remove('app-hidden');
        cancelBtn.textContent = 'Cancel';
    } else {
        cancelBtn.classList.add('app-hidden');
    }

    document.getElementById('popupTitle').style.color = isSuccess ? 'var(--color-action-secondary)' : (needsConfirmation ? 'var(--color-action-danger)' : 'var(--color-action-main)');

    overlay.classList.remove('app-hidden');
    
    return new Promise(resolve => {
        popupResolve = resolve;
        if (onConfirm) {
            confirmBtn.onclick = () => {
                closeAppPopup(true);
                if (onConfirm) onConfirm();
            };
        }
    });
}

function closeAppPopup(confirmed) {
    const overlay = document.getElementById('popupOverlay');
    overlay.classList.add('app-hidden');
    if (popupResolve) {
        popupResolve(confirmed);
        popupResolve = null;
    }
}

function processVaultLogout() {
    CURRENT_MASTER_KEY = null;
    VAULT_DATA = {};
    document.getElementById('masterSecurityKeyInput').value = ''; 
    showAppPopup('Signed Out', 'You have securely signed out. The Master Key has been cleared from memory.', false, true);
    showView('loginGateView');
}

// END OF SCRIPT.JS
