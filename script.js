/*
    SCRIPT.JS
    Secure Vault Keeper Application Logic with AES Encryption
    MODIFIED: Now uses Cross-Origin postMessage to access remote storage on storage.mahdiyasser.site
*/

// --- CONSTANTS & GLOBAL STATE ---

// UPDATED KEY PREFIX: 'skr_' for remote storage
const STORAGE_KEY_USER_ID = 'skr_userId';
const STORAGE_KEY_VAULT_DATA = 'skr_vaultData';
const STORAGE_KEY_AVATAR = 'skr_avatar';
const STORAGE_KEY_THEME = 'skr_theme';
const MAX_AVATAR_SIZE_KB = 1024; // 1024KB limit

let CURRENT_MASTER_KEY = null;
let VAULT_DATA = {}; // Structure: { userId: '...', entries: { accessId: { type: '...', encryptedData: '...' } } }
let CURRENT_USER_ID = 'USER';

// --- REMOTE STORAGE BRIDGE SETUP ---

// The URL for the storage utility page on the separate domain
const STORAGE_BRIDGE_URL = 'https://storage.mahdiyasser.site/';
let storageBridgeIframe = null;
let bridgeReady = false;
let pendingRequests = {};
let messageIdCounter = 0;

/**
 * Initializes the invisible iframe and sets up the message listener.
 * All subsequent storage operations must wait for this to complete.
 */
function initializeStorageBridge() {
    return new Promise(resolve => {
        storageBridgeIframe = document.createElement('iframe');
        storageBridgeIframe.style.display = 'none'; // Keep it invisible
        storageBridgeIframe.src = STORAGE_BRIDGE_URL;

        storageBridgeIframe.onload = () => {
            bridgeReady = true;
            console.log('Storage bridge connected and ready.');
            resolve();
        };

        // Listen for responses from the storage bridge
        window.addEventListener('message', (event) => {
            // Check origin security! Only accept messages from the storage domain.
            if (event.origin !== 'https://storage.mahdiyasser.site') {
                return;
            }

            try {
                const response = JSON.parse(event.data);
                const id = response.id;

                if (id && pendingRequests[id]) {
                    const { resolve, reject } = pendingRequests[id];
                    delete pendingRequests[id];

                    if (response.success) {
                        // Resolve with the data (null for set/remove, string for get)
                        resolve(response.data);
                    } else {
                        reject(new Error(`Remote storage operation failed for action: ${response.action}`));
                    }
                }
            } catch (e) {
                console.error('Error processing message from storage bridge:', e);
            }
        });

        document.body.appendChild(storageBridgeIframe);
    });
}

/**
 * Sends a message to the storage bridge and returns a Promise for the result.
 * @param {string} action - 'set', 'get', or 'remove'
 * @param {string} key - The localStorage key
 * @param {string} [value] - The value to set (for 'set' action)
 * @returns {Promise<string|null>} The stored value for 'get', or null for 'set'/'remove'.
 */
function remoteStorageOperation(action, key, value) {
    if (!bridgeReady) {
        return Promise.reject(new Error('Storage bridge is not ready.'));
    }

    const messageId = messageIdCounter++;
    const message = { id: messageId, action, key, value };

    // Create a promise to resolve when the response comes back
    return new Promise((resolve, reject) => {
        pendingRequests[messageId] = { resolve, reject };

        try {
            // Send message to the iframe
            storageBridgeIframe.contentWindow.postMessage(JSON.stringify(message), 'https://storage.mahdiyasser.site');
        } catch (error) {
            delete pendingRequests[messageId];
            reject(error);
        }
    });
}

const remoteGetItem = (key) => remoteStorageOperation('get', key);
const remoteSetItem = (key, value) => remoteStorageOperation('set', key, value);
const remoteRemoveItem = (key) => remoteStorageOperation('remove', key);

// --- INITIALIZATION & UI SETUP ---

document.addEventListener('DOMContentLoaded', async () => {
    // 1. Initialize the storage bridge and wait for it to be ready
    await initializeStorageBridge(); 
    
    // 2. Load theme and application state
    await loadAppTheme();
    await initializeApp();
    
    // 3. Setup UI listeners
    setupNavigation();
    setupEntryTypeTabs();
    
    // Wire up buttons for authentication view
    document.getElementById('authActionButton').onclick = performAuthentication;
});

async function initializeApp() {
    // Use remote storage
    const storedUserId = await remoteGetItem(STORAGE_KEY_USER_ID); 
    
    if (storedUserId) {
        CURRENT_USER_ID = storedUserId;
        document.getElementById('vaultUsernameInput').value = storedUserId;
        await updateAvatarDisplay(CURRENT_USER_ID); 
        document.getElementById('updateUserID').value = CURRENT_USER_ID;
    } else {
        await updateAvatarDisplay(CURRENT_USER_ID);
    }
    showView('loginGateView'); 
}

// --- ENCRYPTION/DECRYPTION UTILITIES ---

/**
 * Encrypts a plaintext string using the current master key.
 * @param {string} plaintext - The data to encrypt.
 * @returns {string} The encrypted ciphertext.
 */
function encryptData(plaintext) {
    if (!CURRENT_MASTER_KEY) {
        console.error("No master key loaded for encryption.");
        return null;
    }
    return CryptoJS.AES.encrypt(plaintext, CURRENT_MASTER_KEY).toString();
}

/**
 * Decrypts a ciphertext string using the current master key.
 * @param {string} ciphertext - The data to decrypt.
 * @returns {string|null} The decrypted plaintext or null if decryption fails.
 */
function decryptData(ciphertext) {
    if (!CURRENT_MASTER_KEY) {
        console.error("No master key loaded for decryption.");
        return null;
    }
    try {
        const bytes = CryptoJS.AES.decrypt(ciphertext, CURRENT_MASTER_KEY);
        const plaintext = bytes.toString(CryptoJS.enc.Utf8);
        if (plaintext.length === 0 && ciphertext.length > 0) {
            // This usually means the key was incorrect
            return null;
        }
        return plaintext;
    } catch (e) {
        console.error("Decryption failed:", e);
        return null;
    }
}

// --- AUTHENTICATION & VAULT LOADING ---

/**
 * Handles the login/register process based on vault data existence.
 */
async function performAuthentication() {
    const userId = document.getElementById('vaultUsernameInput').value.trim();
    const masterKey = document.getElementById('masterSecurityKeyInput').value;

    if (!userId || !masterKey) {
        showAppPopup('Error', 'User Identifier and Master Key are required.', false);
        return;
    }

    const vaultDataExists = await loadVaultData(userId, masterKey);
    
    if (!vaultDataExists) {
        // Vault does not exist, prompt for registration
        const confirmed = await showAppPopup(
            'New Vault', 
            `A vault for "${userId}" does not exist. Do you want to create a new one using this Master Key?`, 
            true
        );
        if (confirmed) {
            // Register new vault
            CURRENT_USER_ID = userId;
            CURRENT_MASTER_KEY = masterKey;
            VAULT_DATA = { userId: CURRENT_USER_ID, entries: {} };
            await saveUserId(CURRENT_USER_ID);
            await saveVaultData();
            processVaultLogin();
        }
    } else {
        // Successful login
        processVaultLogin();
    }
}

/**
 * Attempts to load vault data for a user ID and master key.
 * @param {string} userId 
 * @param {string} masterKey 
 * @returns {Promise<boolean>} True if data was loaded successfully, false otherwise.
 */
async function loadVaultData(userId, masterKey) {
    const encryptedData = await remoteGetItem(STORAGE_KEY_VAULT_DATA);

    if (!encryptedData) {
        return false; // No data exists
    }

    // Temporarily set the key to attempt decryption
    CURRENT_MASTER_KEY = masterKey;
    const decryptedJson = decryptData(encryptedData);

    if (!decryptedJson) {
        showAppPopup('Authentication Failed', 'Incorrect Master Key or corrupted data.', false);
        CURRENT_MASTER_KEY = null;
        return true; // Data exists, but key was wrong
    }

    try {
        const loadedData = JSON.parse(decryptedJson);
        if (loadedData.userId !== userId) {
             // Although unlikely with the current storage design, good to check
             showAppPopup('Authentication Failed', 'Data is for a different User Identifier. Check your input.', false);
             CURRENT_MASTER_KEY = null;
             return true;
        }
        
        VAULT_DATA = loadedData;
        CURRENT_USER_ID = userId;
        return true; // Success
    } catch (e) {
        showAppPopup('Data Error', 'Vault data is corrupted and cannot be parsed.', false);
        CURRENT_MASTER_KEY = null;
        return true;
    }
}

/**
 * Saves the current user ID to remote storage.
 * @param {string} userId 
 */
async function saveUserId(userId) {
    await remoteSetItem(STORAGE_KEY_USER_ID, userId);
    document.getElementById('updateUserID').value = userId; // Update settings view
}

/**
 * Encrypts and saves the entire VAULT_DATA object to remote storage.
 */
async function saveVaultData() {
    const json = JSON.stringify(VAULT_DATA);
    const encrypted = encryptData(json);
    if (encrypted) {
        await remoteSetItem(STORAGE_KEY_VAULT_DATA, encrypted);
        console.log('Vault data saved remotely.');
    } else {
        console.error('Failed to encrypt vault data.');
    }
}

function processVaultLogin() {
    showAppPopup('Login Success', `Welcome back, ${CURRENT_USER_ID}! Vault is open.`, false, true);
    document.getElementById('greetingUserId').textContent = CURRENT_USER_ID;
    document.getElementById('mainViewUsername').textContent = CURRENT_USER_ID;
    document.getElementById('welcomeUser').textContent = CURRENT_USER_ID;
    updateVaultUI();
    showView('mainAppView');
}

function processVaultLogout() {
    CURRENT_MASTER_KEY = null;
    VAULT_DATA = {};
    document.getElementById('masterSecurityKeyInput').value = ''; 
    showAppPopup('Signed Out', 'You have securely signed out. The Master Key has been cleared from memory.', false, true);
    showView('loginGateView');
}

// --- UI / DATA MANAGEMENT ---

function updateVaultUI() {
    document.getElementById('vaultEntriesCount').textContent = Object.keys(VAULT_DATA.entries).length;
    renderVaultEntries();
}

function renderVaultEntries() {
    const listContainer = document.getElementById('vaultListContainer');
    listContainer.innerHTML = '';
    const entries = Object.values(VAULT_DATA.entries);

    if (entries.length === 0) {
        listContainer.innerHTML = '<p class="text-secondary p-4">Your vault is empty. Add a new secret to get started.</p>';
        return;
    }

    entries.sort((a, b) => a.title.localeCompare(b.title));

    entries.forEach(entry => {
        const item = document.createElement('div');
        item.className = 'vault-list-item';
        item.setAttribute('data-id', entry.accessId);
        item.innerHTML = `
            <span class="entry-icon entry-type-${entry.type}">
                ${getEntryIcon(entry.type)}
            </span>
            <span class="entry-title">${entry.title}</span>
            <span class="entry-meta">Type: ${entry.type}</span>
            <button class="action-secondary action-list-view" onclick="viewEntry('${entry.accessId}')">View</button>
        `;
        listContainer.appendChild(item);
    });
}

function getEntryIcon(type) {
    switch(type) {
        case 'login': return '🔑';
        case 'note': return '📝';
        case 'card': return '💳';
        default: return '🔒';
    }
}

/**
 * Displays the decode panel for an entry.
 * @param {string} accessId 
 */
function viewEntry(accessId) {
    const entry = VAULT_DATA.entries[accessId];
    if (!entry) return;

    // Reset decode panel
    document.getElementById('decodeTitle').textContent = entry.title;
    document.getElementById('decodeDetails').innerHTML = '<p class="text-secondary">Decrypting...</p>';
    document.getElementById('decodeEntryId').value = entry.accessId;
    document.getElementById('decodeDeleteButton').onclick = () => confirmDeleteEntry(accessId);

    showView('decodeView');
    
    // Decrypt and display data asynchronously
    const decryptedContent = decryptData(entry.encryptedData);
    if (decryptedContent) {
        const detailsHtml = formatDecryptedContent(entry.type, decryptedContent);
        document.getElementById('decodeDetails').innerHTML = detailsHtml;
    } else {
        document.getElementById('decodeDetails').innerHTML = '<p class="text-danger">Failed to decrypt. Master Key may have changed or data is corrupted.</p>';
    }
}

/**
 * Formats the decrypted JSON content into readable HTML.
 * @param {string} type 
 * @param {string} jsonString 
 * @returns {string} HTML string
 */
function formatDecryptedContent(type, jsonString) {
    try {
        const data = JSON.parse(jsonString);
        let html = `<div class="decode-output-grid">`;
        
        for (const [key, value] of Object.entries(data)) {
            // Skip the title as it's already displayed
            if (key === 'title') continue; 
            
            let displayValue = value;
            let displayKey = key.charAt(0).toUpperCase() + key.slice(1);
            let copyButton = `<button class="action-copy" onclick="copyToClipboard('${value}')">Copy</button>`;

            // Special handling for passwords
            if (key.toLowerCase().includes('password') || key.toLowerCase().includes('pin')) {
                displayValue = '••••••••';
                copyButton = `<button class="action-copy action-danger" onclick="copyToClipboard('${value}')">Copy (Hidden)</button>`;
            }

            html += `
                <div class="grid-label">${displayKey}</div>
                <div class="grid-value">
                    <span class="font-mono">${displayValue}</span>
                    ${copyButton}
                </div>
            `;
        }
        html += '</div>';
        return html;

    } catch (e) {
        return `<p class="text-danger">Failed to parse JSON content: ${e.message}</p><pre>${jsonString}</pre>`;
    }
}


// --- ADD/EDIT ENTRY ---

/**
 * Sets up the add/edit form based on the selected type.
 * @param {string} type 
 */
function setupEntryTypeTabs() {
    const tabs = document.querySelectorAll('.entry-type-tab');
    tabs.forEach(tab => {
        tab.onclick = () => {
            tabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            const type = tab.getAttribute('data-type');
            showEntryForm(type);
        };
    });
    // Default to 'login' tab on load
    document.querySelector('.entry-type-tab[data-type="login"]').click();
}

/**
 * Renders the appropriate form fields for the selected entry type.
 * @param {string} type 
 */
function showEntryForm(type) {
    const formContainer = document.getElementById('entryFormFields');
    formContainer.innerHTML = '';
    
    // Always include Title
    let html = `
        <label for="entryTitle">Title/Service Name</label>
        <input type="text" id="entryTitle" placeholder="e.g., Google, Bank Account, Private Note Title" required>
    `;

    switch (type) {
        case 'login':
            html += `
                <label for="entryUsername">Username/Email</label>
                <input type="text" id="entryUsername" placeholder="your.name@example.com" required>
                <label for="entryPassword">Password</label>
                <input type="password" id="entryPassword" placeholder="••••••••" required>
                <label for="entryUrl">Website URL (Optional)</label>
                <input type="text" id="entryUrl" placeholder="https://www.example.com">
            `;
            break;
        case 'note':
            html += `
                <label for="entryContent">Secret Note Content</label>
                <textarea id="entryContent" rows="8" placeholder="Enter your secret or detailed note here." required></textarea>
            `;
            break;
        case 'card':
            html += `
                <label for="entryCardholder">Cardholder Name</label>
                <input type="text" id="entryCardholder" required>
                <label for="entryCardNumber">Card Number</label>
                <input type="text" id="entryCardNumber" required>
                <label for="entryCvv">CVV/CVC</label>
                <input type="text" id="entryCvv" maxlength="4" required>
                <div class="action-group-pair">
                    <div style="flex-grow: 1;">
                        <label for="entryExpiryMonth">Expiry Month</label>
                        <input type="number" id="entryExpiryMonth" placeholder="MM" min="1" max="12" required>
                    </div>
                    <div style="flex-grow: 1;">
                        <label for="entryExpiryYear">Expiry Year</label>
                        <input type="number" id="entryExpiryYear" placeholder="YYYY" min="${new Date().getFullYear()}" required>
                    </div>
                </div>
            `;
            break;
    }
    
    formContainer.innerHTML = html;
    document.getElementById('saveEntryButton').onclick = () => saveNewEntry(type);
}

/**
 * Collects form data, encrypts it, and saves it to the vault.
 * @param {string} type 
 */
async function saveNewEntry(type) {
    const title = document.getElementById('entryTitle').value.trim();
    if (!title) {
        showAppPopup('Validation Error', 'The title is required.', false);
        return;
    }

    let rawData = { title };
    let isValid = true;

    switch (type) {
        case 'login':
            rawData.username = document.getElementById('entryUsername').value.trim();
            rawData.password = document.getElementById('entryPassword').value;
            rawData.url = document.getElementById('entryUrl').value.trim();
            if (!rawData.username || !rawData.password) isValid = false;
            break;
        case 'note':
            rawData.content = document.getElementById('entryContent').value;
            if (!rawData.content) isValid = false;
            break;
        case 'card':
            rawData.cardholder = document.getElementById('entryCardholder').value.trim();
            rawData.cardNumber = document.getElementById('entryCardNumber').value.trim();
            rawData.cvv = document.getElementById('entryCvv').value.trim();
            rawData.expiryMonth = document.getElementById('entryExpiryMonth').value.trim();
            rawData.expiryYear = document.getElementById('entryExpiryYear').value.trim();
            if (!rawData.cardholder || !rawData.cardNumber || !rawData.cvv) isValid = false;
            break;
    }

    if (!isValid) {
        showAppPopup('Validation Error', 'Please fill in all required fields for this entry type.', false);
        return;
    }

    const jsonString = JSON.stringify(rawData);
    const encryptedData = encryptData(jsonString);

    if (encryptedData) {
        const newId = 'entry_' + Date.now();
        VAULT_DATA.entries[newId] = {
            accessId: newId,
            type: type,
            title: title,
            encryptedData: encryptedData
        };

        // Save to remote storage
        await saveVaultData(); 

        showAppPopup('Success', `New ${type} entry "${title}" saved!`, false, true);
        
        // Reset and return to dashboard
        document.getElementById('entryTitle').value = '';
        showView('mainAppView');
        updateVaultUI();
    } else {
        showAppPopup('Encryption Error', 'Failed to encrypt data. Check if Master Key is set.', false);
    }
}

/**
 * Confirms and deletes a vault entry.
 * @param {string} accessId 
 */
function confirmDeleteEntry(accessId) {
    showAppPopup(
        'Confirm Deletion',
        'Are you sure you want to permanently delete this entry? This action cannot be undone.',
        true,
        false,
        async () => {
            delete VAULT_DATA.entries[accessId];
            await saveVaultData();
            showAppPopup('Deleted', 'Entry permanently removed.', false, true);
            showView('mainAppView');
            updateVaultUI();
        }
    );
}

// --- CONFIGURATION & SETTINGS ---

/**
 * Saves a new user ID. Requires re-saving the entire vault.
 */
async function updateUserID() {
    const newUserId = document.getElementById('updateUserID').value.trim();
    if (!newUserId || newUserId === CURRENT_USER_ID) {
        return;
    }

    const confirmed = await showAppPopup(
        'Confirm Change', 
        `Are you sure you want to change your User ID from "${CURRENT_USER_ID}" to "${newUserId}"? This will update your vault's internal identifier.`, 
        true
    );

    if (confirmed) {
        CURRENT_USER_ID = newUserId;
        VAULT_DATA.userId = newUserId;
        // Save the new ID and re-save the entire vault data with the updated internal ID
        await saveUserId(newUserId);
        await saveVaultData();
        
        document.getElementById('greetingUserId').textContent = CURRENT_USER_ID;
        document.getElementById('mainViewUsername').textContent = CURRENT_USER_ID;
        document.getElementById('welcomeUser').textContent = CURRENT_USER_ID;
        showAppPopup('Success', `User Identifier successfully updated to ${newUserId}`, false, true);
    } else {
        // Revert input field if canceled
        document.getElementById('updateUserID').value = CURRENT_USER_ID;
    }
}

/**
 * Saves a new master key. Requires re-encrypting the entire vault.
 */
async function updateMasterKey() {
    const newMasterKey = document.getElementById('newMasterKeyInput').value;
    const confirmKey = document.getElementById('confirmMasterKeyInput').value;

    if (!newMasterKey || newMasterKey !== confirmKey) {
        showAppPopup('Error', 'New keys do not match or are empty.', false);
        return;
    }

    const confirmed = await showAppPopup(
        'Master Key Change', 
        'WARNING: This will re-encrypt your entire vault. Proceed only if you are certain you will remember the new key.', 
        true
    );

    if (confirmed) {
        // Save current key temporarily to re-encrypt
        const oldKey = CURRENT_MASTER_KEY;
        CURRENT_MASTER_KEY = newMasterKey;
        
        // The easiest way is to re-encrypt the entire VAULT_DATA
        await saveVaultData(); 

        // Clear input fields
        document.getElementById('newMasterKeyInput').value = '';
        document.getElementById('confirmMasterKeyInput').value = '';

        showAppPopup('Success', 'Master Key successfully updated and vault re-encrypted.', false, true);
    }
}

/**
 * Deletes all stored data (User ID, Vault Data, Avatar, Theme).
 */
function wipeAllVaultData() {
    showAppPopup(
        'CRITICAL ACTION: DELETE ALL DATA', 
        'Are you absolutely sure you want to delete ALL data (vault, user ID, avatar, theme)? This is irreversible!', 
        true, 
        false, 
        async () => {
            await remoteRemoveItem(STORAGE_KEY_USER_ID);
            await remoteRemoveItem(STORAGE_KEY_VAULT_DATA);
            await remoteRemoveItem(STORAGE_KEY_AVATAR);
            await remoteRemoveItem(STORAGE_KEY_THEME);
            
            // Reset in-memory state
            CURRENT_MASTER_KEY = null;
            VAULT_DATA = {};
            CURRENT_USER_ID = 'USER';
            
            showAppPopup('Wiped', 'All data has been permanently deleted from storage. You are starting fresh.', false, true);
            // Reinitialize the app
            document.getElementById('vaultUsernameInput').value = '';
            document.getElementById('masterSecurityKeyInput').value = ''; 
            await updateAvatarDisplay(CURRENT_USER_ID);
            showView('loginGateView');
        }
    );
}

// --- AVATAR MANAGEMENT ---

let userAvatarBase64 = null;

function handleAvatarFile(event) {
    const file = event.target.files[0];
    if (!file) return;

    if (file.size > MAX_AVATAR_SIZE_KB * 1024) {
        showAppPopup('File Too Large', `The avatar file must be less than ${MAX_AVATAR_SIZE_KB}KB.`, false);
        event.target.value = ''; // Clear file input
        return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
        userAvatarBase64 = e.target.result;
        updateAvatarDisplay(CURRENT_USER_ID, userAvatarBase64);
    };
    reader.onerror = () => {
        showAppPopup('File Read Error', 'Could not read the selected file.', false);
        userAvatarBase64 = null;
    };
    reader.readAsDataURL(file);
}

async function saveUserAvatar() {
    if (!userAvatarBase64) {
        showAppPopup('No Avatar', 'Please select a file to upload first.', false);
        return;
    }

    await remoteSetItem(STORAGE_KEY_AVATAR, userAvatarBase64);
    showAppPopup('Saved', 'New avatar uploaded and saved.', false, true);
    userAvatarBase64 = null; // Clear staging area
    document.getElementById('avatarFileInput').value = ''; // Clear file input
    // The display is already updated by handleAvatarFile, but we can confirm reload
    await updateAvatarDisplay(CURRENT_USER_ID); 
}

async function removeUserAvatar() {
    await remoteRemoveItem(STORAGE_KEY_AVATAR);
    userAvatarBase64 = null;
    document.getElementById('avatarFileInput').value = '';
    await updateAvatarDisplay(CURRENT_USER_ID);
    showAppPopup('Removed', 'Avatar successfully removed.', false, true);
}

async function updateAvatarDisplay(userId, base64Override = null) {
    const base64Data = base64Override || await remoteGetItem(STORAGE_KEY_AVATAR);
    const avatarImg = document.getElementById('configAvatarImage');
    const avatarInitial = document.getElementById('configAvatarInitial');
    const displayImg = document.getElementById('userAvatarDisplayImage');
    const displayInitial = document.getElementById('userAvatarDisplayInitial');

    const initial = userId ? userId.charAt(0).toUpperCase() : 'U';

    if (base64Data) {
        avatarImg.src = base64Data;
        avatarImg.classList.remove('app-hidden');
        avatarInitial.classList.add('app-hidden');
        
        if(displayImg) displayImg.src = base64Data;
        if(displayImg) displayImg.classList.remove('app-hidden');
        if(displayInitial) displayInitial.classList.add('app-hidden');

    } else {
        avatarImg.classList.add('app-hidden');
        avatarInitial.classList.remove('app-hidden');
        avatarInitial.textContent = initial;

        if(displayImg) displayImg.classList.add('app-hidden');
        if(displayInitial) displayInitial.classList.remove('app-hidden');
        if(displayInitial) displayInitial.textContent = initial;
    }
}

// --- THEME MANAGEMENT ---

async function saveAppTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    await remoteSetItem(STORAGE_KEY_THEME, theme);
    document.getElementById('themeSelector').value = theme;
}

async function loadAppTheme() {
    const storedTheme = await remoteGetItem(STORAGE_KEY_THEME);
    const theme = storedTheme || (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
    document.documentElement.setAttribute('data-theme', theme);
    const themeSelector = document.getElementById('themeSelector');
    if (themeSelector) {
        themeSelector.value = theme;
        themeSelector.onchange = (e) => saveAppTheme(e.target.value);
    }
}

// --- UTILITY FUNCTIONS ---

/**
 * Copies text to the clipboard.
 * @param {string} text - The text to copy.
 */
function copyToClipboard(text) {
    const el = document.createElement('textarea');
    el.value = text;
    document.body.appendChild(el);
    el.select();
    try {
        const successful = document.execCommand('copy');
        if (successful) {
            showAppPopup('Copied', 'Content copied to clipboard!', false, true);
        } else {
            showAppPopup('Copy Error', 'Could not copy text automatically. Please select and copy manually.', false);
        }
    } catch (err) {
        showAppPopup('Copy Error', `Error: ${err.message}`, false);
    }
    document.body.removeChild(el);
}

/**
 * Toggles visibility of the main application views.
 * @param {string} viewId 
 */
function showView(viewId) {
    const views = document.querySelectorAll('.view-container');
    views.forEach(view => {
        view.classList.add('app-hidden');
    });
    document.getElementById(viewId).classList.remove('app-hidden');
    
    // Update active navigation item
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => item.classList.remove('active'));
    
    // Determine the corresponding nav item for the view
    let navItemId;
    if (viewId === 'mainAppView' || viewId === 'decodeView') {
        navItemId = 'navDashboard';
    } else if (viewId === 'addView') {
        navItemId = 'navAdd';
    } else if (viewId === 'settingsView') {
        navItemId = 'navSettings';
    }

    if (navItemId) {
        document.getElementById(navItemId)?.classList.add('active');
    }

    // Always ensure the main header is visible if not in the login gate
    const header = document.getElementById('appHeader');
    if (header) {
        if (viewId === 'loginGateView') {
            header.classList.add('app-hidden');
        } else {
            header.classList.remove('app-hidden');
        }
    }
}

function setupNavigation() {
    document.getElementById('navDashboard').onclick = () => { updateVaultUI(); showView('mainAppView'); };
    document.getElementById('navAdd').onclick = () => showView('addView');
    document.getElementById('navSettings').onclick = () => showView('settingsView');
    document.getElementById('navLogout').onclick = processVaultLogout;
    document.getElementById('updateIDButton').onclick = updateUserID;
    document.getElementById('updateMasterKeyButton').onclick = updateMasterKey;
}


// --- POPUP MODAL CONTROL ---

let popupResolve = null;

/**
 * Shows a custom popup modal (replaces alert/confirm).
 * @param {string} title 
 * @param {string} message 
 * @param {boolean} [needsConfirmation=false] - Whether to show a cancel button.
 * @param {boolean} [isSuccess=false] - Changes the popup styling to green/success.
 * @param {function} [onConfirm=null] - Optional function to execute on confirmation.
 * @returns {Promise<boolean>} Resolves with true if confirmed, false if canceled.
 */
function showAppPopup(title, message, needsConfirmation = false, isSuccess = false, onConfirm = null) {
    const overlay = document.getElementById('popupOverlay');
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

    // Set styling based on type
    const titleEl = document.getElementById('popupTitle');
    const titleColor = isSuccess ? 'var(--color-action-secondary)' : (needsConfirmation ? 'var(--color-action-danger)' : 'var(--color-action-main)');
    titleEl.style.color = titleColor;

    titleEl.textContent = title;
    document.getElementById('popupMessage').textContent = message;

    overlay.classList.remove('app-hidden');
    
    return new Promise(resolve => {
        popupResolve = resolve;
        if (onConfirm) {
            // Override confirm button to run the provided function and then close
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
