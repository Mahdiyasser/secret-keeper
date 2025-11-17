/*
    SCRIPT.JS - FIXED VERSION
    Secure Vault Keeper Application Logic with AES Encryption
    Uses cross-origin PostMessage storage utilities (now ASYNC)
*/

// --- CONSTANTS & GLOBAL STATE ---

// Using the new, correct keys for the new storage system ('skr_')
const STORAGE_KEY_USER_ID = 'skr_userId';
const STORAGE_KEY_VAULT_DATA = 'skr_vaultData';
const STORAGE_KEY_AVATAR = 'skr_avatar';
const STORAGE_KEY_THEME = 'skr_theme';
const MAX_AVATAR_SIZE_KB = 1024; // 1024KB limit

let CURRENT_MASTER_KEY = null;
let VAULT_DATA = {}; // Structure: { userId: '...', entries: { accessId: { type: '...', encryptedData: '...' } } }
let CURRENT_USER_ID = 'USER';

// --- NEW POSTMESSAGE STORAGE UTILITIES (FROM not-working.js) ---

const STORAGE_ORIGIN = 'https://storage.mahdiyasser.site';
let iframe = null; 
let isIframeReady = false;
let commandCounter = 0;
const pendingCommands = {};

// Listens for responses from the storage iframe
window.addEventListener('message', (event) => {
    if (event.origin !== STORAGE_ORIGIN) return;

    const response = event.data;

    if (response.command === 'READY') {
        isIframeReady = true;
        console.log('Storage frame connected and ready.'); 
        return;
    }

    // Look up the pending command by its ID
    const resolver = pendingCommands[response.id];
    if (resolver) {
        if (response.success) {
            resolver.resolve(response);
        } else {
            // Special handling for RETRIEVE command when key is not found, to mimic localStorage's 'null' return
            if (response.command === 'RETRIEVE' && (response.message === 'Key not found.' || response.data === null)) {
                 resolver.resolve({ data: null, command: response.command }); 
            } else {
                resolver.reject(new Error(response.message || `Storage operation '${response.command}' failed.`));
            }
        }
        delete pendingCommands[response.id];
    }
});

/**
 * Posts a message to the iframe and returns a promise for the response.
 */
function postToStorage(command, payload) {
    return new Promise((resolve, reject) => {
        // Ensure iframe is defined (set in DOMContentLoaded)
        if (!iframe) {
            return reject(new Error("Storage frame not initialized."));
        }

        if (!isIframeReady) {
            // Simple retry mechanism for race condition at startup
            if (commandCounter < 10 && command !== 'READY') { 
                setTimeout(() => {
                     postToStorage(command, payload).then(resolve).catch(reject);
                }, 500);
                return;
            } else {
                 return reject(new Error("Storage frame not ready after timeout."));
            }
        }
        
        const id = commandCounter++;
        pendingCommands[id] = { resolve, reject };

        iframe.contentWindow.postMessage({
            command: command,
            payload: payload,
            id: id
        }, STORAGE_ORIGIN);
    });
}

/**
 * Saves a value to the cross-origin storage (ASYNC).
 */
async function setAppStorage(key, value) {
    if (value === null) {
        return deleteAppStorage(key);
    }
    await postToStorage('SAVE', { key: key, value: value });
}

/**
 * Retrieves a value from the cross-origin storage (ASYNC).
 */
async function getAppStorage(key) {
    try {
        const response = await postToStorage('RETRIEVE', { key: key });
        return response.data || null; 
    } catch (e) {
        console.error(`Error retrieving key '${key}':`, e);
        return null; 
    }
}

/**
 * Deletes a value from the cross-origin storage (ASYNC).
 */
async function deleteAppStorage(key) {
    try {
        await postToStorage('DELETE', { key: key });
    } catch (e) {
        console.warn(`Error deleting key '${key}':`, e);
    }
}

// -------------------------------------------------------------------
// --- INITIALIZATION & UI SETUP (Original Logic converted to ASYNC) ---
// -------------------------------------------------------------------

document.addEventListener('DOMContentLoaded', () => {
    // 1. Initialize iframe reference
    iframe = document.getElementById('storageFrame'); 
    
    // loadAppTheme and initializeApp must be awaited/chained now.
    // Call loadAppTheme() first, then initializeApp()
    loadAppTheme().then(() => initializeApp()); 

    setupNavigation();
    setupEntryTypeTabs();
    
    // Wire up buttons for authentication view
    document.getElementById('authActionButton').onclick = performAuthentication;
});

// initializeApp must now be async to use async storage
async function initializeApp() {
    // Use async storage
    const storedUserId = await getAppStorage(STORAGE_KEY_USER_ID); 
    
    if (storedUserId) {
        CURRENT_USER_ID = storedUserId;
        document.getElementById('vaultUsernameInput').value = storedUserId;
        // updateAvatarDisplay must be awaited as it uses async storage internally
        await updateAvatarDisplay(CURRENT_USER_ID); 
        document.getElementById('updateUserID').value = CURRENT_USER_ID;
    } else {
        await updateAvatarDisplay(CURRENT_USER_ID);
    }
    showView('loginGateView'); 
}

// --- ENCRYPTION/DECRYPTION UTILITIES (No change needed) ---

/**
 * Encrypts a plaintext string using the current master key.
 */
function encryptData(plaintext) {
    if (!CURRENT_MASTER_KEY) throw new Error("Encryption failed: Master Key not set.");
    return CryptoJS.AES.encrypt(plaintext, CURRENT_MASTER_KEY).toString();
}

/**
 * Decrypts an encrypted string using a given key.
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

// -----------------------------------------------------------------
// --- AUTHENTICATION & VAULT MANAGEMENT (Converted to ASYNC) ---
// -----------------------------------------------------------------

// performAuthentication must be async
async function performAuthentication() {
    const userIdInput = document.getElementById('vaultUsernameInput').value.trim();
    const masterKeyInput = document.getElementById('masterSecurityKeyInput').value;

    if (!userIdInput || !masterKeyInput) {
        return showAppPopup('Missing Information', 'User Identifier and Master Security Key are required.', false, false);
    }

    // Check if the vault is being set up for the first time using async storage
    const isSetup = !(await getAppStorage(STORAGE_KEY_USER_ID)); 
    CURRENT_MASTER_KEY = masterKeyInput;
    
    if (isSetup) {
        await handleInitialSetup(userIdInput);
    } else {
        await handleLoginAttempt(userIdInput);
    }
}

// handleInitialSetup must be async
async function handleInitialSetup(userIdInput) {
    // Use async storage
    await setAppStorage(STORAGE_KEY_USER_ID, userIdInput); 
    VAULT_DATA = { userId: userIdInput, entries: {} };
    
    // Encrypt the empty vault object with the new key
    const encryptedVault = encryptData(JSON.stringify(VAULT_DATA));
    // Use async storage
    await setAppStorage(STORAGE_KEY_VAULT_DATA, encryptedVault); 

    CURRENT_USER_ID = userIdInput;
    await updateAvatarDisplay(CURRENT_USER_ID); 

    showAppPopup('Setup Complete', 'New Vault created and secured! You are now logged in.', false, true);
    document.getElementById('masterSecurityKeyInput').value = ''; 
    showAuthenticatedApp();
}

// handleLoginAttempt must be async
async function handleLoginAttempt(userIdInput) {
    // Use async storage
    const storedEncryptedVault = await getAppStorage(STORAGE_KEY_VAULT_DATA); 
    const storedUserId = await getAppStorage(STORAGE_KEY_USER_ID); 

    if (storedUserId !== userIdInput) {
        return showAppPopup('Login Failed', 'The User Identifier does not match the stored account.', false, false);
    }

    const decryptedVaultString = decryptData(storedEncryptedVault, CURRENT_MASTER_KEY);

    if (decryptedVaultString === null) {
        return showAppPopup('Access Denied', 'Invalid Master Security Key. Please try again.', false, false);
    }

    try {
        VAULT_DATA = JSON.parse(decryptedVaultString);
        CURRENT_USER_ID = userIdInput;
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
 * Persists the current VAULT_DATA object to cross-origin storage (encrypted).
 * MUST BE ASYNC now.
 */
async function saveVaultData() {
    try {
        const jsonString = JSON.stringify(VAULT_DATA);
        const encryptedData = encryptData(jsonString);
        // Use async storage
        await setAppStorage(STORAGE_KEY_VAULT_DATA, encryptedData); 
        return true;
    } catch (e) {
        console.error("Save Vault Error:", e);
        showAppPopup('Storage Error', 'Could not save vault data. The storage frame might be unresponsive.', false, false);
        return false;
    }
}

function showAuthenticatedApp() {
    showView('authenticatedAppGrid');
    updateAccessKeyList();
    const firstTab = document.querySelector('.nav-link-btn[data-target="storeDataView"]');
    if(firstTab) firstTab.click(); 
}

function processVaultLogout() {
    CURRENT_MASTER_KEY = null;
    VAULT_DATA = {};
    document.getElementById('masterSecurityKeyInput').value = ''; 
    showAppPopup('Signed Out', 'You have securely signed out. The Master Key has been cleared from memory.', false, true);
    showView('loginGateView');
}


// --- UI/UTILITY FUNCTIONS (No major storage changes) ---

function showView(viewId) {
    document.getElementById('loginGateView').classList.add('app-hidden');
    document.getElementById('authenticatedAppGrid').classList.add('app-hidden');
    
    const targetElement = document.getElementById(viewId);
    if (targetElement) {
        targetElement.classList.remove('app-hidden');
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

// ----------------------------------------------------------------------
// --- VIEW SPECIFIC FUNCTIONS: STORE DATA (storeNewEntry is ASYNC) ---
// ----------------------------------------------------------------------

// This function must be async because it calls saveVaultData
async function storeNewEntry(type) {
    if (CURRENT_MASTER_KEY === null) {
        return showAppPopup('Error', 'You must be logged in to save data.', false, true);
    }
    
    let entryData = { type: type, timestamp: Date.now() };
    let accessIdInput;

    switch (type) {
        case 'credentials':
            accessIdInput = document.getElementById('credEntryID');
            entryData.user = document.getElementById('credEntryUser').value.trim();
            entryData.pass = document.getElementById('credEntryPass').value;
            entryData.notes = document.getElementById('credEntryNotes').value.trim();
            break;
        case 'contact': 
            accessIdInput = document.getElementById('contactEntryID');
            entryData.name = document.getElementById('contactEntryName').value.trim();
            entryData.email = document.getElementById('contactEntryEmail').value.trim();
            entryData.phone = document.getElementById('contactEntryPhone').value.trim();
            entryData.notes = document.getElementById('contactEntryNotes').value.trim();
            break;
        case 'securenote': 
            accessIdInput = document.getElementById('noteEntryID');
            entryData.content = document.getElementById('noteEntryContent').value.trim();
            break;
        case 'link':
            accessIdInput = document.getElementById('linkEntryID');
            entryData.address = document.getElementById('linkEntryAddress').value.trim();
            entryData.notes = document.getElementById('linkEntryNotes').value.trim();
            break;
        case 'file':
            accessIdInput = document.getElementById('fileEntryID');
            const fileUpload = document.getElementById('fileUpload');
            const dataUrl = fileUpload.dataset.dataurl;
            if (!dataUrl) {
                 return showAppPopup('Missing Information', 'File data is required.', false, false);
            }
            entryData.fileName = document.getElementById('fileNameDisplay').textContent;
            entryData.fileMimeType = fileUpload.dataset.filemimetype;
            entryData.fileData = dataUrl;
            break;
        default:
            return showAppPopup('Error', 'Invalid entry type selected.', false, false);
    }

    const accessId = accessIdInput.value.trim();
    
    // Basic validation based on your original working.js logic
    if (!accessId || (type === 'securenote' && !entryData.content) || (type === 'credentials' && (!entryData.user || !entryData.pass))) {
         return showAppPopup('Missing Information', 'Title/Access ID and content fields are required.', false, false);
    }

    if (VAULT_DATA.entries[accessId]) {
        return showAppPopup('Error', `An entry with the ID '<strong>${accessId}</strong>' already exists.`, false, false);
    }

    // Encrypt the full entry data object
    const encryptedData = encryptData(JSON.stringify(entryData));
    VAULT_DATA.entries[accessId] = { type: type, encryptedData: encryptedData };
    
    if (await saveVaultData()) { // AWAIT the save operation
        showAppPopup('Success', `New secret '<strong>${accessId}</strong>' saved securely!`, false, true);
        clearEntryForm();
        updateAccessKeyList();
    }
}

// --------------------------------------------------------------------
// --- VIEW SPECIFIC FUNCTIONS: DECODE DATA (retrieve/delete ASYNC) ---
// --------------------------------------------------------------------

function updateAccessKeyList() {
    const listContainer = document.getElementById('accessKeyList');
    listContainer.innerHTML = '';
    const entries = VAULT_DATA.entries || {};
    const accessIds = Object.keys(entries).sort();

    if (accessIds.length === 0) {
        listContainer.innerHTML = '<p style="color: var(--color-text-secondary); padding: 10px;">No secrets saved yet.</p>';
        return;
    }

    accessIds.forEach(id => {
        const item = document.createElement('div');
        item.className = 'access-key-item';
        item.textContent = id;
        item.setAttribute('data-access-id', id);
        item.onclick = (e) => {
            document.querySelectorAll('.access-key-item').forEach(i => i.classList.remove('active'));
            e.target.classList.add('active');
            document.getElementById('selectedAccessID').value = id;
            clearDecodedOutput();
        };
        listContainer.appendChild(item);
    });
}

// retrieveSelectedData must be async because it uses promptKeyForDecode (which returns a promise)
async function retrieveSelectedData() {
    const accessId = document.getElementById('selectedAccessID').value;
    const outputArea = document.getElementById('decodedDataOutput');
    clearDecodedOutput();

    if (!accessId) {
        return showAppPopup('Missing Selection', 'Please select a secret to decode first.', false, false);
    }

    // Check if the Master Key is set. If not, prompt for it.
    if (CURRENT_MASTER_KEY === null) {
        const tempKey = await promptKeyForDecode(); // AWAIT
        if (!tempKey) return; // User cancelled
        // We temporarily store the key here for decryption, but clear it later if it wasn't the login key
        CURRENT_MASTER_KEY = tempKey; 
    }

    const entry = VAULT_DATA.entries[accessId];
    if (!entry) {
        return showAppPopup('Error', `No entry found with ID: **${accessId}**`, false, true);
    } 

    // Decrypt the entry using the current master key
    let decryptedString = decryptData(entry.encryptedData, CURRENT_MASTER_KEY);
    
    // If decryption fails, clear the temporary key if applicable
    if (!decryptedString) {
        // Clear the key if we used a temporary one (i.e., the login key field is empty)
        if (CURRENT_MASTER_KEY !== null && document.getElementById('masterSecurityKeyInput').value === '') {
             CURRENT_MASTER_KEY = null;
        }
        return showAppPopup('Error', 'Decryption failed. Invalid Master Security Key or corrupted data.', false, true);
    }
    
    document.getElementById('decodeOutput').classList.remove('app-hidden');
    document.getElementById('decodedType').textContent = entry.type.charAt(0).toUpperCase() + entry.type.slice(1);
    
    let displayOutput = '';
    
    try {
        const data = JSON.parse(decryptedString);
        document.getElementById('decodedDate').textContent = new Date(data.timestamp).toLocaleString();

        // Populate decoded content based on type
        switch (data.type) {
            case 'credentials':
                displayOutput = `
                    <div class="decoded-item"><strong>Username:</strong> <span>${data.user}</span> <button class="copy-btn" onclick="copyToClipboard('${data.user}', this)">Copy</button></div>
                    <div class="decoded-item"><strong>Password:</strong> <span class="secret-value">${maskValue(data.pass)}</span> <button class="reveal-btn" onclick="toggleKeyVisibility(this)">Show</button> <button class="copy-btn" onclick="copyToClipboard('${data.pass}', this)">Copy</button></div>
                    <div class="decoded-item"><strong>Notes:</strong> <span>${data.notes || 'N/A'}</span></div>
                `;
                break;
            case 'contact':
                displayOutput = `
                    <div class="decoded-item"><strong>Name:</strong> <span>${data.name}</span></div>
                    <div class="decoded-item"><strong>Email:</strong> <span>${data.email || 'N/A'}</span></div>
                    <div class="decoded-item"><strong>Phone:</strong> <span>${data.phone || 'N/A'}</span></div>
                    <div class="decoded-item"><strong>Notes:</strong> <span>${data.notes || 'N/A'}</span></div>
                `;
                break;
            case 'securenote':
                displayOutput = `
                    <textarea id="decodedContent" readonly>${data.content}</textarea>
                    <button class="copy-btn full-width" onclick="copyToClipboard('${data.content}', this)">Copy Note</button>
                `;
                break;
            case 'link':
                 displayOutput = `
                    <div class="decoded-item"><strong>URL:</strong> <a href="${data.address}" target="_blank">${data.address}</a> <button class="copy-btn" onclick="copyToClipboard('${data.address}', this)">Copy</button></div>
                    <div class="decoded-item"><strong>Notes:</strong> <span>${data.notes || 'N/A'}</span></div>
                `;
                break;
            case 'file':
                // Setup file download area
                document.getElementById('fileDownloadArea').classList.remove('app-hidden');
                const downloadButton = document.getElementById('downloadFileButton');
                downloadButton.textContent = `Download: ${data.fileName}`;
                downloadButton.dataset.dataurl = data.fileData;
                downloadButton.dataset.filename = data.fileName;
                downloadButton.dataset.filemimetype = data.fileMimeType;
                
                displayOutput = `<p>File data successfully retrieved and ready for download.</p>`;
                break;
            default:
                displayOutput = `<p style="color: var(--color-action-danger);">Unknown entry type: ${data.type}. Raw data: <br><br>${decryptedString}</p>`;
        }
    } catch (e) {
        displayOutput = `<p style="color: var(--color-action-critical);">Data Error: Content for ID '<strong>${accessId}</strong>' is corrupted.</p>`;
    }
    outputArea.innerHTML = displayOutput;

    // Reset temporary key if applicable (i.e., if the master key input is empty)
    if (CURRENT_MASTER_KEY !== null && document.getElementById('masterSecurityKeyInput').value === '') {
         CURRENT_MASTER_KEY = null;
    }
}


// deleteSelectedData must be async because its callback calls saveVaultData
function deleteSelectedData() {
    const accessId = document.getElementById('selectedAccessID').value;
    if (!accessId) {
        return showAppPopup('Missing Selection', 'Please select a secret to delete first.', false, false);
    }

    // The callback must be async to use await saveVaultData()
    showAppPopup('Confirm Deletion', `Are you sure you want to <strong>PERMANENTLY</strong> delete the secret with ID: <strong>${accessId}</strong>? This action cannot be reversed.`, true, false, async () => {
        
        if (VAULT_DATA.entries[accessId]) {
            delete VAULT_DATA.entries[accessId];
            
            if (await saveVaultData()) { // AWAIT the save operation
                showAppPopup('Success', `Secret '<strong>${accessId}</strong>' has been permanently deleted.`, false, true);
                clearDecodedOutput();
                updateAccessKeyList();
            }
        } else {
             showAppPopup('Error', 'Entry not found in vault.', false, true);
        }
    });
}


// -------------------------------------------------------------
// --- CONFIGURATION FUNCTIONS (Converted to ASYNC) ---
// -------------------------------------------------------------

// updateUserID must be async
async function updateUserID() {
    const oldId = CURRENT_USER_ID;
    const newId = document.getElementById('updateUserID').value.trim();

    if (!newId || newId === oldId) {
        return showAppPopup('Error', 'Please enter a valid, new User ID.', false, true);
    }

    const confirmed = await showAppPopup('Confirm Change', `Change User ID from **${oldId}** to **${newId}**? This ID is used for storage key.`, true, false);
    if (!confirmed) return;

    try {
        // 1. Update the VAULT_DATA structure
        VAULT_DATA.userId = newId;

        // 2. Encrypt and save the vault (with new ID inside)
        const encryptedData = encryptData(JSON.stringify(VAULT_DATA));
        await setAppStorage(STORAGE_KEY_VAULT_DATA, encryptedData); // AWAIT

        // 3. Save the new User ID as the storage key for future loads
        await setAppStorage(STORAGE_KEY_USER_ID, newId); // AWAIT

        CURRENT_USER_ID = newId;
        document.getElementById('vaultUsernameInput').value = newId;
        
        // Update UI elements that show the ID
        document.getElementById('headerUsername').textContent = newId;
        document.getElementById('sidebarUsername').textContent = `User: ${newId}`;
        
        await updateAvatarDisplay(CURRENT_USER_ID); // AWAIT
        
        showAppPopup('Success', `User ID successfully updated to **${newId}**!`, false, true);

    } catch (e) {
        console.error("User ID Update Error:", e);
        showAppPopup('Error', 'Failed to update User ID. Please check console for details.', false, true);
        // Attempt to revert state if saving failed
        VAULT_DATA.userId = oldId;
    }
}

// wipeAllVaultData must ensure its callback is async
function wipeAllVaultData() {
    // The callback must be async to use await deleteAppStorage()
    showAppPopup('DANGER ZONE', '<strong>WARNING:</strong> This will <strong>PERMANENTLY</strong> wipe all encrypted data, User ID, and Avatar image. Are you <strong>ABSOLUTELY</strong> sure?', true, false, async () => {
        // Use async storage
        await deleteAppStorage(STORAGE_KEY_USER_ID); 
        await deleteAppStorage(STORAGE_KEY_VAULT_DATA);
        await deleteAppStorage(STORAGE_KEY_AVATAR);
        await deleteAppStorage(STORAGE_KEY_THEME);
        
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

// -------------------------------------------------------------
// --- AVATAR MANAGEMENT (Converted to ASYNC) ---
// -------------------------------------------------------------

// updateAvatarDisplay must be async to retrieve from storage
async function updateAvatarDisplay(userId) {
    // Use async storage
    const avatarData = await getAppStorage(STORAGE_KEY_AVATAR); 
    const initial = userId.charAt(0).toUpperCase();
    
    // Assuming elements based on HTML structure
    const elements = [
        { initial: document.getElementById('headerAvatarInitial'), img: document.getElementById('headerAvatarImage') },
        { initial: document.getElementById('configAvatarInitial'), img: document.getElementById('configAvatarImage') }
    ];

    elements.forEach(el => {
        if (el.initial && el.img) {
            if (avatarData) {
                el.img.src = avatarData;
                el.img.classList.remove('app-hidden');
                el.initial.classList.add('app-hidden');
            } else {
                el.img.classList.add('app-hidden');
                el.initial.classList.remove('app-hidden');
                el.initial.textContent = initial;
            }
        }
    });
}

function handleAvatarFile(event) {
    const file = event.target.files[0];
    if (file && file.size > MAX_AVATAR_SIZE_KB * 1024) {
        event.target.value = ''; // Clear file input
        showAppPopup('Error', `File size exceeds the limit of ${MAX_AVATAR_SIZE_KB}KB.`, false, true);
    }
}

// saveUserAvatar must be async (and its reader.onload handler)
function saveUserAvatar() { // Original was not async, but it must be now because its inner function uses await
    const fileInput = document.getElementById('avatarFileInput');
    const file = fileInput.files[0];

    if (!file) {
        return showAppPopup('Error', 'Please select an image file to upload.', false, true);
    }

    const reader = new FileReader();
    // The onload function must be async to use setAppStorage
    reader.onload = async (e) => { // ASYNC
        const dataUrl = e.target.result;
        try {
            // Use async storage
            await setAppStorage(STORAGE_KEY_AVATAR, dataUrl); // AWAIT
            await updateAvatarDisplay(CURRENT_USER_ID); // AWAIT
            showAppPopup('Success', 'Avatar image saved successfully!', false, true);
            fileInput.value = ''; // Clear file input
        } catch(err) {
            showAppPopup('Error', `Failed to save avatar: ${err.message}`, false, true);
        }
    };
    reader.readAsDataURL(file);
}

// removeUserAvatar must be async
async function removeUserAvatar() {
    // Use async storage
    await deleteAppStorage(STORAGE_KEY_AVATAR); // AWAIT
    await updateAvatarDisplay(CURRENT_USER_ID); // AWAIT
    showAppPopup('Success', 'Avatar image removed.', false, true);
}


// -----------------------------------------------------------
// --- THEME MANAGEMENT (Converted to ASYNC) ---
// -----------------------------------------------------------

// loadAppTheme must be async
async function loadAppTheme() {
    const storedTheme = await getAppStorage(STORAGE_KEY_THEME); // AWAIT
    const theme = storedTheme || 'dark';
    document.documentElement.setAttribute('data-theme', theme);
    const toggle = document.getElementById('themeToggle');
    if (toggle) {
        toggle.textContent = theme === 'dark' ? '☀️' : '🌙';
        toggle.onclick = toggleAppTheme;
    }
}

// toggleAppTheme must be async
async function toggleAppTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', newTheme);
    document.getElementById('themeToggle').textContent = newTheme === 'dark' ? '☀️' : '🌙';
    await setAppStorage(STORAGE_KEY_THEME, newTheme); // AWAIT
}


// -------------------------------------------------------------
// --- IMPORT/EXPORT/UTILITY FUNCTIONS (Export is ASYNC) ---
// -------------------------------------------------------------

function handleImportFile(event) {
    const file = event.target.files[0];
    if (!file) return;

    // The callback must be async to use await setAppStorage()
    showAppPopup('Confirm Overwrite', 'Importing a backup will <strong>OVERWRITE</strong> your current vault data. Proceed?', true, false, async () => {
        const reader = new FileReader();
        reader.onload = async (e) => { // ASYNC
            try {
                const importedData = JSON.parse(e.target.result);
                if (!importedData.encryptedVaultData || !importedData.userId) {
                    throw new Error("Invalid backup file structure.");
                }
                
                // Use async set storage wrappers
                await setAppStorage(STORAGE_KEY_VAULT_DATA, importedData.encryptedVaultData);
                await setAppStorage(STORAGE_KEY_USER_ID, importedData.userId);

                // Re-initialize app to log in with the imported ID
                document.getElementById('vaultUsernameInput').value = importedData.userId;
                showAppPopup('Import Complete', 'Vault data successfully imported! Please re-enter your Master Security Key to log in.', false, true);
                
                CURRENT_MASTER_KEY = null; 
                VAULT_DATA = {};
                initializeApp(); 
                showView('loginGateView');
            } catch (error) {
                showAppPopup('Import Failed', `Error: ${error.message}`, false, true);
            }
        };
        reader.readAsText(file);
    });
}

// exportVaultData must be async now to fetch data
async function exportVaultData() {
    // Use async storage to get the encrypted vault data
    const encryptedVaultData = await getAppStorage(STORAGE_KEY_VAULT_DATA);
    
    if (!encryptedVaultData) {
        return showAppPopup('Export Error', 'No vault data to export.', false, true);
    }
    
    const exportObject = {
        userId: CURRENT_USER_ID,
        encryptedVaultData: encryptedVaultData,
        timestamp: Date.now()
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


function clearEntryForm() {
    // Clear fields across all tabs
    document.getElementById('credEntryID').value = '';
    document.getElementById('credEntryUser').value = '';
    document.getElementById('credEntryPass').value = '';
    document.getElementById('credEntryNotes').value = '';

    document.getElementById('contactEntryID').value = '';
    document.getElementById('contactEntryName').value = '';
    document.getElementById('contactEntryEmail').value = '';
    document.getElementById('contactEntryPhone').value = '';
    document.getElementById('contactEntryNotes').value = '';
    
    document.getElementById('noteEntryID').value = '';
    document.getElementById('noteEntryContent').value = '';

    document.getElementById('linkEntryID').value = '';
    document.getElementById('linkEntryAddress').value = '';
    document.getElementById('linkEntryNotes').value = '';

    document.getElementById('fileEntryID').value = '';
    document.getElementById('fileUpload').value = '';
    document.getElementById('fileNameDisplay').textContent = 'No file selected.';
    document.getElementById('fileNameDisplay').classList.add('app-hidden');
    
    // Clear file data attributes
    const fileUploadEl = document.getElementById('fileUpload');
    if (fileUploadEl) {
        delete fileUploadEl.dataset.dataurl;
        delete fileUploadEl.dataset.filemimetype;
    }

    // Activate the first tab after clear (e.g., credentials)
    const firstTab = document.querySelector('#storeDataView .type-tab-btn');
    if(firstTab) firstTab.click(); 
}

function clearDecodedOutput() {
    document.getElementById('selectedAccessID').value = '';
    document.getElementById('decodedDataOutput').innerHTML = '<p style="color: var(--color-text-secondary);">Content will appear here after successful decryption.</p>';
    document.getElementById('decodedType').textContent = 'N/A';
    document.getElementById('decodedDate').textContent = 'N/A';
    document.getElementById('decodeOutput').classList.add('app-hidden');
    document.getElementById('fileDownloadArea').classList.add('app-hidden');
    document.querySelectorAll('.access-key-item').forEach(i => i.classList.remove('active'));
}

function updateConfigView() {
    document.getElementById('updateUserID').value = CURRENT_USER_ID;
    // Avatar display is updated in updateAvatarDisplay which is called on init and on avatar change
}


function handleFileUpload(event) {
    const file = event.target.files[0];
    const fileNameDisplay = document.getElementById('fileNameDisplay');
    const fileUploadEl = document.getElementById('fileUpload');
    
    if (!file) {
        fileNameDisplay.textContent = 'No file selected.';
        fileNameDisplay.classList.add('app-hidden');
        delete fileUploadEl.dataset.dataurl;
        delete fileUploadEl.dataset.filemimetype;
        return;
    }
    
    if (file.size > MAX_AVATAR_SIZE_KB * 1024) {
        event.target.value = '';
        fileNameDisplay.textContent = 'File too large!';
        fileNameDisplay.classList.remove('app-hidden');
        return showAppPopup('Error', `File size exceeds the limit of ${MAX_AVATAR_SIZE_KB}KB.`, false, true);
    }

    fileNameDisplay.textContent = file.name;
    fileNameDisplay.classList.remove('app-hidden');

    const reader = new FileReader();
    reader.onload = (e) => {
        fileUploadEl.dataset.dataurl = e.target.result;
        fileUploadEl.dataset.filemimetype = file.type;
    };
    reader.readAsDataURL(file);
}

function downloadDecryptedFile() {
    const downloadButton = document.getElementById('downloadFileButton');
    const dataUrl = downloadButton.dataset.dataurl;
    const fileName = downloadButton.dataset.filename || 'downloaded_file';
    const mimeType = downloadButton.dataset.filemimetype || 'application/octet-stream';

    if (!dataUrl) {
        return showAppPopup('Error', 'No file data found for download.', false, true);
    }

    const a = document.createElement('a');
    a.href = dataUrl;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    showAppPopup('Download', `Downloading ${fileName}...`, true, true);
}


// --- POPUP/HELPER UTILITIES ---

let popupResolve = null;

function showAppPopup(title, message, needsConfirmation = false, isSuccess = true, onConfirm = null) {
    const overlay = document.getElementById('popupOverlay');
    
    document.getElementById('popupTitle').textContent = title;
    document.getElementById('popupMessage').innerHTML = message;
    
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
    
    // Returns a promise that resolves to true/false for confirmation
    return new Promise(resolve => {
        popupResolve = resolve;
        if (onConfirm) {
            confirmBtn.onclick = () => {
                closeAppPopup(true);
                // Execute the callback, which may be an async function
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

/**
 * Prompts user for the Master Key and returns it (used for temporary decryption).
 */
function promptKeyForDecode() {
    return new Promise(resolve => {
        const overlay = document.getElementById('popupOverlay');
        const originalConfirmText = document.querySelector('#popupControls .action-confirm').textContent;
        
        document.getElementById('popupTitle').textContent = 'Security Check Required';
        document.getElementById('popupMessage').innerHTML = 'For security, please re-enter your Master Security Key to decrypt the selected item: <br><br>' + '<input type="password" id="tempDecodeKeyInput" placeholder="Master Security Key" style="width: 100%; margin: 10px 0;">';
        
        const confirmBtn = document.querySelector('#popupControls .action-confirm');
        const cancelBtn = document.querySelector('#popupControls .action-cancel');
        
        confirmBtn.textContent = 'Decrypt';
        cancelBtn.classList.remove('app-hidden');

        const keyAttemptHandler = () => {
            const tempKey = document.getElementById('tempDecodeKeyInput').value;
            // Restore button text
            confirmBtn.textContent = originalConfirmText; 
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
        // Ensure the input exists before trying to focus
        const tempInput = document.getElementById('tempDecodeKeyInput');
        if (tempInput) {
             tempInput.focus();
        }
    });
}


function copyToClipboard(text, buttonElement) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    document.body.appendChild(textarea);
    textarea.select();
    try {
        document.execCommand('copy');
        if (buttonElement) {
            buttonElement.textContent = 'Copied!';
            setTimeout(() => {
                buttonElement.textContent = 'Copy';
            }, 1500);
        }
    } catch (err) {
        showAppPopup('Error', 'Failed to copy text. Please copy manually.', false, true);
    }
    document.body.removeChild(textarea);
}

function toggleKeyVisibility(el) {
    const secretSpan = el.parentElement.querySelector('.secret-value');
    
    // FIX: Add null check to prevent TypeError when 'secretSpan' is not found.
    if (!secretSpan) {
        console.warn("Could not find the password element. Check HTML structure for .secret-value.");
        return; 
    }
    
    // We only decrypt if we have the CURRENT_MASTER_KEY
    if (secretSpan.textContent.startsWith('***') && CURRENT_MASTER_KEY) {
        // Need to retrieve the encrypted data to decrypt the password
        const accessId = document.getElementById('selectedAccessID').value;
        const entry = VAULT_DATA.entries[accessId];

        if (entry) {
            const decryptedString = decryptData(entry.encryptedData, CURRENT_MASTER_KEY);
            if (decryptedString) {
                try {
                    const data = JSON.parse(decryptedString);
                    secretSpan.textContent = data.pass; // Pass is the full decrypted password
                    el.textContent = 'Hide';
                } catch(e) {
                    secretSpan.textContent = 'Decryption Failed';
                }
            } else {
                 secretSpan.textContent = 'Decryption Failed';
            }
        }
    } else {
        // Mask the value again
        const fullValue = secretSpan.textContent;
        secretSpan.textContent = maskValue(fullValue);
        el.textContent = 'Show';
    }
}

function maskValue(value) {
    // Only mask if the value is long enough to bother
    return value.length > 5 ? '***' + value.slice(0, 3) + '...' : '***';
}

// NOTE: The function generateOTP is explicitly omitted as it was not in your original "working" file.
