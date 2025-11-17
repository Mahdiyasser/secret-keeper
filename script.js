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
const MAX_AVATAR_SIZE_KB = 1024;

let CURRENT_MASTER_KEY = null;
let VAULT_DATA = {};
let CURRENT_USER_ID = 'USER';

// --- NEW POSTMESSAGE STORAGE UTILITIES (FROM not-working.js) ---

const STORAGE_ORIGIN = 'https://storage.mahdiyasser.site';
let iframe = null; 
let isIframeReady = false;
let commandCounter = 0;
const pendingCommands = {};

window.addEventListener('message', (event) => {
    if (event.origin !== STORAGE_ORIGIN) return;

    const response = event.data;

    if (response.command === 'READY') {
        isIframeReady = true;
        console.log('Storage frame connected and ready.'); 
        return;
    }

    const resolver = pendingCommands[response.id];
    if (resolver) {
        if (response.success) {
            resolver.resolve(response);
        } else {
            if (response.command === 'RETRIEVE' && (response.message === 'Key not found.' || response.data === null)) {
                 resolver.resolve({ data: null, command: response.command }); 
            } else {
                resolver.reject(new Error(response.message || `Storage operation '${response.command}' failed.`));
            }
        }
        delete pendingCommands[response.id];
    }
});

function postToStorage(command, payload) {
    return new Promise((resolve, reject) => {
        if (!iframe) {
            return reject(new Error("Storage frame not initialized."));
        }

        if (!isIframeReady) {
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

async function setAppStorage(key, value) {
    if (value === null) {
        return deleteAppStorage(key);
    }
    await postToStorage('SAVE', { key: key, value: value });
}

async function getAppStorage(key) {
    try {
        const response = await postToStorage('RETRIEVE', { key: key });
        return response.data || null; 
    } catch (e) {
        console.error(`Error retrieving key '${key}':`, e);
        return null; 
    }
}

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
    iframe = document.getElementById('storageFrame'); 
    
    loadAppTheme().then(() => initializeApp()); 

    setupNavigation();
    setupEntryTypeTabs();
    
    document.getElementById('authActionButton').onclick = performAuthentication;
});

async function initializeApp() {
    const storedUserId = await getAppStorage(STORAGE_KEY_USER_ID); 
    
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

// --- ENCRYPTION/DECRYPTION UTILITIES (No change needed) ---

function encryptData(plaintext) {
    if (!CURRENT_MASTER_KEY) throw new Error("Encryption failed: Master Key not set.");
    return CryptoJS.AES.encrypt(plaintext, CURRENT_MASTER_KEY).toString();
}

function decryptData(encryptedText, decryptionKey) {
    if (!decryptionKey) return null;
    try {
        const bytes = CryptoJS.AES.decrypt(encryptedText, decryptionKey);
        if (!bytes || bytes.sigBytes === 0) {
            return null;
        }
        return bytes.toString(CryptoJS.enc.Utf8);
    } catch (e) {
        return null;
    }
}

// -----------------------------------------------------------------
// --- AUTHENTICATION & VAULT MANAGEMENT (Converted to ASYNC) ---
// -----------------------------------------------------------------

async function performAuthentication() {
    const userIdInput = document.getElementById('vaultUsernameInput').value.trim();
    const masterKeyInput = document.getElementById('masterSecurityKeyInput').value;

    if (!userIdInput || !masterKeyInput) {
        return showAppPopup('Missing Information', 'User Identifier and Master Security Key are required.', false, false);
    }

    const isSetup = !(await getAppStorage(STORAGE_KEY_USER_ID)); 
    CURRENT_MASTER_KEY = masterKeyInput;
    
    if (isSetup) {
        await handleInitialSetup(userIdInput);
    } else {
        await handleLoginAttempt(userIdInput);
    }
}

async function handleInitialSetup(userIdInput) {
    await setAppStorage(STORAGE_KEY_USER_ID, userIdInput); 
    VAULT_DATA = { userId: userIdInput, entries: {} };
    
    const encryptedVault = encryptData(JSON.stringify(VAULT_DATA));
    await setAppStorage(STORAGE_KEY_VAULT_DATA, encryptedVault); 

    CURRENT_USER_ID = userIdInput;
    await updateAvatarDisplay(CURRENT_USER_ID); 

    showAppPopup('Setup Complete', 'New Vault created and secured! You are now logged in.', false, true);
    document.getElementById('masterSecurityKeyInput').value = ''; 
    showAuthenticatedApp();
}

async function handleLoginAttempt(userIdInput) {
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
        showAppPopup('Data Error', 'Vault data is corrupted and cannot be loaded.', false, false);
    }
}

async function saveVaultData() {
    try {
        const jsonString = JSON.stringify(VAULT_DATA);
        const encryptedData = encryptData(jsonString);
        await setAppStorage(STORAGE_KEY_VAULT_DATA, encryptedData); 
        return true;
    } catch (e) {
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
            
            const target = e.target.dataset.target;
            document.getElementById(target).classList.remove('app-hidden');
            e.target.classList.add('active');

            if (target === 'decodeDataView') {
                updateAccessKeyList();
            } else if (target === 'storeDataView') {
                clearNewEntryForm();
            } else if (target === 'settingsConfigView') {
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
        case 'note':
            accessIdInput = document.getElementById('noteEntryID');
            entryData.content = document.getElementById('noteEntryContent').value;
            break;
        case 'link':
            accessIdInput = document.getElementById('linkEntryID');
            entryData.address = document.getElementById('linkEntryAddress').value.trim();
            entryData.notes = document.getElementById('linkEntryNotes').value.trim();
            break;
        case 'file':
            accessIdInput = document.getElementById('fileEntryID');
            const fileUploadEl = document.getElementById('fileUpload');
            entryData.fileDataUrl = fileUploadEl.dataset.dataurl || null;
            entryData.fileMimeType = fileUploadEl.dataset.filemimetype || null;
            entryData.fileName = document.getElementById('fileNameDisplay').textContent.replace('File: ', '');
            if (!entryData.fileDataUrl) {
                 return showAppPopup('Error', 'Please select a file to upload.', false, false);
            }
            break;
        default:
            return showAppPopup('Error', 'Unknown entry type selected.', false, false);
    }

    const accessId = accessIdInput.value.trim();
    if (!accessId) {
        return showAppPopup('Error', 'Access ID cannot be empty.', false, false);
    }
    
    // Check for duplicate Access ID
    if (VAULT_DATA.entries[accessId]) {
        return showAppPopup('Error', `An entry with Access ID '<strong>${accessId}</strong>' already exists.`, false, false);
    }

    try {
        const encryptedData = encryptData(JSON.stringify(entryData));
        
        VAULT_DATA.entries[accessId] = {
            type: type,
            encryptedData: encryptedData
        };

        if (await saveVaultData()) {
            showAppPopup('Success', `New ${type} entry '<strong>${accessId}</strong>' saved securely.`, false, true);
            clearNewEntryForm();
        }
    } catch (e) {
        showAppPopup('Encryption Error', e.message, false, false);
    }
}

// --------------------------------------------------------------------
// --- VIEW SPECIFIC FUNCTIONS: DECODE DATA (retrieveSelectedData is ASYNC) ---
// --------------------------------------------------------------------

function updateAccessKeyList() {
    const listContainer = document.getElementById('accessKeyList');
    listContainer.innerHTML = '';
    
    const sortedKeys = Object.keys(VAULT_DATA.entries).sort();

    sortedKeys.forEach(id => {
        const item = document.createElement('div');
        item.className = 'access-key-item';
        item.textContent = id;
        item.dataset.accessId = id;
        
        item.onclick = (e) => {
            document.querySelectorAll('.access-key-item').forEach(i => i.classList.remove('active'));
            e.target.classList.add('active');
            document.getElementById('selectedAccessID').value = id;
            clearDecodedOutput();
        };
        listContainer.appendChild(item);
    });
}

async function retrieveSelectedData() {
    const accessId = document.getElementById('selectedAccessID').value;
    const outputArea = document.getElementById('decodedDataOutput');
    clearDecodedOutput();

    if (!accessId) {
        return showAppPopup('Missing Selection', 'Please select a secret to decode first.', false, false);
    }

    if (CURRENT_MASTER_KEY === null) {
        const tempKey = await promptKeyForDecode();
        if (!tempKey) return;
        CURRENT_MASTER_KEY = tempKey;
    }

    const entry = VAULT_DATA.entries[accessId];
    if (!entry) {
        return showAppPopup('Error', 'Entry not found in vault data.', false, false);
    }

    const decryptedString = decryptData(entry.encryptedData, CURRENT_MASTER_KEY);

    if (decryptedString === null) {
        return showAppPopup('Access Denied', 'Invalid Master Security Key for this entry.', false, false);
    }

    let displayOutput = '';
    try {
        const data = JSON.parse(decryptedString);
        
        switch (data.type) {
            case 'credentials':
                displayOutput = `
                    <h3>Decoded Credential: ${accessId}</h3>
                    <div class="decode-output-grid">
                        <span>Username:</span><code class="decode-value">${data.user}</code>
                        <span>Password:</span><code class="decode-value secret-value">${maskValue(data.pass)}</code>
                        <span class="decode-toggle-btn" onclick="toggleKeyVisibility(this)">Show</span>
                        <span>Notes:</span><code class="decode-value">${data.notes}</code>
                    </div>`;
                break;
            case 'contact':
                displayOutput = `
                    <h3>Decoded Contact: ${accessId}</h3>
                    <div class="decode-output-grid">
                        <span>Name:</span><code class="decode-value">${data.name}</code>
                        <span>Email:</span><code class="decode-value">${data.email}</code>
                        <span>Phone:</span><code class="decode-value">${data.phone}</code>
                        <span>Notes:</span><code class="decode-value">${data.notes}</code>
                    </div>`;
                break;
            case 'note':
                displayOutput = `
                    <h3>Decoded Note: ${accessId}</h3>
                    <div class="decode-output-grid-full">
                        <pre class="decode-value">${data.content}</pre>
                    </div>`;
                break;
            case 'link':
                displayOutput = `
                    <h3>Decoded Link: ${accessId}</h3>
                    <div class="decode-output-grid">
                        <span>Address:</span><code class="decode-value"><a href="${data.address}" target="_blank" rel="noopener noreferrer">${data.address}</a></code>
                        <span>Notes:</span><code class="decode-value">${data.notes}</code>
                    </div>`;
                break;
            case 'file':
                 displayOutput = `
                    <h3>Decoded File: ${accessId}</h3>
                    <div class="decode-output-grid">
                        <span>File Name:</span><code class="decode-value">${data.fileName}</code>
                        <span>File Type:</span><code class="decode-value">${data.fileMimeType}</code>
                        <span>Action:</span><a href="${data.fileDataUrl}" download="${data.fileName}" class="decode-value action-secondary download-link">Download File</a>
                    </div>`;
                break;
            default:
                displayOutput = `<p style="color: var(--color-action-danger);">Unknown entry type: ${data.type}. Raw data: <br><br>${decryptedString}</p>`;
        }
    } catch (e) {
        displayOutput = `<p style="color: var(--color-action-critical);">Data Error: Content for ID '<strong>${accessId}</strong>' is corrupted.</p>`;
    }

    outputArea.innerHTML = displayOutput;

    if (CURRENT_MASTER_KEY !== null && document.getElementById('masterSecurityKeyInput').value === '') {
        CURRENT_MASTER_KEY = null;
    }
}

function deleteSelectedData() {
    const accessId = document.getElementById('selectedAccessID').value;
    if (!accessId) {
        return showAppPopup('Missing Selection', 'Please select a secret to delete first.', false, false);
    }
    
    showAppPopup('Confirm Deletion', `Are you sure you want to <strong>PERMANENTLY</strong> delete the entry: <strong>${accessId}</strong>?`, true, false, async () => {
        delete VAULT_DATA.entries[accessId];
        if (await saveVaultData()) {
             showAppPopup('Success', `Entry '<strong>${accessId}</strong>' deleted.`, false, true);
             document.getElementById('selectedAccessID').value = '';
             clearDecodedOutput();
             updateAccessKeyList();
        }
    });
}

// --------------------------------------------------------------------
// --- CORE UTILITIES ---
// --------------------------------------------------------------------

function maskValue(value) {
    return value && value.length > 5 ? '***' + value.slice(0, 3) + '...' : '***';
}

function clearNewEntryForm() {
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

    const fileUploadEl = document.getElementById('fileUpload');
    if (fileUploadEl) {
        delete fileUploadEl.dataset.dataurl;
        delete fileUploadEl.dataset.filemimetype;
    }

    const firstTab = document.querySelector('#storeDataView .type-tab-btn');
    if(firstTab) firstTab.click();
}

function clearDecodedOutput() {
    document.getElementById('selectedAccessID').value = '';
    document.getElementById('decodedDataOutput').innerHTML = '<p class="text-secondary">Select an entry from the list to decode.</p>';
}

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

function promptKeyForDecode() {
    return showAppPopup(
        'Temporary Key Required',
        'Enter your Master Key to temporarily decrypt and view the selected secret. The key will be cleared from memory after viewing.', 
        false, 
        false,
        () => { /* No-op, key is handled in retrieveSelectedData */ } 
    ).then(confirmed => {
        if (confirmed) {
            const key = document.getElementById('masterSecurityKeyInput').value;
            document.getElementById('masterSecurityKeyInput').value = '';
            return key;
        }
        return null;
    });
}

/**
 * FIXED: The logic for handling input fields (new entry/settings) and displayed secrets (decode view)
 * is now correctly separated and includes a null check to prevent the TypeError.
 */
function toggleKeyVisibility(el) {
    const targetId = el.dataset.target;
    const targetInput = document.getElementById(targetId);

    // Case 1: Input Field Toggle (e.g., for 'credEntryPass')
    if (targetInput && targetInput.tagName === 'INPUT') {
        if (targetInput.type === 'password') {
            targetInput.type = 'text';
            el.textContent = '🙈';
        } else {
            targetInput.type = 'password';
            el.textContent = '👁️';
        }
        return;
    }

    // Case 2: Displayed Secret Toggle (e.g., on the Decode view)
    const container = el.closest('.entry-item');
    let secretSpan = null;
    if (container) {
        secretSpan = container.querySelector('.secret-value');
    }
    
    // FIX for TypeError: Check if the element was found before trying to read properties
    if (!secretSpan) {
        return; 
    }

    if (secretSpan.textContent.startsWith('***') && CURRENT_MASTER_KEY) {
        const accessId = document.getElementById('selectedAccessID').value;
        const entry = VAULT_DATA.entries[accessId];

        if (entry) {
            const decryptedString = decryptData(entry.encryptedData, CURRENT_MASTER_KEY);
            if (decryptedString) {
                try {
                    const data = JSON.parse(decryptedString);
                    secretSpan.textContent = data.pass; 
                    el.textContent = 'Hide';
                } catch(e) {
                    secretSpan.textContent = 'Decryption Failed';
                    el.textContent = 'Show';
                }
            } else {
                 secretSpan.textContent = 'Decryption Failed';
                 el.textContent = 'Show';
            }
        }
    } else {
        const fullValue = secretSpan.textContent;
        secretSpan.textContent = maskValue(fullValue);
        el.textContent = 'Show';
    }
}


// --------------------------------------------------------------------
// --- CONFIGURATION & SETTINGS (updateConfigView is ASYNC) ---
// --------------------------------------------------------------------

function updateConfigView() {
    document.getElementById('updateUserID').value = CURRENT_USER_ID;
}

// updateUserID must be async because it uses async storage
async function updateUserID() {
    const newId = document.getElementById('updateUserID').value.trim();
    if (!newId || newId === CURRENT_USER_ID) return;

    // Update vault structure and storage
    VAULT_DATA.userId = newId;
    
    // The previous storage key was updated to 'skr_userId'
    await setAppStorage(STORAGE_KEY_USER_ID, newId);
    
    // Update master key view and global state
    document.getElementById('vaultUsernameInput').value = newId;
    CURRENT_USER_ID = newId;
    
    // Update avatar display (which uses CURRENT_USER_ID)
    await updateAvatarDisplay(CURRENT_USER_ID); 
    
    // Save vault data to ensure new ID is encrypted in the vault too (though userId is also stored separately)
    await saveVaultData();
    
    showAppPopup('User ID Updated', `User Identifier changed to <strong>${newId}</strong>.`, false, true);
}


function handleAvatarFile(event) {
    const file = event.target.files[0];
    if (!file) return;

    if (file.size > MAX_AVATAR_SIZE_KB * 1024) {
        showAppPopup('File Too Large', `Avatar must be under ${MAX_AVATAR_SIZE_KB}KB.`, false, false);
        event.target.value = '';
        return;
    }

    const reader = new FileReader();
    reader.onload = function(e) {
        const fileUploadEl = document.getElementById('fileUpload'); // Re-using fileUpload for temp data storage
        if (fileUploadEl) {
            fileUploadEl.dataset.dataurl = e.target.result;
            fileUploadEl.dataset.filemimetype = file.type;
        }

        const fileNameDisplay = document.getElementById('fileNameDisplay');
        fileNameDisplay.textContent = `Avatar: ${file.name}`;
        fileNameDisplay.classList.remove('app-hidden');
    };
    reader.readAsDataURL(file);
}

// saveUserAvatar must be async because it uses async storage
async function saveUserAvatar() {
    const fileUploadEl = document.getElementById('fileUpload'); 
    const dataUrl = fileUploadEl.dataset.dataurl;
    
    if (!dataUrl) {
         return showAppPopup('Missing Image', 'Please select an image file first.', false, false);
    }
    
    // The previous storage key was updated to 'skr_avatar'
    await setAppStorage(STORAGE_KEY_AVATAR, dataUrl); 
    
    // Update live display
    await updateAvatarDisplay(CURRENT_USER_ID); 
    
    // Clear the temporary form data
    document.getElementById('avatarFileInput').value = '';
    const fileNameDisplay = document.getElementById('fileNameDisplay');
    fileNameDisplay.textContent = 'No file selected.';
    fileNameDisplay.classList.add('app-hidden');
    
    showAppPopup('Success', 'Avatar image saved.', false, true);
}

// removeUserAvatar must be async because it uses async storage
async function removeUserAvatar() {
    // The previous storage key was updated to 'skr_avatar'
    await deleteAppStorage(STORAGE_KEY_AVATAR);
    await updateAvatarDisplay(CURRENT_USER_ID); 
    showAppPopup('Success', 'Avatar image removed.', false, true);
}

// updateAvatarDisplay must be async because it uses async storage
async function updateAvatarDisplay(userId) {
    const avatarImage = document.getElementById('configAvatarImage');
    const avatarInitial = document.getElementById('configAvatarInitial');

    // The previous storage key was updated to 'skr_avatar'
    const storedAvatar = await getAppStorage(STORAGE_KEY_AVATAR); 

    if (storedAvatar) {
        avatarImage.src = storedAvatar;
        avatarImage.classList.remove('app-hidden');
        if (avatarInitial) avatarInitial.classList.add('app-hidden');
    } else {
        avatarImage.src = '';
        avatarImage.classList.add('app-hidden');
        if (avatarInitial) {
             avatarInitial.textContent = userId.charAt(0).toUpperCase();
             avatarInitial.classList.remove('app-hidden');
        }
    }
}

// -----------------------------------------------------------
// --- THEME MANAGEMENT (Converted to ASYNC) ---
// -----------------------------------------------------------

// loadAppTheme must be async
async function loadAppTheme() {
    const storedTheme = await getAppStorage(STORAGE_KEY_THEME);
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
    await setAppStorage(STORAGE_KEY_THEME, newTheme);
}

// -------------------------------------------------------------
// --- IMPORT/EXPORT/UTILITY FUNCTIONS (Export is ASYNC) ---
// -------------------------------------------------------------

function handleImportFile(event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function(e) {
        showAppPopup('Confirm Import', 'WARNING: Importing vault data will <strong>OVERWRITE</strong> your current vault contents. Are you sure?', true, false, async () => {
             await processImportData(e.target.result);
        });
    };
    reader.readAsText(file);
}

async function processImportData(fileContent) {
    try {
        const importedVault = JSON.parse(fileContent);
        
        if (!importedVault.userId || !importedVault.encryptedData) {
            return showAppPopup('Import Error', 'Invalid vault file structure.', false, false);
        }
        
        // This is a new vault format that only stores encryptedData
        // Need to decrypt the inner vault content to get the entries
        const decryptedString = decryptData(importedVault.encryptedData, CURRENT_MASTER_KEY);

        if (decryptedString === null) {
            return showAppPopup('Import Failed', 'The Master Key provided is invalid for the imported vault file.', false, false);
        }
        
        VAULT_DATA = JSON.parse(decryptedString);

        // Update storage with new data
        await setAppStorage(STORAGE_KEY_USER_ID, importedVault.userId);
        await setAppStorage(STORAGE_KEY_VAULT_DATA, importedVault.encryptedData);
        
        // Update global state
        CURRENT_USER_ID = importedVault.userId;
        document.getElementById('vaultUsernameInput').value = CURRENT_USER_ID;
        document.getElementById('masterSecurityKeyInput').value = ''; 
        
        await updateAvatarDisplay(CURRENT_USER_ID); 
        
        showAppPopup('Import Complete', `Vault for User ID <strong>${CURRENT_USER_ID}</strong> imported successfully.`, false, true);
        showAuthenticatedApp();
        
    } catch (e) {
        showAppPopup('Import Error', 'Could not parse imported data or decryption failed.', false, false);
    }
}

async function exportVaultData() {
    if (CURRENT_MASTER_KEY === null) {
        return showAppPopup('Error', 'You must be logged in to export data.', false, true);
    }
    
    // The new export format includes userId and the encryptedData payload
    const encryptedVault = await getAppStorage(STORAGE_KEY_VAULT_DATA);
    
    const exportObject = {
        userId: CURRENT_USER_ID,
        encryptedData: encryptedVault,
        exportDate: new Date().toISOString()
    };
    
    const jsonString = JSON.stringify(exportObject, null, 2);
    
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `vault_export_${CURRENT_USER_ID}_${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    
    showAppPopup('Export Complete', 'Vault data downloaded securely.', false, true);
}


function wipeAllVaultData() {
    showAppPopup('DANGER ZONE', '<strong>WARNING:</strong> This will <strong>PERMANENTLY</strong> wipe all encrypted data, User ID, and Avatar image. Are you <strong>ABSOLUTELY</strong> sure?', true, false, async () => {
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
