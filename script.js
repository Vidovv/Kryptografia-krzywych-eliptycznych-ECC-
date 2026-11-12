'use strict';
const $ = id => document.getElementById(id);
const MAX_SIZE = 15 * 1024 * 1024;

function switchTab(name) {
  document.querySelectorAll('[data-tab]').forEach(button => {
    const active = button.dataset.tab === name;
    button.classList.toggle('active', active);
    button.setAttribute('aria-selected', String(active));
    button.tabIndex = active ? 0 : -1;
  });
  for (const key of ['about', 'keys', 'encrypt', 'decrypt']) $('panel-' + key).classList.toggle('hidden', key !== name);
}
document.querySelectorAll('[data-tab]').forEach(button => button.addEventListener('click', () => switchTab(button.dataset.tab)));

function switchAbout(name) {
  document.querySelectorAll('[data-about]').forEach(button => {
    const active = button.dataset.about === name;
    button.classList.toggle('active', active);
    button.setAttribute('aria-selected', String(active));
    button.tabIndex = active ? 0 : -1;
  });
  for (const key of ['opis', 'publiczny', 'prywatny']) {
    $('about-' + key).classList.toggle('hidden', key !== name);
  }
}
document.querySelectorAll('[data-about]').forEach(button => button.addEventListener('click', () => switchAbout(button.dataset.about)));


function setStatus(id, message, type = '') {
  const element = $(id); element.textContent = message; element.className = 'feedback ' + type;
}
function toBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 32768) binary += String.fromCharCode(...bytes.subarray(i, i + 32768));
  return btoa(binary);
}
function fromBase64(value) {
  const binary = atob(value), bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
async function post(path, payload) {
  let response;
  try { response = await fetch(path, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)}); }
  catch { throw new Error('Brak połączenia z serwerem. Uruchom FastAPI.'); }
  const data = await response.json().catch(() => { throw new Error('Serwer zwrócił nieprawidłową odpowiedź.'); });
  if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : `Błąd HTTP ${response.status}`);
  return data;
}
function download(data, filename, mime = 'application/octet-stream') {
  const url = URL.createObjectURL(new Blob([data], {type: mime}));
  const link = document.createElement('a'); link.href = url; link.download = filename; document.body.appendChild(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
function safeFilename(name) {
  return String(name || 'odszyfrowany_plik').split(/[\\/]/).pop().replace(/[\x00-\x1f]/g, '_') || 'odszyfrowany_plik';
}
async function bindKeyFile(fileInput, textArea) {
  $(fileInput).addEventListener('change', async () => {
    const file = $(fileInput).files[0];
    if (!file) return;
    if (file.size > 64 * 1024) { setStatus(fileInput.startsWith('enc') ? 'encryptStatus' : 'decryptStatus', 'Plik PEM jest zbyt duży.', 'error'); return; }
    $(textArea).value = await file.text();
  });
}
bindKeyFile('encKeyFile', 'encKey');
bindKeyFile('decKeyFile', 'decKey');

$('encryptForm').addEventListener('submit', async event => {
  event.preventDefault();
  const button = $('encryptBtn'); button.disabled = true;
  setStatus('encryptStatus', 'Szyfrowanie w toku...');
  try {
    const file = $('encFile').files[0];
    if (!file) throw new Error('Wybierz plik.');
    if (file.size > MAX_SIZE) throw new Error('Maksymalny rozmiar pliku to 15 MB.');
    const key = $('encKey').value.trim();
    if (!key) throw new Error('Podaj klucz publiczny.');
    const encrypted = await post('/api/files/encrypt', {public_key_pem: key, filename: file.name, file_base64: toBase64(new Uint8Array(await file.arrayBuffer()))});
    download(JSON.stringify(encrypted, null, 2), safeFilename(file.name) + '.ecc', 'application/json');
    setStatus('encryptStatus', 'Plik został zaszyfrowany i pobrany.', 'success');
  } catch (error) { setStatus('encryptStatus', error.message, 'error'); }
  finally { button.disabled = false; }
});
$('decryptForm').addEventListener('submit', async event => {
  event.preventDefault();
  const button = $('decryptBtn'); button.disabled = true;
  setStatus('decryptStatus', 'Odszyfrowywanie w toku...');
  try {
    const file = $('decFile').files[0];
    if (!file) throw new Error('Wybierz plik .ecc.');
    if (file.size > MAX_SIZE * 1.5) throw new Error('Zaszyfrowany plik jest zbyt duży.');
    let encrypted;
    try { encrypted = JSON.parse(await file.text()); }
    catch { throw new Error('Nieprawidłowy plik .ecc (wymagany format JSON).'); }
    const privateKey = $('decKey').value.trim(), password = $('decPassword').value;
    if (!privateKey || !password) throw new Error('Podaj klucz prywatny oraz jego hasło.');
    const result = await post('/api/files/decrypt', {private_key_pem: privateKey, password, encrypted});
    download(fromBase64(result.file_base64), safeFilename(result.filename));
    setStatus('decryptStatus', 'Plik został odszyfrowany i pobrany.', 'success');
  } catch (error) { setStatus('decryptStatus', error.message, 'error'); }
  finally { button.disabled = false; }
});

// Generator używa istniejącego endpointu API. Klucze pozostają tylko w bieżącej karcie.
$('keyForm').addEventListener('submit', async event => {
  event.preventDefault();
  const button = $('generateBtn');
  const password = $('keyPassword').value;
  const confirmation = $('keyPasswordConfirm').value;
  if (!password) { setStatus('keyStatus', 'Podaj hasło.', 'error'); return; }
  if (password !== confirmation) { setStatus('keyStatus', 'Hasła muszą być takie same.', 'error'); return; }
  button.disabled = true;
  $('keyResults').classList.add('hidden');
  $('generatedPublic').value = '';
  $('generatedPrivate').value = '';
  setStatus('keyStatus', 'Generowanie kluczy...');
  try {
    const result = await post('/keys/generate', {password});
    if (typeof result.public_key_pem !== 'string' || typeof result.private_key_pem !== 'string') throw new Error('Serwer nie zwrócił poprawnych kluczy.');
    $('generatedPublic').value = result.public_key_pem;
    $('generatedPrivate').value = result.private_key_pem;
    $('keyResults').classList.remove('hidden');
    setStatus('keyStatus', 'Para kluczy została wygenerowana.', 'success');
  } catch (error) { setStatus('keyStatus', error.message, 'error'); }
  finally { button.disabled = false; }
});

function downloadPem(id, name) {
  const value = $(id).value;
  if (value) download(value, name, 'application/x-pem-file');
}
async function copyPem(id) {
  const value = $(id).value;
  if (!value) return;
  try {
    await navigator.clipboard.writeText(value);
    setStatus('keyStatus', 'Klucz skopiowany do schowka.', 'success');
  } catch {
    $(id).focus(); $(id).select();
    setStatus('keyStatus', 'Nie można skopiować automatycznie. Zaznaczony tekst skopiuj Ctrl+C.', 'error');
  }
}
$('copyPublic').addEventListener('click', () => copyPem('generatedPublic'));
$('copyPrivate').addEventListener('click', () => copyPem('generatedPrivate'));
$('downloadPublic').addEventListener('click', () => downloadPem('generatedPublic', 'public_key.pem'));
$('downloadPrivate').addEventListener('click', () => downloadPem('generatedPrivate', 'private_key.pem'));
$('usePublic').addEventListener('click', () => {
  $('encKey').value = $('generatedPublic').value;
  switchTab('encrypt');
  $('encFile').focus();
});
$('usePrivate').addEventListener('click', () => {
  $('decKey').value = $('generatedPrivate').value;
  $('decPassword').value = $('keyPassword').value;
  switchTab('decrypt');
  $('decFile').focus();
});
