// Client-side decryption script using Web Crypto API

async function decryptContent() {
  const input = document.getElementById('password-input');
  const errorDiv = document.getElementById('decrypt-error');
  const password = input.value;

  if (!password) {
    showError('请输入密码');
    return;
  }

  try {
    // Get encrypted data
    const dataElement = document.getElementById('encrypted-data');
    const encryptedData = JSON.parse(dataElement.textContent);

    // Convert base64 to ArrayBuffer
    const salt = base64ToBuffer(encryptedData.salt);
    const iv = base64ToBuffer(encryptedData.iv);
    const encrypted = base64ToBuffer(encryptedData.encrypted);
    const tag = base64ToBuffer(encryptedData.tag);

    // Derive key from password
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);

    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      passwordBuffer,
      { name: 'PBKDF2' },
      false,
      ['deriveBits', 'deriveKey']
    );

    // Get iterations from encrypted data (default to 100000 for backward compatibility)
    const iterations = encryptedData.iterations || 100000;

    const key = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: iterations,
        hash: 'SHA-256',
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );

    // Combine encrypted data with auth tag
    const ciphertext = new Uint8Array(encrypted.byteLength + tag.byteLength);
    ciphertext.set(new Uint8Array(encrypted), 0);
    ciphertext.set(new Uint8Array(tag), encrypted.byteLength);

    // Decrypt
    const decrypted = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv,
      },
      key,
      ciphertext
    );

    // Convert to string
    const decoder = new TextDecoder();
    const decryptedContent = decoder.decode(decrypted);

    // Replace encrypted wrapper with decrypted content
    const wrapper = document.getElementById('encrypted-content');
    wrapper.outerHTML = `<div class="article-content">${decryptedContent}</div>`;

    // Hide error
    errorDiv.style.display = 'none';
  } catch (error) {
    console.error('Decryption failed:', error);
    showError('密码错误，请重试');
  }
}

function showError(message) {
  const errorDiv = document.getElementById('decrypt-error');
  errorDiv.textContent = message;
  errorDiv.style.display = 'block';
}

function base64ToBuffer(base64) {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

// Allow Enter key to submit
document.addEventListener('DOMContentLoaded', () => {
  const input = document.getElementById('password-input');
  if (input) {
    input.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        decryptContent();
      }
    });
    input.focus();
  }
});
