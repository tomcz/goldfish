"use strict";

const errorAlert = document.getElementById("error-alert");
const encryptForm = document.getElementById("encrypt-form");
const decryptForm = document.getElementById("decrypt-form");
const encryptResult = document.getElementById("encrypt-result");
const decryptResult = document.getElementById("decrypt-result");
const decryptKey = document.getElementById("decrypt-key");

const passwordLength = 42;
const passwordAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
decryptKey.pattern = `[${passwordAlphabet}]{${passwordLength}}x[${passwordAlphabet}]{${passwordLength}}`;

function createDecryptLink(pwd, key) {
  return window.location.origin + window.location.pathname + "#" + pwd + "x" + key;
}

function parseDecryptKey() {
  const [pwd, key] = decryptKey.value.split("x");
  return { pwd, key };
}

function setDecryptKeyFromLocation() {
  const hash = window.location.hash;
  if (!!hash) {
    decryptKey.value = hash.substring(1);
    return true;
  }
  return false;
}

// byteArray is a Uint8Array
function encodeBase64(byteArray) {
  if ("toBase64" in byteArray) {
    return byteArray.toBase64();
  }
  return btoa(String.fromCharCode(...byteArray));
}

// b64Text is a string
function decodeBase64(b64Text) {
  if ("fromBase64" in Uint8Array) {
    return Uint8Array.fromBase64(b64Text);
  }
  const binaryString = atob(b64Text);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

function createPassword() {
  const numbers = window.crypto.getRandomValues(new Uint8Array(passwordLength));
  let pwd = "";
  for (const num of numbers) {
    pwd += passwordAlphabet[num % passwordAlphabet.length];
  }
  return pwd;
}

async function pwdToKey(password, salt) {
  const enc = new TextEncoder().encode(password);
  const keyMaterial = await window.crypto.subtle.importKey("raw", enc, "PBKDF2", false, ["deriveBits", "deriveKey"]);
  return window.crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );
}

async function encryptSecret(pwd, plainText) {
  const secret = new TextEncoder().encode(plainText);
  const saltBytes = window.crypto.getRandomValues(new Uint8Array(16));
  const ivBytes = window.crypto.getRandomValues(new Uint8Array(12));

  const key = await pwdToKey(pwd, saltBytes);
  const encBytes = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv: ivBytes }, key, secret);

  return [encodeBase64(saltBytes), encodeBase64(ivBytes), encodeBase64(new Uint8Array(encBytes))].join(".");
}

async function decryptSecret(pwd, cipherText) {
  const [saltText, ivText, encText] = cipherText.split(".");
  const saltBytes = decodeBase64(saltText);
  const ivBytes = decodeBase64(ivText);
  const encBytes = decodeBase64(encText);

  const key = await pwdToKey(pwd, saltBytes);
  const secret = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: ivBytes }, key, encBytes);

  return new TextDecoder().decode(secret);
}

function handleFetchResponse(res) {
  if (res.ok) {
    return res.text();
  }
  if (res.headers.get("Content-Type").startsWith("text/plain")) {
    return res.text().then((txt) => {
      throw new Error(`${res.status}: ${txt}`);
    });
  }
  throw new Error(`${res.status}: ${res.statusText}`);
}

function setSecret(secret, ttl) {
  const body = new URLSearchParams();
  body.set("secret", secret);
  body.set("ttl", ttl);
  const opts = {
    method: "POST",
    body: body,
  };
  return fetch("push", opts).then(handleFetchResponse);
}

function getSecret(secretKey) {
  const body = new URLSearchParams();
  body.set("key", secretKey);
  const opts = {
    method: "POST",
    body: body,
  };
  return fetch("pull", opts).then(handleFetchResponse);
}

function showElement(element) {
  element.style.display = "";
}

function hideElement(element) {
  element.style.display = "none";
}

function disableForm(form) {
  form.querySelector("fieldset").disabled = true;
}

function enableForm(form) {
  form.querySelector("fieldset").disabled = false;
}

function updateErrorAlert(message) {
  errorAlert.textContent = message;
  showElement(errorAlert);
}

function showSection(section) {
  showElement(section);
  window.setTimeout(function () {
    section.querySelector(".focus-target").focus();
  });
}

function updateEncryptResults(pwd, key, ttl) {
  const link = createDecryptLink(pwd, key);
  const ttlTxt = ttl === "1" ? "1 hour" : `${ttl} hours`;
  const expiry = Date.now() + parseInt(ttl) * 60 * 60 * 1000;
  const expiryTxt = new Date(expiry).toLocaleString();

  encryptResult.querySelector(".copy-me").textContent = link;
  encryptResult.querySelector(".expire-in").textContent = ttlTxt;
  encryptResult.querySelector(".expire-at").textContent = expiryTxt;
  showElement(encryptResult);
}

function updateDecryptResults(secret) {
  decryptResult.querySelector(".copy-me").textContent = secret;
  showElement(decryptResult);
}

encryptForm.addEventListener("submit", (evt) => {
  evt.preventDefault();

  const secret = document.getElementById("encrypt-value").value;
  const ttl = document.getElementById("encrypt-ttl").value;
  const pwd = createPassword();

  hideElement(errorAlert);
  hideElement(encryptResult);
  disableForm(encryptForm);

  encryptSecret(pwd, secret)
    .then((cipherText) => {
      return setSecret(cipherText, ttl);
    })
    .then((secretKey) => {
      updateEncryptResults(pwd, secretKey, ttl);
      enableForm(encryptForm);
    })
    .catch((ex) => {
      console.error(ex);
      updateErrorAlert(ex.toString());
      enableForm(encryptForm);
    });
});

decryptForm.addEventListener("submit", (evt) => {
  evt.preventDefault();

  const shared = parseDecryptKey();

  hideElement(errorAlert);
  hideElement(decryptResult);
  disableForm(decryptForm);

  getSecret(shared.key)
    .then((cipherText) => {
      return decryptSecret(shared.pwd, cipherText);
    })
    .then((secret) => {
      updateDecryptResults(secret);
      enableForm(decryptForm);
    })
    .catch((ex) => {
      console.error(ex);
      updateErrorAlert(ex.toString());
      enableForm(decryptForm);
    });
});

decryptKey.addEventListener("input", () => {
  if (decryptKey.validity.patternMismatch) {
    decryptKey.setCustomValidity("Invalid shared key.");
  } else {
    decryptKey.setCustomValidity("");
  }
});

document.querySelectorAll("nav li.logo a").forEach((elt) => {
  elt.href = window.location.origin + window.location.pathname;
});

document.querySelectorAll(".initially-hidden").forEach((elt) => {
  hideElement(elt); // take over hiding from CSS
  elt.classList.remove("initially-hidden");
});

document.querySelectorAll("pre.copy-me").forEach((pre) => {
  pre.addEventListener("click", () => {
    navigator.clipboard.writeText(pre.textContent).then(() => {
      pre.classList.add("is-copied");
      window.setTimeout(function () {
        pre.classList.remove("is-copied");
      }, 1000);
    });
  });
});

document.querySelectorAll("a.tab-link").forEach((elt) => {
  elt.addEventListener("click", (evt) => {
    evt.preventDefault();
    document.querySelectorAll("section.tab-body").forEach((body) => {
      hideElement(body);
    });
    showSection(document.querySelector(elt.hash));
  });
});

if (setDecryptKeyFromLocation()) {
  showSection(document.getElementById("recover-tab"));
} else {
  showSection(document.getElementById("share-tab"));
}

fetch("version")
  .then(handleFetchResponse)
  .then((version) => {
    const elt = document.getElementById("source-link");
    elt.href = `${elt.href}/tree/${version.trim()}`;
  })
  .catch((ex) => {
    console.warn(ex);
  });
