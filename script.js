"use strict";

const API_URL = "/api";
const $ = (id) => document.getElementById(id);
const fields = ["ciphertext", "nonce", "salt", "ephemeral_public_key"];

function showStatus(id, message, type = "") {
  const target = $(id);
  target.textContent = message;
  target.className = `feedback ${type}`;
}

function switchTab(tabName) {
  document.querySelectorAll("[data-tab]").forEach((button) => {
    const selected = button.dataset.tab === tabName;
    button.classList.toggle("active", selected);
    button.setAttribute("aria-selected", String(selected));
    button.tabIndex = selected ? 0 : -1;
  });
  ["keys", "encrypt", "decrypt"].forEach((name) => {
    $("panel-" + name).classList.toggle("hidden", name !== tabName);
  });
}

document.querySelectorAll("[data-tab]").forEach((button) => {
  button.addEventListener("click", () => switchTab(button.dataset.tab));
  button.addEventListener("keydown", (event) => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const tabs = [...document.querySelectorAll("[data-tab]")];
    const idx = tabs.indexOf(button);
    const next =
      event.key === "Home"
        ? 0
        : event.key === "End"
          ? tabs.length - 1
          : (idx + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) %
            tabs.length;
    tabs[next].focus();
    switchTab(tabs[next].dataset.tab);
  });
});

async function request(path, payload) {
  let response;
  try {
    response = await fetch(API_URL + path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  } catch {
    throw new Error(
      "Nie można połączyć się z API. Sprawdź, czy FastAPI i serwer frontendowy działają.",
    );
  }
  let data;
  try {
    data = await response.json();
  } catch {
    throw new Error(
      `Nieprawidłowa odpowiedź serwera (HTTP ${response.status}).`,
    );
  }
  if (!response.ok) {
    const detail = data.detail;
    const message =
      typeof detail === "string"
        ? detail
        : Array.isArray(detail)
          ? detail.map((item) => item.msg || "Niepoprawne dane").join("; ")
          : `Błąd HTTP ${response.status}`;
    throw new Error(message);
  }
  return data;
}

async function run(buttonId, statusId, operation) {
  const button = $(buttonId);
  button.disabled = true;
  showStatus(statusId, "Trwa przetwarzanie...");
  try {
    await operation();
    showStatus(statusId, "Operacja zakończona pomyślnie.", "success");
  } catch (error) {
    showStatus(statusId, error.message || "Wystąpił nieznany błąd.", "error");
  } finally {
    button.disabled = false;
  }
}

$("generateBtn").addEventListener("click", () =>
  run("generateBtn", "statusKeys", async () => {
    const password = $("generatePassword").value;
    if (!password.trim())
      throw new Error("Wprowadź hasło do klucza prywatnego.");
    $("generatedResults").classList.add("hidden");
    const result = await request("/keys/generate", { password });
    if (
      typeof result.public_key_pem !== "string" ||
      typeof result.private_key_pem !== "string"
    ) {
      throw new Error("API nie zwróciło poprawnych kluczy.");
    }
    $("publicKeyGenerated").value = result.public_key_pem;
    $("privateKeyGenerated").value = result.private_key_pem;
    $("generatedResults").classList.remove("hidden");
  }),
);

$("encryptBtn").addEventListener("click", () =>
  run("encryptBtn", "statusEn", async () => {
    const public_key_pem = $("keyEn").value.trim();
    const message = $("messageEn").value;
    if (!public_key_pem) throw new Error("Wprowadź klucz publiczny.");
    if (!message.trim()) throw new Error("Wpisz wiadomość do zaszyfrowania.");
    $("encryptResults").classList.add("hidden");
    const result = await request("/encrypt", { public_key_pem, message });
    if (!fields.every((field) => typeof result[field] === "string")) {
      throw new Error("API zwróciło niekompletne dane szyfrogramu.");
    }
    const encrypted = Object.fromEntries(
      fields.map((field) => [field, result[field]]),
    );
    $("resultEn").value = JSON.stringify(encrypted, null, 2);
    $("encryptResults").classList.remove("hidden");
  }),
);

$("decryptBtn").addEventListener("click", () =>
  run("decryptBtn", "statusDe", async () => {
    const private_key_pem = $("keyDe").value.trim();
    const password = $("decryptPassword").value;
    const content = $("messageDe").value.trim();
    if (!private_key_pem) throw new Error("Wprowadź klucz prywatny.");
    if (!password.trim()) throw new Error("Wprowadź hasło klucza prywatnego.");
    if (!content) throw new Error("Wklej zaszyfrowane dane JSON.");
    let encrypted;
    try {
      encrypted = JSON.parse(content);
    } catch {
      throw new Error("Zaszyfrowane dane muszą być poprawnym JSON-em.");
    }
    if (
      !encrypted ||
      Array.isArray(encrypted) ||
      typeof encrypted !== "object" ||
      !fields.every(
        (field) =>
          typeof encrypted[field] === "string" && encrypted[field].length > 0,
      )
    ) {
      throw new Error(
        "JSON musi zawierać: ciphertext, nonce, salt i ephemeral_public_key.",
      );
    }
    $("decryptResults").classList.add("hidden");
    const result = await request("/decrypt", {
      private_key_pem,
      password,
      encrypted: Object.fromEntries(
        fields.map((field) => [field, encrypted[field]]),
      ),
    });
    if (typeof result.message !== "string")
      throw new Error("API nie zwróciło wiadomości.");
    $("resultDe").value = result.message;
    $("decryptResults").classList.remove("hidden");
  }),
);

$("usePublicBtn").addEventListener("click", () => {
  $("keyEn").value = $("publicKeyGenerated").value;
  switchTab("encrypt");
});
$("usePrivateBtn").addEventListener("click", () => {
  $("keyDe").value = $("privateKeyGenerated").value;
  $("decryptPassword").value = $("generatePassword").value;
  switchTab("decrypt");
});
$("useEncryptedBtn").addEventListener("click", () => {
  $("messageDe").value = $("resultEn").value;
  switchTab("decrypt");
});

document.querySelectorAll("[data-copy]").forEach((button) => {
  button.addEventListener("click", async () => {
    const value = $(button.dataset.copy).value;
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      const original = button.textContent;
      button.textContent = "Skopiowano";
      setTimeout(() => {
        button.textContent = original;
      }, 1400);
    } catch {
      button.textContent = "Nie udało się skopiować";
    }
  });
});
document.querySelectorAll("[data-toggle-password]").forEach((button) => {
  button.addEventListener("click", () => {
    const input = $(button.dataset.togglePassword);
    const visible = input.type === "password";
    input.type = visible ? "text" : "password";
    button.textContent = visible ? "Ukryj" : "Pokaż";
    button.setAttribute("aria-label", visible ? "Ukryj hasło" : "Pokaż hasło");
  });
});
