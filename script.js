
const keyEn = document.getElementById("keyEn");
const messageEn = document.getElementById("messageEn");
const resultEn = document.getElementById("resultEn");
const statusEn = document.getElementById("statusEn");

const keyDe = document.getElementById("keyDe");
const messageDe = document.getElementById("messageDe");
const resultDe = document.getElementById("resultDe");
const statusDe = document.getElementById("statusDe");

const encryptBtn = document.getElementById("encryptBtn");
const decryptBtn = document.getElementById("decryptBtn");

const API_URL = "http://localhost:8000";

async function processData(operation) {

    const encrypt = operation === "encrypt";

    const key = encrypt ? keyEn.value : keyDe.value;
    const text = encrypt ? messageEn.value : messageDe.value;

    const result = encrypt ? resultEn : resultDe;
    const status = encrypt ? statusEn : statusDe;

    if (key.trim() === "" || text.trim() === "") {
        status.textContent = "Wypełnij oba pola!";
        return;
    }

    const endpoint = encrypt ? "/encrypt" : "/decrypt";

    result.textContent = "";
    status.textContent = "Przetwarzanie...";

    encryptBtn.disabled = true;
    decryptBtn.disabled = true;

    try {
        const response = await fetch(API_URL + endpoint, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                key: key,
                text: text
            })
        });

        if (!response.ok) {
            throw new Error("Błąd API: " + response.status);
        }

        const data = await response.json();

        if (typeof data.result !== "string") {
            throw new Error("Nieprawidłowa odpowiedź API");
        }

        result.textContent = data.result;
        status.textContent = "Operacja zakończona.";

    } catch (error) {
        status.textContent = "Błąd: " + error.message;

    } finally {
        encryptBtn.disabled = false;
        decryptBtn.disabled = false;
    }
}

encryptBtn.addEventListener("click", function () {
    processData("encrypt");
});

decryptBtn.addEventListener("click", function () {
    processData("decrypt");
});
