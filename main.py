
import json
from getpass import getpass
from cryptography.exceptions import InvalidTag

from key_generator import (
    generate_keys,
    save_keys,
    load_keys,
    verify_keys
)

from encryption import encrypt_message, decrypt_message


def main():
    private_key = None
    public_key = None

    while True:
        print("\n========== ECC CRYPTO ==========")
        print("1. Generuj klucze ECC")
        print("2. Eksportuj klucze PEM")
        print("3. Importuj klucze PEM")
        print("4. Zaszyfruj wiadomość")
        print("5. Odszyfruj wiadomość")
        print("0. Zakończ")

        choice = input("\nWybierz opcję: ")

        if choice == "1":
            private_key, public_key, *_ = generate_keys()
            print("Wygenerowano nową parę kluczy ECC.")




        elif choice == "2":

            if private_key is None or public_key is None:
                print("Najpierw wygeneruj lub zaimportuj klucze.")

                continue

            confirmation = input(

                "Eksport nadpisze istniejące pliki PEM. "

                "Kontynuować? (t/n): "

            )

            if confirmation.lower() != "t":
                continue


            password = getpass("Podaj hasło do klucza prywatnego: ")

            repeat_password = getpass("Powtórz hasło: ")


            if password != repeat_password:
                print("Hasła nie są identyczne.")

                continue

            if not password:
                print("Hasło nie może być puste.")

                continue


            try:


                save_keys(private_key, public_key, password)


                print("Klucze zapisano.")

                print("Klucz prywatny zabezpieczono hasłem.")


            except (OSError, ValueError, TypeError) as error:

                print(f"Typ błędu: {type(error).__name__}")

                print(f"Szczegóły: {error}")



        elif choice == "3":

            password = getpass("Podaj hasło do klucza prywatnego: ")

            try:

                loaded_private, loaded_public = load_keys(password)

                if not verify_keys(loaded_private, loaded_public):
                    print("Pliki zawierają niezgodne klucze.")

                    continue

                private_key = loaded_private

                public_key = loaded_public

                print("Poprawnie zaimportowano klucze.")



            except (OSError, ValueError, TypeError) as error:

                print("Nie udało się zaimportować kluczy.")

                print(f"Typ błędu: {type(error).__name__}")

                print(f"Szczegóły: {error}")

        elif choice == "4":
            if public_key is None:
                print("Najpierw wygeneruj lub zaimportuj klucze.")
                continue

            message = input("Podaj wiadomość: ")
            encrypted = encrypt_message(message, public_key)

            with open("encrypted.json", "w", encoding="utf-8") as file:
                json.dump(encrypted, file, indent=4)

            print("Wiadomość zaszyfrowana.")
            print("Szyfrogram zapisano w encrypted.json.")

        elif choice == "5":
            if private_key is None:
                print("Najpierw zaimportuj lub wygeneruj klucze.")
                continue

            try:
                with open("encrypted.json", "r", encoding="utf-8") as file:
                    encrypted = json.load(file)

                message = decrypt_message(encrypted, private_key)
                print("Odszyfrowana wiadomość:", message)

            except FileNotFoundError:
                print("Nie znaleziono pliku encrypted.json.")

            except (InvalidTag, ValueError, KeyError, TypeError):
                print("Nie udało się odszyfrować wiadomości.")

        elif choice == "0":
            print("Zakończono program.")
            break

        else:
            print("Nieprawidłowa opcja.")


if __name__ == "__main__":
    main()
