"This is a high-security, standalone desktop application built to do two things perfectly: generate mathematically unbreakable passwords, and lock them inside encrypted tokens using a Master Password. It doesn't save anything to the cloud or a local file—it acts as a secure, temporary workspace to create and protect passwords on the fly."

### The 3-Step Workflow

The app is designed around a clean, three-tab process:

**1. Generate (Creating the Secret)**

* **Unique-Character Passwords:** It generates passwords where a character is never repeated twice. The app dynamically calculates the maximum possible length (up to 94 characters) based on the specific character types you choose to include (uppercase, lowercase, numbers, symbols, and excluding confusing characters like 'l' and '1').
* **Passphrases:** Alternatively, it can string together random dictionary words (like `Amber-Glacier-Falcon!93`) for something easy to type but hard to guess.
* **Live Strength Meter:** As you tweak the password, a live meter calculates its cryptographic "entropy" (how many centuries it would take a supercomputer to guess it).

**2. Encrypt (Locking the Secret)**

* You take the password you just generated and lock it using a **Master Password**.
* **Strict Rules:** The app refuses to encrypt unless your Master Password is actually strong (at least 12 characters, mixing upper, lower, numbers, and symbols).
* **The Output:** It spits out a scrambled, copy-pasteable text token. You can safely save this token anywhere—in a simple text file, a notes app, or an email—because it is completely unreadable without the Master Password.

**3. Decrypt (Unlocking the Secret)**

* When you actually need to log into a website, you paste that scrambled token back into the app, type your Master Password, and it reveals the original password.
* **Auto-Hide:** To prevent someone from reading the password over your shoulder, the app automatically wipes the decrypted password from the screen after 30 seconds of inactivity.

### Under-the-Hood Security Features (For Technical Folks)

If you need to explain *why* it is secure, you can highlight these four architectural choices:

* **Military-Grade Crypto:** It uses **AES-256-GCM**. This not only encrypts the password but adds a cryptographic "seal." If a hacker alters even one letter of your encrypted token, the app will instantly reject it as tampered.
* **Brute-Force Protection:** It runs the Master Password through **1,000,000 iterations of PBKDF2**. This takes a fraction of a second for the app to do once, but makes it computationally impossible for a hacker to mass-guess passwords offline.
* **RAM Zeroing (Memory Hygiene):** Standard apps leave passwords sitting in your computer's RAM (memory) even after you close them, where malware can scrape them. This app explicitly overwrites those memory blocks with zeroes (`0x00`) the second it finishes encrypting or decrypting.
* **Non-Blocking Architecture:** Heavy cryptographic math is pushed to background threads, meaning the modern, dark-mode user interface never freezes or lags, even while doing millions of calculations.
