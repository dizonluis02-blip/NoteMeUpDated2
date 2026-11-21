(function () {
    const accountsKey = "notemeAccounts";
    const currentUserKey = "notemeCurrentUser";
    const returnToKey = "notemeReturnTo";

    function readAccounts() {
        try {
            const accounts = JSON.parse(localStorage.getItem(accountsKey) || "[]");
            return Array.isArray(accounts) ? accounts.filter(account =>
                account &&
                typeof account.username === "string" &&
                typeof account.email === "string" &&
                typeof account.salt === "string" &&
                typeof account.passwordHash === "string"
            ) : [];
        } catch {
            return [];
        }
    }

    function getCurrentUser() {
        try {
            const user = JSON.parse(localStorage.getItem(currentUserKey) || "null");
            return user && typeof user.username === "string" ? user : null;
        } catch {
            return null;
        }
    }

    function setFormError(element, message) {
        if (element) element.textContent = message;
    }

    function toHex(buffer) {
        return Array.from(new Uint8Array(buffer), byte =>
            byte.toString(16).padStart(2, "0")
        ).join("");
    }

    async function hashPassword(password, salt) {
        if (!window.crypto?.subtle || !window.TextEncoder) {
            throw new Error("Secure password hashing is unavailable in this browser. Open NoteMe using HTTPS or localhost.");
        }

        const key = await window.crypto.subtle.importKey(
            "raw",
            new TextEncoder().encode(password),
            "PBKDF2",
            false,
            ["deriveBits"]
        );
        const bits = await window.crypto.subtle.deriveBits({
            name: "PBKDF2",
            salt,
            iterations: 120000,
            hash: "SHA-256"
        }, key, 256);

        return toHex(bits);
    }

    function makeSalt() {
        const salt = new Uint8Array(16);
        window.crypto.getRandomValues(salt);
        return toHex(salt);
    }

    function bytesFromHex(hex) {
        const bytes = new Uint8Array(hex.length / 2);
        for (let index = 0; index < bytes.length; index += 1) {
            bytes[index] = parseInt(hex.slice(index * 2, index * 2 + 2), 16);
        }
        return bytes;
    }

    function getReturnTarget() {
        const target = sessionStorage.getItem(returnToKey);
        sessionStorage.removeItem(returnToKey);

        if (!target) return "index.html";

        try {
            const url = new URL(target);
            const appDirectory = new URL(".", window.location.href).pathname;
            if (url.protocol === window.location.protocol &&
                url.host === window.location.host &&
                url.pathname.startsWith(appDirectory)) {
                return url.href;
            }
        } catch {
            return "index.html";
        }

        return "index.html";
    }

    function completeAuthentication(user) {
        localStorage.setItem(currentUserKey, JSON.stringify({
            username: user.username,
            name: user.name,
            email: user.email
        }));
        window.location.assign(getReturnTarget());
    }

    window.notemeRequireAccount = function () {
        if (getCurrentUser()) return true;

        try {
            sessionStorage.setItem(returnToKey, window.location.href);
        } catch {
            // Continue to login even if this browser cannot preserve a return location.
        }

        alert("Please sign up or log in before adding items to your cart.");
        window.location.assign("login.html");
        return false;
    };

    const signedIn = Boolean(getCurrentUser());
    document.querySelectorAll("#loginLink, #menuLogin, #menuSignup, .header-signup").forEach(link => {
        if (signedIn) link.style.display = "none";
    });
    document.querySelectorAll("#logoutBtn, #menuLogout").forEach(link => {
        if (signedIn) link.style.display = "";
        link.addEventListener("click", event => {
            event.preventDefault();
            localStorage.removeItem(currentUserKey);
            window.location.assign("index.html");
        });
    });

    const signupForm = document.getElementById("signupForm");
    if (signupForm) {
        signupForm.addEventListener("submit", async event => {
            event.preventDefault();
            const errorElement = document.getElementById("signupError");
            const submitButton = signupForm.querySelector('[type="submit"]');
            const username = document.getElementById("su-username").value.trim();
            const name = document.getElementById("su-name").value.trim();
            const email = document.getElementById("su-email").value.trim();
            const password = document.getElementById("su-password").value;

            if (readAccounts().some(account =>
                account.username.toLowerCase() === username.toLowerCase() ||
                account.email.toLowerCase() === email.toLowerCase()
            )) {
                setFormError(errorElement, "That username or email is already registered. Log in or use different details.");
                return;
            }

            submitButton.disabled = true;
            setFormError(errorElement, "");
            try {
                const salt = makeSalt();
                const account = {
                    username,
                    name,
                    email,
                    salt,
                    passwordHash: await hashPassword(password, bytesFromHex(salt))
                };
                const accounts = readAccounts();
                accounts.push(account);
                localStorage.setItem(accountsKey, JSON.stringify(accounts));
                completeAuthentication(account);
            } catch (error) {
                setFormError(errorElement, error.message || "Unable to create your account. Please try again.");
            } finally {
                submitButton.disabled = false;
            }
        });
    }

    const loginForm = document.getElementById("loginForm");
    if (loginForm) {
        loginForm.addEventListener("submit", async event => {
            event.preventDefault();
            const errorElement = document.getElementById("loginError");
            const submitButton = loginForm.querySelector('[type="submit"]');
            const username = document.getElementById("login-username").value.trim();
            const password = document.getElementById("login-password").value;

            const account = readAccounts().find(item =>
                item.username.toLowerCase() === username.toLowerCase()
            );
            if (!account) {
                setFormError(errorElement, "Account not found. Please sign up first.");
                return;
            }

            submitButton.disabled = true;
            setFormError(errorElement, "");
            try {
                const passwordHash = await hashPassword(password, bytesFromHex(account.salt));
                if (passwordHash !== account.passwordHash) {
                    setFormError(errorElement, "Incorrect username or password.");
                    return;
                }
                completeAuthentication(account);
            } catch (error) {
                setFormError(errorElement, error.message || "Unable to log in. Please try again.");
            } finally {
                submitButton.disabled = false;
            }
        });
    }
})();
