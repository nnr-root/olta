// The feed UI intentionally builds DOM nodes without inserting event HTML.
(() => {
    "use strict";

    const feed = document.getElementById("feed");
    const status = document.getElementById("connection-status");
    const tokenForm = document.getElementById("token-form");
    const tokenInput = document.getElementById("viewer-token");
    const audioControl = document.getElementById("audio-control");
    let socket = null;
    let muted = true;
    let notificationCount = 0;

    function encodeToken(token) {
        const bytes = new TextEncoder().encode(token);
        let binary = "";
        bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
        return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
    }

    function websocketURL() {
        const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
        return `${scheme}//${window.location.host}/ws`;
    }

    function tokenFromFragment() {
        const params = new URLSearchParams(window.location.hash.slice(1));
        const token = params.get("token") || "";
        if (token) {
            sessionStorage.setItem("olta.feed.viewerToken", token);
            history.replaceState(null, "", window.location.pathname + window.location.search);
        }
        return token;
    }

    function connect(token) {
        if (socket) {
            socket.close();
        }
        const protocols = ["olta.v1"];
        if (token) {
            protocols.push("olta.auth." + encodeToken(token));
        }
        status.textContent = "Connecting…";
        tokenForm.hidden = true;
        socket = new WebSocket(websocketURL(), protocols);

        socket.addEventListener("open", () => {
            status.textContent = "Connected";
            status.className = "notification is-success";
        });
        socket.addEventListener("close", () => {
            status.textContent = "Disconnected. Enter the configured viewer token to reconnect.";
            status.className = "notification is-warning";
            tokenForm.hidden = false;
            socket = null;
        });
        socket.addEventListener("error", () => {
            status.textContent = "Unable to connect to the feed.";
            status.className = "notification is-danger";
        });
        socket.addEventListener("message", (event) => {
            try {
                renderEvent(JSON.parse(event.data));
            } catch (_) {
                status.textContent = "The feed received an invalid event.";
                status.className = "notification is-danger";
            }
        });
    }

    function textElement(tag, className, value) {
        const element = document.createElement(tag);
        if (className) {
            element.className = className;
        }
        element.textContent = typeof value === "string" ? value : "";
        return element;
    }

    function renderEvent(event) {
        const box = document.createElement("div");
        box.className = "box";
        const article = document.createElement("article");
        article.className = "media";
        const content = document.createElement("div");
        content.className = "media-content content";
        content.appendChild(textElement("strong", "", event.event));
        content.appendChild(document.createTextNode(" "));
        content.appendChild(textElement("small", "", event.time));
        content.appendChild(document.createElement("br"));
        content.appendChild(textElement("span", "", event.message));

        if (event.event === "Captured Session" && typeof event.tokens === "string" && event.tokens !== "") {
            const button = textElement("button", "token-button", "View protected tokens");
            button.type = "button";
            const tokenSpace = textElement("pre", "token-space", event.tokens);
            tokenSpace.hidden = true;
            button.addEventListener("click", () => {
                tokenSpace.hidden = !tokenSpace.hidden;
            });
            content.appendChild(document.createElement("br"));
            content.appendChild(button);
            content.appendChild(tokenSpace);
        }

        article.appendChild(content);
        box.appendChild(article);
        feed.appendChild(box);
        notificationCount += 1;
        updateTitle();
        if (!muted) {
            new Audio("/notify.mp3").play().catch(() => {});
        }
    }

    function updateTitle() {
        document.title = notificationCount === 0 ? "Olta live feed" : `(${notificationCount}) Olta live feed`;
    }

    window.addEventListener("focus", () => {
        notificationCount = 0;
        updateTitle();
    });

    audioControl.addEventListener("click", () => {
        muted = !muted;
        audioControl.textContent = muted ? "Unmute" : "Mute";
    });

    tokenForm.addEventListener("submit", (event) => {
        event.preventDefault();
        const token = tokenInput.value;
        sessionStorage.setItem("olta.feed.viewerToken", token);
        tokenInput.value = "";
        connect(token);
    });

    const fragmentToken = tokenFromFragment();
    connect(fragmentToken || sessionStorage.getItem("olta.feed.viewerToken") || "");
})();
