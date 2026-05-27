/* ============================================================
   HRApp - UX feedback layer + tracking
   ============================================================ */
(function () {
    "use strict";

    const HRApp = {};

    // -------- Toast helpers (immediate feedback) --------
    HRApp.toast = function (message, kind = "info", ttl = 3500) {
        const host = document.getElementById("toast-host");
        if (!host) return;
        const el = document.createElement("div");
        el.className = `toast toast-${kind}`;
        el.innerHTML = `
            <span class="toast-icon">${kind === "error" ? "!" : kind === "success" ? "✓" : "i"}</span>
            <span>${message}</span>
            <button class="toast-close" aria-label="Fermer">×</button>
        `;
        host.appendChild(el);
        const close = () => el.parentElement && el.remove();
        el.querySelector(".toast-close").addEventListener("click", close);
        if (ttl > 0) setTimeout(close, ttl);
    };

    // Auto-dismiss server-flashed toasts
    document.querySelectorAll("[data-auto-dismiss]").forEach((el) => {
        const btn = el.querySelector(".toast-close");
        if (btn) btn.addEventListener("click", () => el.remove());
        setTimeout(() => el.remove(), 5000);
    });

    // -------- Tracking helper --------
    HRApp.track = function (eventType, extra = {}) {
        const body = Object.assign({ event_type: eventType }, extra);
        try {
            fetch("/api/track", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(body),
                keepalive: true,
            });
        } catch (_) { /* silent */ }
    };

    // -------- Page session timer (abandon detection) --------
    const pageStart = Date.now();
    window.addEventListener("beforeunload", () => {
        HRApp.track("page_leave", {
            duration_ms: Date.now() - pageStart,
            payload: { path: window.location.pathname },
        });
    });

    // -------- SEARCH (debounced live results) --------
    HRApp.initSearch = function () {
        const input = document.getElementById("search-input");
        const list = document.getElementById("search-results");
        const spinner = document.getElementById("search-spinner");
        const hint = document.getElementById("search-hint");
        if (!input || !list) return;

        let timer = null;
        let lastQuery = "";
        let firstKey = true;

        function setSpinner(on) { if (spinner) spinner.hidden = !on; }

        function render(results, q) {
            list.innerHTML = "";
            if (!q) { hint.textContent = "Commencez à taper — la recherche se lance toute seule."; return; }
            if (!results.length) {
                hint.textContent = "";
                const li = document.createElement("li");
                li.className = "empty-state";
                li.textContent = `Aucun collaborateur trouvé pour « ${q} ».`;
                list.appendChild(li);
                return;
            }
            hint.textContent = `${results.length} résultat${results.length > 1 ? "s" : ""} pour « ${q} »`;
            for (const r of results) {
                const li = document.createElement("li");
                const a = document.createElement("a");
                a.className = "result-item";
                a.href = `/employee/${encodeURIComponent(r.matricule)}`;
                a.innerHTML = `
                    <span class="result-avatar">${(r.prenom[0] || "").toUpperCase()}${(r.nom[0] || "").toUpperCase()}</span>
                    <span class="result-body">
                        <span class="result-name">${r.prenom} ${r.nom}</span>
                        <span class="result-meta">${r.matricule} · ${r.poste || ""} · ${r.service || ""}</span>
                    </span>
                    <span class="result-chevron" aria-hidden="true">›</span>
                `;
                li.appendChild(a);
                list.appendChild(li);
            }
        }

        async function runSearch(q) {
            if (q === lastQuery) return;
            lastQuery = q;
            if (!q) { render([], ""); return; }
            setSpinner(true);
            try {
                const r = await fetch(`/api/search?q=${encodeURIComponent(q)}`);
                const data = await r.json();
                render(data.results || [], q);
            } catch (e) {
                HRApp.toast("Impossible de joindre le serveur", "error");
            } finally {
                setSpinner(false);
            }
        }

        input.addEventListener("input", () => {
            if (firstKey) {
                HRApp.track("search_started");
                firstKey = false;
            }
            const q = input.value.trim();
            clearTimeout(timer);
            if (q.length === 0) { render([], ""); return; }
            timer = setTimeout(() => runSearch(q), 220);  // debounce
        });

        input.addEventListener("keydown", (e) => {
            if (e.key === "Enter") {
                e.preventDefault();
                const first = list.querySelector(".result-item");
                if (first) first.click();
            }
        });
    };

    // -------- Track hover on request cards (interest signal) --------
    HRApp.trackCardHovers = function (matricule) {
        document.querySelectorAll(".request-card").forEach((card) => {
            let enter = 0;
            card.addEventListener("mouseenter", () => { enter = Date.now(); });
            card.addEventListener("mouseleave", () => {
                if (!enter) return;
                const ms = Date.now() - enter;
                if (ms > 500) {
                    HRApp.track("card_hover", {
                        employee_matricule: matricule,
                        template_key: card.dataset.templateKey,
                        duration_ms: ms,
                    });
                }
                enter = 0;
            });
        });
    };

    // -------- FORM: live validation + submit feedback --------
    HRApp.initForm = function () {
        const form = document.querySelector(".rh-form");
        if (!form) return;
        const submitBtn = form.querySelector("#submit-btn");
        const templateKey = form.dataset.templateKey;
        const matricule = form.dataset.matricule;

        HRApp.track("form_opened", {
            employee_matricule: matricule,
            template_key: templateKey,
        });

        const fields = form.querySelectorAll(".field input, .field select, .field textarea");

        function validateField(el) {
            const wrap = el.closest(".field");
            const feedback = wrap.querySelector(".field-feedback");
            const required = wrap.classList.contains("required");
            const v = el.value.trim();

            wrap.classList.remove("valid", "invalid");
            feedback.textContent = "";

            if (required && !v) {
                wrap.classList.add("invalid");
                feedback.textContent = "Champ requis.";
                return false;
            }
            if (el.type === "number" && v && isNaN(Number(v))) {
                wrap.classList.add("invalid");
                feedback.textContent = "Doit être un nombre.";
                return false;
            }
            if (v) {
                wrap.classList.add("valid");
                feedback.textContent = "OK";
            }
            return true;
        }

        fields.forEach((el) => {
            el.addEventListener("blur", () => validateField(el));
            el.addEventListener("input", () => {
                const wrap = el.closest(".field");
                if (wrap.classList.contains("invalid")) validateField(el);
            });
        });

        form.addEventListener("submit", (e) => {
            let ok = true;
            fields.forEach((el) => { if (!validateField(el)) ok = false; });
            if (!ok) {
                e.preventDefault();
                HRApp.toast("Merci de compléter les champs requis.", "error");
                const firstInvalid = form.querySelector(".field.invalid input, .field.invalid select, .field.invalid textarea");
                if (firstInvalid) firstInvalid.focus();
                HRApp.track("form_validation_failed", {
                    template_key: templateKey,
                    employee_matricule: matricule,
                });
                return;
            }
            submitBtn.classList.add("loading");
            submitBtn.setAttribute("disabled", "true");
            HRApp.toast("Génération du document…", "info", 2200);
            HRApp.track("form_submitted", {
                template_key: templateKey,
                employee_matricule: matricule,
            });
        });
    };

    window.HRApp = HRApp;
})();
