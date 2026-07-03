export function normalizeCustomSiteInput(input) {
    const raw = typeof input === "string" ? input.trim().toLowerCase() : "";
    if (!raw) return { ok: false, error: "empty" };
    if (raw.includes("*")) return { ok: false, error: "wildcard_not_allowed" };
    if (raw.includes("@")) return { ok: false, error: "userinfo_not_allowed" };

    const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw);
    if (!hasScheme && /[/?#]/.test(raw)) {
        return { ok: false, error: "domain_only" };
    }

    let url;
    try {
        url = new URL(hasScheme ? raw : `https://${raw}`);
    } catch {
        return { ok: false, error: "invalid_host" };
    }

    if (url.protocol !== "https:") return { ok: false, error: "https_only" };
    if (url.username || url.password) {
        return { ok: false, error: "userinfo_not_allowed" };
    }
    if (url.pathname !== "/" || url.search || url.hash) {
        return { ok: false, error: "domain_only" };
    }

    const host = url.hostname.replace(/\.$/, "");
    const labels = host.split(".");
    const validDomain =
        labels.length >= 2 &&
        labels.every(
            (label) =>
                /^[a-z0-9-]{1,63}$/.test(label) &&
                !label.startsWith("-") &&
                !label.endsWith("-"),
        ) &&
        /^[a-z]{2,63}$/.test(labels[labels.length - 1]);
    if (!validDomain) return { ok: false, error: "invalid_host" };

    return { ok: true, host, pattern: `https://${host}/*` };
}
