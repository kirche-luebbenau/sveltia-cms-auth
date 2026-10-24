/**
 * Anmelde-Worker der Gemeinde - Anmeldung über GitHub, ohne Pop-up-Fenster.
 *
 * Ablauf:
 *   1. Die Seite schickt den Browser an  <worker>/auth?rueck=<Adresse der Seite>
 *   2. Der Worker leitet zu GitHub weiter (mit einem Zufallswert zum Schutz vor Fälschungen).
 *   3. GitHub schickt den Browser mit einem einmaligen Code zurück an  <worker>/callback
 *   4. Der Worker tauscht den Code gegen den Schlüssel und leitet zur Seite zurück:
 *        https://seite/?redaktion#token=...
 *      Hinter dem # - das sendet kein Browser je an einen Server. Die Seite liest den Schlüssel
 *      und entfernt ihn sofort aus der Adresszeile.
 *
 * Er ersetzt "sveltia-cms-auth" und nutzt dieselben Einstellungen (Variablen), die dort schon
 * eingetragen sind. Die GitHub-App und ihre Rückkehradresse (<worker>/callback) bleiben wie sie sind.
 *
 * Einstellungen im Cloudflare-Kundenmenü (Settings -> Variables and Secrets):
 *   GITHUB_CLIENT_ID      Text    Client ID der GitHub-App
 *   GITHUB_CLIENT_SECRET  Secret  Client secret der GitHub-App
 *   ALLOWED_DOMAINS       Text    Seiten, die sich anmelden dürfen, genau und mit Komma getrennt:
 *                                 kirche-luebbenau.pages.dev,www.kirche-luebbenau.de
 *   GITHUB_SCOPE          Text    freiwillig; Standard "repo". Bei einer GitHub-App ohne Wirkung.
 *
 * Wichtig: Zurückgeleitet wird NUR zu Adressen aus ALLOWED_DOMAINS. Sonst könnte jeder fremde
 * Link Schlüssel an eine beliebige Seite schicken.
 */

const GITHUB = 'https://github.com';
const COOKIE = 'rueck-csrf';

const antwort = (text, status = 400) => new Response(text, {
    status,
    headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' },
});

const erlaubteSeiten = (env) => (env.ALLOWED_DOMAINS || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);

const base64url = (text) => btoa(String.fromCharCode(...new TextEncoder().encode(text))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const ausBase64url = (b) => {
    const bin = atob(b.replace(/-/g, '+').replace(/_/g, '/'));
    return new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
};

/** Prüft die Adresse, zu der zurückgeleitet werden soll. Gibt sie bereinigt zurück oder null. */
function pruefeRueck(roh, env) {
    let u;
    try { u = new URL(roh); } catch (e) { return null; }
    if (u.protocol !== 'https:' || u.username || u.password) return null;
    if (!erlaubteSeiten(env).includes(u.hostname.toLowerCase())) return null;
    return u.origin + u.pathname + u.search;      // ohne # - der Schlüssel kommt dort hinten dran
}

const gleich = (a, b) => {
    if (a.length !== b.length) return false;
    let r = 0;
    for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return r === 0;
};

const cookieAus = (request, name) => {
    const m = new RegExp('(?:^|;\\s*)' + name + '=([^;]*)').exec(request.headers.get('Cookie') || '');
    return m ? m[1] : '';
};

const loescheCookie = `${COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;

function zurueck(rueck, teil) {
    return new Response(null, {
        status: 302,
        headers: {
            Location: rueck + '#' + teil,
            'Set-Cookie': loescheCookie,
            'Cache-Control': 'no-store',
            'Referrer-Policy': 'no-referrer',
        },
    });
}

function auth(url, env) {
    const rueck = pruefeRueck(url.searchParams.get('rueck') || '', env);
    if (!rueck) return antwort('Diese Seite darf sich nicht anmelden.', 403);
    if (!env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET) return antwort('Der Anmelde-Worker ist nicht fertig eingerichtet.', 500);

    const zufall = crypto.randomUUID().replaceAll('-', '');
    const state = zufall + '.' + base64url(rueck);
    const ziel = new URL(GITHUB + '/login/oauth/authorize');
    ziel.searchParams.set('client_id', env.GITHUB_CLIENT_ID);
    ziel.searchParams.set('scope', env.GITHUB_SCOPE || 'repo');
    ziel.searchParams.set('state', state);

    return new Response(null, {
        status: 302,
        headers: {
            Location: ziel.toString(),
            'Set-Cookie': `${COOKIE}=${zufall}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`,
            'Cache-Control': 'no-store',
        },
    });
}

async function callback(url, request, env) {
    const state = url.searchParams.get('state') || '';
    const [zufall, rueckKodiert] = state.split('.');
    const cookie = cookieAus(request, COOKIE);

    // Ohne passenden Zufallswert im Cookie stammt der Aufruf nicht von diesem Browser: abbrechen.
    if (!zufall || !rueckKodiert || !cookie || !gleich(zufall, cookie)) return antwort('Die Anmeldung ist abgelaufen oder ungültig. Bitte noch einmal von der Seite aus anmelden.', 400);

    let rueck = null;
    try { rueck = pruefeRueck(ausBase64url(rueckKodiert), env); } catch (e) { /* bleibt null */ }
    if (!rueck) return antwort('Diese Seite darf sich nicht anmelden.', 403);

    if (url.searchParams.get('error')) return zurueck(rueck, 'fehler=abgelehnt');
    const code = url.searchParams.get('code');
    if (!code) return zurueck(rueck, 'fehler=ohne-code');

    try {
        const r = await fetch(GITHUB + '/login/oauth/access_token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
            body: JSON.stringify({ client_id: env.GITHUB_CLIENT_ID, client_secret: env.GITHUB_CLIENT_SECRET, code }),
        });
        const daten = await r.json();
        if (!daten.access_token) return zurueck(rueck, 'fehler=austausch');
        return zurueck(rueck, 'token=' + encodeURIComponent(daten.access_token));
    } catch (e) {
        return zurueck(rueck, 'fehler=austausch');
    }
}

export default {
    async fetch(request, env) {
        const url = new URL(request.url);
        if (request.method !== 'GET') return antwort('Nur GET.', 405);

        if (url.pathname === '/auth') return auth(url, env);
        if (url.pathname === '/callback') return callback(url, request, env);

        // Die Seite fragt hier, welche Art von Anmeldung dieser Worker kann.
        if (url.pathname === '/art') {
            return new Response(JSON.stringify({ art: 'weiterleitung', version: 1 }), {
                headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-store' },
            });
        }
        return antwort('Anmelde-Worker der Evangelischen Gesamtkirchengemeinde Lübbenau und Umland.', 200);
    },
};
