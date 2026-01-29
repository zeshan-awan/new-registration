// ===== Firebase (Modular v9) =====
import { initializeApp } from "https://www.gstatic.com/firebasejs/9.23.0/firebase-app.js";
import { getAnalytics } from "https://www.gstatic.com/firebasejs/9.23.0/firebase-analytics.js";

import {
  getAuth,
  onAuthStateChanged,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  updateProfile,
  signOut,
  GoogleAuthProvider,
  GithubAuthProvider,
  signInWithPopup,
  signInWithRedirect,
  getRedirectResult,
  EmailAuthProvider,
  linkWithCredential,
} from "https://www.gstatic.com/firebasejs/9.23.0/firebase-auth.js";

import {
  getFirestore,
  doc,
  setDoc,
  getDoc,
  getDocs,
  collection,
  query,
  orderBy,
  serverTimestamp,
} from "https://www.gstatic.com/firebasejs/9.23.0/firebase-firestore.js";

// ===== Your Firebase Config =====
const firebaseConfig = {
  apiKey: "AIzaSyC__eMBJi7uI-V41N8rRNb1XqS3zcrQfL0",
  authDomain: "studentportal-8affc.firebaseapp.com",
  projectId: "studentportal-8affc",
  storageBucket: "studentportal-8affc.firebasestorage.app",
  messagingSenderId: "907971119852",
  appId: "1:907971119852:web:4a27da8565740e3ad1b3c9",
  measurementId: "G-QFDBVCRTV6",
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
getAnalytics(app);

const auth = getAuth(app);
const db = getFirestore(app);

// ===== Admin credentials (enforced) =====
const ADMIN_EMAIL = "admin@test.com";
const ADMIN_PASSWORD = "12345678";

// ===== CNIC pattern (Pakistan) =====
const CNIC_REGEX = /^\d{5}-\d{7}-\d{1}$/;

// ===== UI refs =====
const authView = document.getElementById("authView");
const loginView = document.getElementById("loginView");
const signupView = document.getElementById("signupView");
const studentView = document.getElementById("studentView");
const adminView = document.getElementById("adminView");

const logoutBtn = document.getElementById("logoutBtn");
const sessionBadge = document.getElementById("sessionBadge");

const authMsg = document.getElementById("authMsg");
const studentMsg = document.getElementById("studentMsg");
const adminMsg = document.getElementById("adminMsg");

// Login inputs
const loginEmail = document.getElementById("loginEmail");
const loginPassword = document.getElementById("loginPassword");
const loginBtn = document.getElementById("loginBtn");

// OAuth buttons
const googleLoginBtn = document.getElementById("googleLoginBtn");
const githubLoginBtn = document.getElementById("githubLoginBtn");
const googleSignupBtn = document.getElementById("googleSignupBtn");
const githubSignupBtn = document.getElementById("githubSignupBtn");

// View switching
const showSignupBtn = document.getElementById("showSignupBtn");
const showLoginBtn = document.getElementById("showLoginBtn");

// Signup inputs
const signupName = document.getElementById("signupName");
const signupEmail = document.getElementById("signupEmail");
const signupPassword = document.getElementById("signupPassword");
const signupBtn = document.getElementById("signupBtn");

// Student search
const cnicInput = document.getElementById("cnicInput");
const cnicSearchBtn = document.getElementById("cnicSearchBtn");
const resultCard = document.getElementById("resultCard");

// Set portal password button
const setPasswordBtn = document.getElementById("setPasswordBtn");

// Admin add student
const refreshStudentsBtn = document.getElementById("refreshStudentsBtn");
const studentsTbody = document.getElementById("studentsTbody");

const addName = document.getElementById("addName");
const addCnic = document.getElementById("addCnic");
const addClass = document.getElementById("addClass");
const addStudentBtn = document.getElementById("addStudentBtn");

// ===== Helpers =====
function showMsg(el, text, type = "info") {
  el.textContent = text;
  el.classList.remove("hidden");

  el.style.borderColor =
    type === "error"
      ? "rgba(255,90,120,.55)"
      : type === "success"
        ? "rgba(60,255,190,.40)"
        : "rgba(255,255,255,.14)";
}

function hideMsg(el) {
  el.classList.add("hidden");
  el.textContent = "";
}

function setView(view) {
  authView.classList.add("hidden");
  studentView.classList.add("hidden");
  adminView.classList.add("hidden");
  view.classList.remove("hidden");
}

function showLoginView() {
  loginView.classList.remove("hidden");
  signupView.classList.add("hidden");
}

function showSignupView() {
  loginView.classList.add("hidden");
  signupView.classList.remove("hidden");
}

function isAdminUser(user) {
  return user?.email?.toLowerCase() === ADMIN_EMAIL;
}

function normalizeCnic(value) {
  return (value || "").trim();
}

function renderStudentResult(data) {
  if (!data) {
    resultCard.innerHTML = `<div class="result-empty">No data yet. Search using CNIC.</div>`;
    return;
  }

  resultCard.innerHTML = `
    <div class="kv">
      <div class="k">Name</div><div class="v">${escapeHtml(data.name || "-")}</div>
      <div class="k">CNIC</div><div class="v">${escapeHtml(data.cnic || "-")}</div>
      <div class="k">Class</div><div class="v">${escapeHtml(data.class || "-")}</div>
    </div>
  `;
}

// Basic HTML escape
function escapeHtml(str) {
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

// Store/Update OAuth + user profile on backend (Firestore)
async function ensureStudentProfile(user, providerName = "oauth") {
  if (!user) return;
  if (user.email?.toLowerCase() === ADMIN_EMAIL) return;

  const uid = user.uid;
  const ref = doc(db, "users", uid);
  const snap = await getDoc(ref);

  const payload = {
    uid,
    role: "student",
    fullName: user.displayName || "",
    email: user.email || "",
    provider: providerName,
    lastLoginAt: serverTimestamp(),
  };

  if (!snap.exists()) {
    await setDoc(ref, { ...payload, createdAt: serverTimestamp() });
  } else {
    await setDoc(ref, payload, { merge: true });
  }
}

// ===== Redirect result handler (for popup blocked cases) =====
getRedirectResult(auth)
  .then(async (result) => {
    if (!result || !result.user) return;

    if (result.user.email?.toLowerCase() === ADMIN_EMAIL) {
      showMsg(authMsg, "Admin must login using email/password only.", "error");
      await signOut(auth);
      return;
    }

    // Determine provider from result
    const providerId = result.providerId || result._tokenResponse?.providerId || "oauth";
    const providerName = providerId.includes("google")
      ? "google"
      : providerId.includes("github")
        ? "github"
        : "oauth";

    await ensureStudentProfile(result.user, providerName);
    showMsg(authMsg, `Successfully signed in with ${providerName}!`, "success");
  })
  .catch((e) => {
    console.error('Redirect result error:', e);
    if (!authView.classList.contains("hidden")) {
      showMsg(authMsg, `Sign-in error: ${e.message}`, "error");
    }
  });

// ===== Auth flow =====
onAuthStateChanged(auth, async (user) => {
  hideMsg(authMsg);
  hideMsg(studentMsg);
  hideMsg(adminMsg);

  if (!user) {
    sessionBadge.classList.add("hidden");
    logoutBtn.classList.add("hidden");
    setView(authView);
    showLoginView();
    renderStudentResult(null);
    return;
  }

  sessionBadge.classList.remove("hidden");
  logoutBtn.classList.remove("hidden");

  if (isAdminUser(user)) {
    setView(adminView);
    await loadAllStudents();
  } else {
    setView(studentView);
    renderStudentResult(null);
  }
});

// ===== Login =====
loginBtn.addEventListener("click", async () => {
  hideMsg(authMsg);

  const email = (loginEmail.value || "").trim();
  const password = loginPassword.value || "";

  if (!email || !password) {
    showMsg(authMsg, "Please enter email and password.", "error");
    return;
  }

  // Enforce admin password if admin email used
  if (email.toLowerCase() === ADMIN_EMAIL && password !== ADMIN_PASSWORD) {
    showMsg(authMsg, "Invalid admin credentials.", "error");
    return;
  }

  try {
    await signInWithEmailAndPassword(auth, email, password);
    showMsg(authMsg, "Signed in successfully!", "success");
  } catch (e) {
    showMsg(authMsg, e.message, "error");
  }
});

// ===== Signup (Student) =====
signupBtn.addEventListener("click", async () => {
  hideMsg(authMsg);

  const fullName = (signupName.value || "").trim();
  const email = (signupEmail.value || "").trim();
  const password = signupPassword.value || "";

  if (!fullName || !email || !password) {
    showMsg(authMsg, "Please fill Full Name, Email, and Password.", "error");
    return;
  }

  if (email.toLowerCase() === ADMIN_EMAIL) {
    showMsg(authMsg, "This email is reserved for admin.", "error");
    return;
  }

  try {
    const cred = await createUserWithEmailAndPassword(auth, email, password);
    await updateProfile(cred.user, { displayName: fullName });

    // Store profile for email/password users too
    await ensureStudentProfile(cred.user, "password");

    showMsg(
      authMsg,
      "Account created! Redirecting to Student Dashboard…",
      "success",
    );
  } catch (e) {
    showMsg(authMsg, e.message, "error");
  }
});

// ===== OAuth (Popup first, fallback to Redirect) =====
async function signInWithPopupOrRedirect(provider, providerName) {
  try {
    showMsg(authMsg, `Signing in with ${providerName}...`, "info");
    
    const result = await signInWithPopup(auth, provider);

    if (result.user.email?.toLowerCase() === ADMIN_EMAIL) {
      showMsg(authMsg, "Admin must login using email/password only.", "error");
      await signOut(auth);
      return;
    }

    await ensureStudentProfile(result.user, providerName);
    showMsg(
      authMsg,
      `Signed in with ${providerName[0].toUpperCase() + providerName.slice(1)}!`,
      "success",
    );
  } catch (e) {
    console.error(`${providerName} auth error:`, e);
    
    const popupIssue =
      e?.code === "auth/popup-blocked" ||
      e?.code === "auth/popup-closed-by-user" ||
      e?.code === "auth/cancelled-popup-request";

    if (popupIssue) {
      showMsg(authMsg, "Popup blocked. Redirecting…", "info");
      try {
        await signInWithRedirect(auth, provider);
      } catch (redirectError) {
        console.error('Redirect error:', redirectError);
        showMsg(authMsg, `Redirect failed: ${redirectError.message}`, "error");
      }
      return;
    }

    if (e?.code === "auth/account-exists-with-different-credential") {
      showMsg(authMsg, "Account exists with different sign-in method. Try email/password.", "error");
    } else if (e?.code === "auth/unauthorized-domain") {
      showMsg(authMsg, "Domain not authorized. Check Firebase console settings.", "error");
    } else if (e?.code === "auth/operation-not-allowed") {
      showMsg(authMsg, `${providerName} sign-in is not enabled. Check Firebase console.`, "error");
    } else {
      showMsg(authMsg, `${providerName} sign-in failed: ${e.message}`, "error");
    }
  }
}

googleLoginBtn.addEventListener("click", async () => {
  hideMsg(authMsg);
  try {
    const provider = new GoogleAuthProvider();
    provider.addScope('email');
    provider.addScope('profile');
    await signInWithPopupOrRedirect(provider, "google");
  } catch (e) {
    console.error('Google button error:', e);
    showMsg(authMsg, `Google setup error: ${e.message}`, "error");
  }
});

githubLoginBtn.addEventListener("click", async () => {
  hideMsg(authMsg);
  try {
    const provider = new GithubAuthProvider();
    provider.addScope("user:email");
    provider.addScope("read:user");
    await signInWithPopupOrRedirect(provider, "github");
  } catch (e) {
    console.error('GitHub button error:', e);
    showMsg(authMsg, `GitHub setup error: ${e.message}`, "error");
  }
});

googleSignupBtn.addEventListener("click", async () => {
  hideMsg(authMsg);
  try {
    const provider = new GoogleAuthProvider();
    provider.addScope('email');
    provider.addScope('profile');
    await signInWithPopupOrRedirect(provider, "google");
  } catch (e) {
    console.error('Google signup error:', e);
    showMsg(authMsg, `Google setup error: ${e.message}`, "error");
  }
});

githubSignupBtn.addEventListener("click", async () => {
  hideMsg(authMsg);
  try {
    const provider = new GithubAuthProvider();
    provider.addScope("user:email");
    provider.addScope("read:user");
    await signInWithPopupOrRedirect(provider, "github");
  } catch (e) {
    console.error('GitHub signup error:', e);
    showMsg(authMsg, `GitHub setup error: ${e.message}`, "error");
  }
});

// View switching
showSignupBtn.addEventListener("click", (e) => {
  e.preventDefault();
  hideMsg(authMsg);
  showSignupView();
});

showLoginBtn.addEventListener("click", (e) => {
  e.preventDefault();
  hideMsg(authMsg);
  showLoginView();
});

// ===== Logout =====
logoutBtn.addEventListener("click", async () => {
  await signOut(auth);
});

// ===== Student: CNIC search =====
cnicSearchBtn.addEventListener("click", async () => {
  hideMsg(studentMsg);
  renderStudentResult(null);

  const cnic = normalizeCnic(cnicInput.value);

  if (!CNIC_REGEX.test(cnic)) {
    showMsg(studentMsg, "Invalid CNIC format. Use: 32203-9494999-1", "error");
    resultCard.innerHTML = `<div class="result-empty">No data found.</div>`;
    return;
  }

  try {
    const snap = await getDoc(doc(db, "students", cnic));
    if (!snap.exists()) {
      resultCard.innerHTML = `<div class="result-empty">No data found.</div>`;
      showMsg(studentMsg, "No data found.", "error");
      return;
    }

    renderStudentResult(snap.data());
    showMsg(studentMsg, "Record found!", "success");
  } catch (e) {
    showMsg(studentMsg, e.message, "error");
  }
});

// ===== Optional: Set Portal Password (for Google/GitHub users) =====
// This allows future login via Email+Password (portal password), not Google/GitHub password.
setPasswordBtn?.addEventListener("click", async () => {
  hideMsg(studentMsg);

  const user = auth.currentUser;
  if (!user || !user.email) {
    showMsg(studentMsg, "You must be logged in.", "error");
    return;
  }

  const newPass = prompt("Enter a new portal password (min 6 characters):");
  if (!newPass || newPass.length < 6) {
    showMsg(studentMsg, "Password must be at least 6 characters.", "error");
    return;
  }

  try {
    const emailCred = EmailAuthProvider.credential(user.email, newPass);
    await linkWithCredential(user, emailCred);

    // Mark in backend (do NOT store password)
    await setDoc(
      doc(db, "users", user.uid),
      { hasPortalPassword: true },
      { merge: true },
    );

    showMsg(
      studentMsg,
      "Portal password set! Next time you can login with Email + Password.",
      "success",
    );
  } catch (e) {
    if (e?.code === "auth/provider-already-linked") {
      showMsg(
        studentMsg,
        "A portal password is already set for this account.",
        "info",
      );
      return;
    }
    showMsg(studentMsg, e.message, "error");
  }
});

// ===== Admin: load all students =====
refreshStudentsBtn.addEventListener("click", loadAllStudents);

async function loadAllStudents() {
  hideMsg(adminMsg);
  studentsTbody.innerHTML = `<tr><td colspan="3" class="muted">Loading…</td></tr>`;

  const user = auth.currentUser;
  if (!isAdminUser(user)) {
    studentsTbody.innerHTML = `<tr><td colspan="3" class="muted">Not authorized.</td></tr>`;
    showMsg(adminMsg, "Not authorized.", "error");
    return;
  }

  try {
    const q = query(collection(db, "students"), orderBy("createdAt", "desc"));
    const snaps = await getDocs(q);

    if (snaps.empty) {
      studentsTbody.innerHTML = `<tr><td colspan="3" class="muted">No students yet.</td></tr>`;
      return;
    }

    studentsTbody.innerHTML = snaps.docs
      .map((d) => {
        const s = d.data();
        return `
        <tr>
          <td>${escapeHtml(s.name || "-")}</td>
          <td>${escapeHtml(s.cnic || d.id)}</td>
          <td>${escapeHtml(s.class || "-")}</td>
        </tr>
      `;
      })
      .join("");

    showMsg(adminMsg, "Loaded successfully.", "success");
  } catch (e) {
    // Fallback without orderBy
    try {
      const snaps2 = await getDocs(collection(db, "students"));
      if (snaps2.empty) {
        studentsTbody.innerHTML = `<tr><td colspan="3" class="muted">No students yet.</td></tr>`;
        return;
      }
      studentsTbody.innerHTML = snaps2.docs
        .map((d) => {
          const s = d.data();
          return `
          <tr>
            <td>${escapeHtml(s.name || "-")}</td>
            <td>${escapeHtml(s.cnic || d.id)}</td>
            <td>${escapeHtml(s.class || "-")}</td>
          </tr>
        `;
        })
        .join("");
      showMsg(adminMsg, "Loaded successfully (fallback).", "success");
    } catch (e2) {
      showMsg(adminMsg, e2.message, "error");
    }
  }
}

// ===== Admin: add new student =====
addStudentBtn.addEventListener("click", async () => {
  hideMsg(adminMsg);

  const user = auth.currentUser;
  if (!isAdminUser(user)) {
    showMsg(adminMsg, "Not authorized.", "error");
    return;
  }

  const name = (addName.value || "").trim();
  const cnic = normalizeCnic(addCnic.value);
  const cls = (addClass.value || "").trim();

  if (!name || !cnic || !cls) {
    showMsg(adminMsg, "Please fill name, CNIC and class.", "error");
    return;
  }

  if (!CNIC_REGEX.test(cnic)) {
    showMsg(adminMsg, "CNIC must match pattern: 32203-9494999-1", "error");
    return;
  }

  try {
    await setDoc(
      doc(db, "students", cnic),
      {
        name,
        cnic,
        class: cls,
        createdAt: serverTimestamp(),
      },
      { merge: true },
    );

    showMsg(adminMsg, "Student added successfully!", "success");
    addName.value = "";
    addCnic.value = "";
    addClass.value = "";
    await loadAllStudents();
  } catch (e) {
    showMsg(adminMsg, e.message, "error");
  }
});

// ===== Auto-format CNIC while typing =====
function formatCnicInput(el) {
  el.addEventListener("input", () => {
    const digits = el.value.replace(/\D/g, "").slice(0, 13);
    let out = digits;

    if (digits.length > 12) {
      out =
        digits.slice(0, 5) + "-" + digits.slice(5, 12) + "-" + digits.slice(12);
    } else if (digits.length > 5) {
      out = digits.slice(0, 5) + "-" + digits.slice(5);
    }

    el.value = out;
  });
}
formatCnicInput(cnicInput);
formatCnicInput(addCnic);
