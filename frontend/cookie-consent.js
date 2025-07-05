// Inject HTML dynamically
document.body.insertAdjacentHTML('beforeend', `
  <div id="cookie-banner" class="fixed bottom-0 left-0 right-0 bg-white border-t border-gray-300 p-4 shadow z-50 hidden">
    <div class="max-w-4xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
      <p class="text-sm text-gray-700">
        We use cookies to enhance your experience, analyse usage, and deliver relevant ads. You can manage your preferences below.
      </p>
      <div class="flex gap-2">
        <button onclick="acceptAllCookies()" class="bg-blue-600 text-white text-sm px-3 py-1.5 rounded hover:bg-blue-700">Accept All</button>
        <button onclick="rejectAllCookies()" class="bg-gray-200 text-gray-800 text-sm px-3 py-1.5 rounded hover:bg-gray-300">Reject</button>
        <button onclick="openCookieSettings()" class="border border-gray-400 text-gray-700 text-sm px-3 py-1.5 rounded hover:bg-gray-100">Settings</button>
      </div>
    </div>
  </div>

  <div id="cookie-settings-modal" class="fixed inset-0 bg-black bg-opacity-50 z-50 hidden">
    <div class="bg-white max-w-md mx-auto mt-20 p-6 rounded shadow">
      <h3 class="text-lg font-semibold mb-2">Cookie Preferences</h3>
      <p class="text-sm text-gray-600 mb-4">Select which cookies you allow:</p>
      <div class="space-y-2">
        <label class="flex items-center">
          <input type="checkbox" checked disabled class="mr-2"> Essential Cookies (always active)
        </label>
        <label class="flex items-center">
          <input type="checkbox" id="analytics-cookies" class="mr-2"> Analytics Cookies
        </label>
        <label class="flex items-center">
          <input type="checkbox" id="advertising-cookies" class="mr-2"> Advertising Cookies
        </label>
      </div>
      <div class="mt-4 flex justify-end gap-2">
        <button onclick="saveCookieSettings()" class="bg-blue-600 text-white text-sm px-3 py-1.5 rounded hover:bg-blue-700">Save</button>
        <button onclick="closeCookieSettings()" class="bg-gray-200 text-gray-800 text-sm px-3 py-1.5 rounded hover:bg-gray-300">Cancel</button>
      </div>
    </div>
  </div>
`);

// Show banner if consent not yet set
if (!localStorage.getItem('cookieConsent')) {
  document.getElementById('cookie-banner').classList.remove('hidden');
}

// Functions
function acceptAllCookies() {
  localStorage.setItem('cookieConsent', JSON.stringify({
    analytics: true,
    advertising: true
  }));
  document.getElementById('cookie-banner').classList.add('hidden');
  location.reload();
}

function rejectAllCookies() {
  localStorage.setItem('cookieConsent', JSON.stringify({
    analytics: false,
    advertising: false
  }));
  document.getElementById('cookie-banner').classList.add('hidden');
  location.reload();
}

function openCookieSettings() {
  document.getElementById('cookie-settings-modal').classList.remove('hidden');
}

function closeCookieSettings() {
  document.getElementById('cookie-settings-modal').classList.add('hidden');
}

function saveCookieSettings() {
  const analytics = document.getElementById('analytics-cookies').checked;
  const advertising = document.getElementById('advertising-cookies').checked;
  localStorage.setItem('cookieConsent', JSON.stringify({
    analytics: analytics,
    advertising: advertising
  }));
  document.getElementById('cookie-settings-modal').classList.add('hidden');
  document.getElementById('cookie-banner').classList.add('hidden');
  location.reload();
}
