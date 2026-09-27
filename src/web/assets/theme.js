// Runs before first paint (blocking, tiny): apply the saved theme so there is no flash.
(function () {
  var t = null;
  try { t = localStorage.getItem('fastvol.theme'); } catch (e) { /* storage blocked */ }
  if (t !== 'light' && t !== 'dark') {
    t = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  }
  document.documentElement.setAttribute('data-theme', t);
})();
