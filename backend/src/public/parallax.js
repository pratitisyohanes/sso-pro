// Moves the background photo layers a few pixels against the mouse; a layer's data-depth sets how far (nearer layers move more).
// Its own file because the pages only allow scripts from this server.
(function () {
  var layers = Array.prototype.slice.call(document.querySelectorAll('[data-depth]'));
  if (!layers.length) return;
  var still = window.matchMedia('(prefers-reduced-motion: reduce)');
  var fine = window.matchMedia('(hover: hover) and (pointer: fine)');
  if (still.matches || !fine.matches) return;

  var MAX = 24; // pixels the nearest layer may shift; every layer is larger than its box so no edge shows
  var frame = 0;
  var x = 0;
  var y = 0;
  document.addEventListener('mousemove', function (event) {
    x = (event.clientX / window.innerWidth - 0.5) * -2 * MAX;
    y = (event.clientY / window.innerHeight - 0.5) * -2 * MAX;
    if (frame) return;
    frame = requestAnimationFrame(function () {
      frame = 0;
      layers.forEach(function (layer) {
        var depth = parseFloat(layer.getAttribute('data-depth'));
        layer.style.transform = 'translate3d(' + (x * depth).toFixed(1) + 'px,' + (y * depth).toFixed(1) + 'px,0)';
      });
    });
  });
})();
