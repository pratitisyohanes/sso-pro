// Copy button for a read-only field: <button data-copy="fieldId">. Its own file because the pages only allow scripts from this server.
document.querySelectorAll('button[data-copy]').forEach(function (button) {
  var label = button.textContent;

  button.addEventListener('click', function () {
    var field = document.getElementById(button.getAttribute('data-copy'));
    if (!field) return;

    var done = function () {
      button.textContent = 'Copied';
      setTimeout(function () { button.textContent = label; }, 1500);
    };
    // Selecting the text is the fallback: the person can press Ctrl+C
    var select = function () {
      field.focus();
      field.select();
      button.textContent = 'Press Ctrl+C';
    };

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(field.value).then(done, select);
    } else {
      select();
    }
  });
});
