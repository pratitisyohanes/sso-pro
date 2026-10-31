// Show/hide button for every password field. Its own file because the pages only allow scripts from this server.
document.querySelectorAll('input[type="password"]').forEach(function (input) {
  var wrap = document.createElement('span');
  wrap.className = 'pw';
  input.parentNode.insertBefore(wrap, input);
  wrap.appendChild(input);

  var button = document.createElement('button');
  button.type = 'button';
  button.className = 'pw-toggle';
  button.textContent = 'Show';
  button.setAttribute('aria-label', 'Show password');
  button.setAttribute('aria-pressed', 'false');
  button.addEventListener('click', function () {
    var reveal = input.type === 'password';
    input.type = reveal ? 'text' : 'password';
    button.textContent = reveal ? 'Hide' : 'Show';
    button.setAttribute('aria-label', reveal ? 'Hide password' : 'Show password');
    button.setAttribute('aria-pressed', reveal ? 'true' : 'false');
    input.focus();
  });
  wrap.appendChild(button);
});
