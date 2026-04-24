async function createShare(fileId) {
  const password = document.getElementById(`share-password-${fileId}`).value;
  const expiryHours = document.getElementById(`share-expiry-${fileId}`).value;
  const result = document.getElementById(`share-result-${fileId}`);

  if (!password || password.length < 8) {
    result.textContent = 'Share password must be at least 8 characters.';
    return;
  }

  const formData = new FormData();
  formData.append('password', password);
  formData.append('expires_hours', expiryHours || '24');

  const response = await fetch(`/files/${fileId}/share`, {
    method: 'POST',
    body: formData,
  });

  const payload = await response.json();
  if (!response.ok) {
    result.textContent = payload.detail || 'Unable to create share link.';
    return;
  }

  result.innerHTML = `Share link: <a href="${payload.share_url}" target="_blank" rel="noreferrer">${window.location.origin}${payload.share_url}</a>`;
}
