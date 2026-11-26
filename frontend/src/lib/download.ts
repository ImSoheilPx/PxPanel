// Text-blob download helper shared by the VPN pages: the per-protocol config
// getters answer JSON (the configs travel as fields), and .ovpn profiles come
// back as plain text, so everything here can be client-side assembled.
export function downloadText(filename: string, text: string, mime = 'text/plain'): void {
  const blob = new Blob([text], { type: `${mime};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
