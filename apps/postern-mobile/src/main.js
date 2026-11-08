// Postern Mobile — app entry. Mounts the Svelte shell. No inline code ships:
// this module is bundled to a hashed, same-origin assets/*.js file.
import App from './App.svelte';
import './app.css';

const app = new App({
  target: document.getElementById('app'),
});

export default app;
