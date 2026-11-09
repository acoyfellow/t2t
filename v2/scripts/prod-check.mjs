const state = await (await fetch('http://localhost:5198/state')).json();
console.log(JSON.stringify({ keys: state.keys, overlayVisible: state.overlayVisible, accessibility: state.accessibility, inputMonitoring: state.inputMonitoring, gateway: state.gateway }));
const ui = await fetch('http://localhost:5197/');
console.log('ui', ui.status);
const site = await fetch('https://t2t.now');
console.log('site', site.status);
const release = await fetch('https://github.com/acoyfellow/t2t/releases/download/v2.0.0/t2t-v2.zip', { method: 'HEAD', redirect: 'manual' });
console.log('release', release.status);
