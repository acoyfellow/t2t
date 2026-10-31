import { mount } from 'svelte';
import './app.css';
import Settings from './Settings.svelte';

document.documentElement.classList.add('settings');
mount(Settings, { target: document.getElementById('app')! });
