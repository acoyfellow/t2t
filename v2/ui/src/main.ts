import { mount } from 'svelte';
import './app.css';
import Overlay from './Overlay.svelte';

mount(Overlay, { target: document.getElementById('app')! });
