'use strict';

const themeButtons = document.querySelectorAll('[data-theme-toggle]');
const savedTheme = localStorage.getItem('sentinel-theme');
const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
const root = document.documentElement;

function setTheme(theme) {
    root.dataset.theme = theme;
    themeButtons.forEach((button) => {
        const nextTheme = theme === 'dark' ? 'light' : 'dark';
        button.textContent = `Use ${nextTheme} mode`;
        button.setAttribute('aria-label', `Switch to ${nextTheme} theme`);
        button.setAttribute('aria-pressed', String(theme === 'dark'));
    });
}

setTheme(savedTheme === 'light' || savedTheme === 'dark' ? savedTheme : (prefersDark ? 'dark' : 'light'));
themeButtons.forEach((button) => {
    button.addEventListener('click', () => {
        const nextTheme = root.dataset.theme === 'dark' ? 'light' : 'dark';
        localStorage.setItem('sentinel-theme', nextTheme);
        setTheme(nextTheme);
    });
});
