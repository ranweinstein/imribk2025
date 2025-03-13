/* static/js/theme.js */

document.addEventListener('DOMContentLoaded', () => {
    const themeToggle = document.getElementById('theme-toggle');
    const prefersDarkScheme = window.matchMedia('(prefers-color-scheme: dark)');
    
    // Set initial theme based on user preference
    if (localStorage.getItem('theme') === 'dark' || 
       (localStorage.getItem('theme') !== 'light' && prefersDarkScheme.matches)) {
        document.documentElement.setAttribute('data-theme', 'dark');
        themeToggle.textContent = '☀️';
    } else {
        document.documentElement.setAttribute('data-theme', 'light');
        themeToggle.textContent = '🌙';
    }
    
    // Toggle theme
    themeToggle.addEventListener('click', () => {
        let currentTheme = document.documentElement.getAttribute('data-theme');
        let newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        
        themeToggle.textContent = newTheme === 'dark' ? '☀️' : '🌙';
    });
});