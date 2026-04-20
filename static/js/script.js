// Form validation
document.addEventListener('DOMContentLoaded', function() {
    // Auto-hide alerts after 5 seconds
    setTimeout(function() {
        const alerts = document.querySelectorAll('.alert');
        alerts.forEach(alert => {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);
    
    // Form validation
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function(event) {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        }, false);
    });
});

// Copy to clipboard function
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        alert('Copied to clipboard!');
    });
}

// Real-time attack simulation
function simulateAttack() {
    const attackTypes = ['DDoS', 'Malware', 'Phishing', 'Brute Force', 'SQL Injection'];
    const randomAttack = attackTypes[Math.floor(Math.random() * attackTypes.length)];
    alert(`Simulating ${randomAttack} attack detection...`);
    return randomAttack;
}