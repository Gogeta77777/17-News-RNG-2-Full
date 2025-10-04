// Game functionality
document.addEventListener('DOMContentLoaded', function() {
    // Tab switching
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabPanes = document.querySelectorAll('.tab-pane');
    
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            // Remove active class from all buttons and panes
            tabBtns.forEach(b => b.classList.remove('active'));
            tabPanes.forEach(p => p.classList.remove('active'));
            
            // Add active class to clicked button and corresponding pane
            btn.classList.add('active');
            const tabId = btn.getAttribute('data-tab') + '-tab';
            document.getElementById(tabId).classList.add('active');
        });
    });
    
    // Spin functionality
    const spinBtn = document.getElementById('spin-btn');
    const spinResult = document.getElementById('spin-result');
    
    if (spinBtn) {
        spinBtn.addEventListener('click', async () => {
            spinBtn.disabled = true;
            spinBtn.textContent = 'Spinning...';
            
            try {
                const response = await fetch('/spin', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });
                
                const result = await response.json();
                
                if (result.success) {
                    // Update coin count
                    document.getElementById('coin-count').textContent = result.coins;
                    
                    // Display result with rarity color
                    spinResult.innerHTML = `
                        <div class="spin-success" style="color: ${result.rarity.color}; margin-top: 10px;">
                            <strong>Congratulations!</strong><br>
                            You got: ${result.item}<br>
                            Rarity: ${result.rarity.name}
                        </div>
                    `;
                    
                    // Refresh inventory (in a real app, you might update it dynamically)
                    setTimeout(() => {
                        location.reload();
                    }, 2000);
                } else {
                    spinResult.innerHTML = `<div class="error-message">${result.message}</div>`;
                }
            } catch (error) {
                spinResult.innerHTML = `<div class="error-message">An error occurred. Please try again.</div>`;
            } finally {
                spinBtn.disabled = false;
                spinBtn.textContent = 'Spin Now!';
            }
        });
    }
    
    // Code redemption
    const redeemBtn = document.getElementById('redeem-btn');
    const codeInput = document.getElementById('code-input');
    const codeResult = document.getElementById('code-result');
    
    if (redeemBtn) {
        redeemBtn.addEventListener('click', async () => {
            const code = codeInput.value.trim();
            
            if (!code) {
                codeResult.innerHTML = `<div class="error-message">Please enter a code</div>`;
                return;
            }
            
            redeemBtn.disabled = true;
            redeemBtn.textContent = 'Redeeming...';
            
            try {
                const response = await fetch('/use-code', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ code })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    codeResult.innerHTML = `<div style="color: #27ae60; margin-top: 10px;">${result.message}</div>`;
                    codeInput.value = '';
                    
                    // Update coin count if needed
                    document.getElementById('coin-count').textContent = result.coins || 
                        document.getElementById('coin-count').textContent;
                    
                    // Refresh inventory if item was added
                    if (result.message.includes('item')) {
                        setTimeout(() => {
                            location.reload();
                        }, 1500);
                    }
                } else {
                    codeResult.innerHTML = `<div class="error-message">${result.message}</div>`;
                }
            } catch (error) {
                codeResult.innerHTML = `<div class="error-message">An error occurred. Please try again.</div>`;
            } finally {
                redeemBtn.disabled = false;
                redeemBtn.textContent = 'Redeem';
            }
        });
    }
    
    // Allow pressing Enter in code input
    if (codeInput) {
        codeInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                redeemBtn.click();
            }
        });
    }
});
