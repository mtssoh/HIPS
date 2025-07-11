let authToken = null;

document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('login-form');
    const loginContainer = document.getElementById('login-container');
    const dashboardContainer = document.getElementById('dashboard-container');
    const userDisplay = document.getElementById('user-display');

    loginForm.addEventListener('submit', async (evt) => {
        evt.preventDefault();

        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;

        try {
            const response = await fetch('http://localhost:8000/login_json', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username, password})
            });

            if (!response.ok) throw new Error('Login failed');

            const data = await response.json();
            authToken = data.access_token;
            userDisplay.textContent = `User: ${username}`;

            loginContainer.classList.add('hidden');
            dashboardContainer.classList.remove('hidden');
            
            // Iniciar escaneo automático después del login
            startAutoScan();
        } catch (error) {
            alert('Login failed: ' + error.message);
        }
    });

    async function fetchWithAuth(url) {
        if (!authToken) {
            throw new Error('Not authenticated');
        }

        const response = await fetch(`http://localhost:8000${url}`, {
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            }
        });

        if (!response.ok) {
            if (response.status === 401) {
                logout();
                throw new Error('Session expired');
            }
            throw new Error(`HTTP ${response.status}`);
        }

        return response.json();
    }

    async function fetchAndDisplay(url, spinnerId) {
        const spinner = document.getElementById(spinnerId);
        if (spinner) spinner.classList.remove('hidden');

        try {
            const data = await fetchWithAuth(url);
            displayResults(data);
            updateStatus(data);
        } catch (error) {
            alert('Error: ' + error.message);
        } finally {
            if (spinner) spinner.classList.add('hidden');
        }
    }

    function updateStatus(data) {
        // Update status badges based on response
        if (data.status === 'ALERT') {
            updateStatusBadge('danger');
        } else if (data.status === 'ERROR') {
            updateStatusBadge('warning');
        } else {
            updateStatusBadge('success');
        }
    }

    function updateStatusBadge(type) {
        const badges = document.querySelectorAll('.badge');
        badges.forEach(badge => {
            badge.className = `badge bg-${type}`;
            badge.textContent = type === 'success' ? 'OK' : type.toUpperCase();
        });
    }

    // Global functions for buttons
    window.scanSystemFiles = () => fetchAndDisplay('/scan/system_files', 'scan-spinner');
    window.checkConnectedUsers = () => fetchAndDisplay('/system/connected_users', 'users-spinner');
    window.detectSniffers = () => fetchAndDisplay('/system/detect_sniffers', 'sniffers-spinner');
    window.checkMemoryUsage = () => fetchAndDisplay('/system/processes_check?threshold_percent=6.0', 'memory-spinner');
    window.checkTmpDirectory = () => fetchAndDisplay('/system/tmp_check', 'tmp-spinner');
    window.checkCronJobs = () => fetchAndDisplay('/system/check_cron_jobs', 'cron-spinner');

    window.analyzeLogs = (logType) => {
        fetchAndDisplay(`/system/analyze_logs?log_type=${logType}`, null);
    };

    window.analyzeDDoSLog = () => {
        const logPathInput = document.getElementById('ddos-log-path');
        const logPath = logPathInput.value.trim();
        if (!logPath) {
            alert('Please enter a log file path');
            return;
        }
        
        // Use POST method for DDoS analysis
        analyzeDD0SWithPost(logPath);
    };

    async function analyzeDD0SWithPost(logPath) {
        const spinner = document.getElementById('ddos-spinner');
        if (spinner) spinner.classList.remove('hidden');

        try {
            if (!authToken) {
                throw new Error('Not authenticated');
            }

            const response = await fetch('http://localhost:8000/system/analyze_ddos_log', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ log_file_path: logPath })
            });

            if (!response.ok) {
                if (response.status === 401) {
                    logout();
                    throw new Error('Session expired');
                }
                throw new Error(`HTTP ${response.status}`);
            }

            const data = await response.json();
            displayResults(data);
            updateStatus(data);
        } catch (error) {
            alert('Error: ' + error.message);
        } finally {
            if (spinner) spinner.classList.add('hidden');
        }
    }

    function displayResults(data) {
        const resultsContainer = document.getElementById('results-container');
        resultsContainer.innerHTML = ''; // Clear previous results

        const resultCard = document.createElement('div');
        resultCard.className = 'col-12';
        resultCard.innerHTML = `
            <div class="card dashboard-card">
                <div class="card-body">
                    <h5 class="card-title">
                        <i class="fas fa-clipboard-list"></i> 
                        Scan Results
                        <span class="badge bg-${data.status === 'ALERT' ? 'danger' : data.status === 'ERROR' ? 'warning' : 'success'} ms-2">
                            ${data.status || 'OK'}
                        </span>
                    </h5>
                   <div class="json-display"><pre>${JSON.stringify(data, null, 2)}</pre></div>
                </div>
            </div>
        `;

        resultsContainer.appendChild(resultCard);
    }

    window.logout = () => {
        authToken = null;
        userDisplay.textContent = '';
        loginContainer.classList.remove('hidden');
        dashboardContainer.classList.add('hidden');
        document.getElementById('results-container').innerHTML = '';
        // Limpiar intervalos automáticos
        if (window.autoScanInterval) {
            clearInterval(window.autoScanInterval);
        }
    };

    // Función para ejecutar todos los escaneos automáticamente
    function runAllScans() {
        console.log('Ejecutando escaneos automáticos...');
        
        // Ejecutar todos los escaneos secuencialmente con un pequeño delay
        setTimeout(() => scanSystemFiles(), 0);
        setTimeout(() => checkConnectedUsers(), 2000);
        setTimeout(() => detectSniffers(), 4000);
        setTimeout(() => checkMemoryUsage(), 6000);
        setTimeout(() => checkTmpDirectory(), 8000);
        setTimeout(() => checkCronJobs(), 10000);
        
        // Análisis de logs con delays adicionales
        setTimeout(() => analyzeLogs('auth'), 12000);
        setTimeout(() => analyzeLogs('web'), 14000);
        setTimeout(() => analyzeLogs('mail'), 16000);
        
        updateLastScanTime();
    }

    // Función para iniciar el escaneo automático
    function startAutoScan() {
        // Ejecutar inmediatamente al iniciar
        runAllScans();
        
        // Programar ejecución cada 5 minutos (300000 ms)
        window.autoScanInterval = setInterval(() => {
            runAllScans();
        }, 300000); // 5 minutos
        
        console.log('Escaneo automático iniciado - cada 5 minutos');
    }

    // Función para actualizar la hora del último escaneo
    function updateLastScanTime() {
        const now = new Date();
        const timeString = now.toLocaleTimeString();
        const dateString = now.toLocaleDateString();
        
        let lastScanElement = document.getElementById('last-scan-time');
        if (lastScanElement) {
            lastScanElement.textContent = `Último escaneo: ${dateString} ${timeString}`;
        }
        
        // Reiniciar countdown
        startCountdown();
    }

    // Variables para el control del escaneo automático
    let autoScanActive = true;
    let countdownInterval;
    let nextScanTime = 5 * 60; // 5 minutos en segundos

    // Función para iniciar el countdown
    function startCountdown() {
        nextScanTime = 5 * 60; // Resetear a 5 minutos
        
        if (countdownInterval) {
            clearInterval(countdownInterval);
        }
        
        countdownInterval = setInterval(() => {
            if (nextScanTime <= 0) {
                clearInterval(countdownInterval);
                return;
            }
            
            const minutes = Math.floor(nextScanTime / 60);
            const seconds = nextScanTime % 60;
            const countdownElement = document.getElementById('next-scan-countdown');
            
            if (countdownElement) {
                countdownElement.textContent = `${minutes}:${seconds.toString().padStart(2, '0')}`;
            }
            
            nextScanTime--;
        }, 1000);
    }

    // Función para pausar/reanudar el escaneo automático
    window.toggleAutoScan = () => {
        const statusElement = document.getElementById('auto-scan-status');
        const toggleButton = document.getElementById('toggle-auto-scan');
        
        if (autoScanActive) {
            // Pausar
            if (window.autoScanInterval) {
                clearInterval(window.autoScanInterval);
            }
            if (countdownInterval) {
                clearInterval(countdownInterval);
            }
            
            autoScanActive = false;
            statusElement.textContent = 'Escaneo automático: Pausado';
            statusElement.className = 'badge bg-warning ms-2';
            toggleButton.innerHTML = '<i class="fas fa-play"></i> Reanudar';
            
            const countdownElement = document.getElementById('next-scan-countdown');
            if (countdownElement) {
                countdownElement.textContent = 'Pausado';
            }
        } else {
            // Reanudar
            autoScanActive = true;
            statusElement.textContent = 'Escaneo automático: Activo';
            statusElement.className = 'badge bg-info ms-2';
            toggleButton.innerHTML = '<i class="fas fa-pause"></i> Pausar';
            
            // Reiniciar escaneo automático
            window.autoScanInterval = setInterval(() => {
                if (autoScanActive) {
                    runAllScans();
                }
            }, 300000); // 5 minutos
            
            startCountdown();
        }
    };

});

