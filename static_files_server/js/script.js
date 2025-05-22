document.addEventListener('DOMContentLoaded', function() {
    // Slider functionality
    const slider = document.querySelector('.slider');
    if (slider) {
        const slideContainer = slider.querySelector('.slide-container');
        const slides = slider.querySelectorAll('.slide');
        const sliderNav = slider.querySelector('.slider-nav');
        let currentSlide = 0;

        slides.forEach((_, index) => {
            const button = document.createElement('button');
            button.addEventListener('click', () => goToSlide(index));
            sliderNav.appendChild(button);
        });

        const navButtons = sliderNav.querySelectorAll('button');

        function goToSlide(index) {
            currentSlide = index;
            slideContainer.style.transform = `translateX(-${index * 100}%)`;
            updateNavButtons();
        }

        function updateNavButtons() {
            navButtons.forEach((button, index) => {
                if (index === currentSlide) {
                    button.classList.add('active');
                } else {
                    button.classList.remove('active');
                }
            });
        }

        function nextSlide() {
            currentSlide = (currentSlide + 1) % slides.length;
            goToSlide(currentSlide);
        }

        setInterval(nextSlide, 5000);
        updateNavButtons();
    }

    
});
document.addEventListener('DOMContentLoaded', function() {
    // Existing code...

    // Handle login form submission
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const recaptchaResponse = grecaptcha.getResponse();

            if (!recaptchaResponse) {
                alert('Por favor, completa el reCAPTCHA');
                return;
            }

            console.log('Login attempt:', { email, password });
            
            // Simulate login (replace with actual authentication logic)
            if (email && password) {
                localStorage.setItem('isLoggedIn', 'true');
                window.location.href = 'perfil.html';
            }
        });
    }

    // Handle Google Sign-In
    window.handleCredentialResponse = function(response) {
        // Decode the JWT token
        const responsePayload = decodeJwtResponse(response.credential);

        console.log("ID: " + responsePayload.sub);
        console.log('Full Name: ' + responsePayload.name);
        console.log('Given Name: ' + responsePayload.given_name);
        console.log('Family Name: ' + responsePayload.family_name);
        console.log("Image URL: " + responsePayload.picture);
        console.log("Email: " + responsePayload.email);

        // Simulate login with Google (replace with actual authentication logic)
        localStorage.setItem('isLoggedIn', 'true');
        window.location.href = 'perfil.html';
    }

    function decodeJwtResponse(token) {
        var base64Url = token.split('.')[1];
        var base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        var jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));

        return JSON.parse(jsonPayload);
    }

    // Existing code...
});

function confirmar_eliminar(ruta){
    console.log(ruta);
    if(confirm("Está seguro? ")){
        location.href = ruta;
    }
}