const cors = require('cors');
const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());

app.use(cors());

// MySQL connection
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'ss',
    password: 'Sindu_2004',
    database: 'factflare'
});

connection.connect(err => {
    if (err) throw err;
    console.log('Connected to MySQL Server!');
    console.log('')
});

function login() {
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;

    fetch('http://localhost:3001/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email, password })
    }).then(response => {
        if (response.ok) {
            document.getElementById('auth-container').style.display = 'none';
            document.getElementById('content').style.display = 'block';
        } else {
            alert('Invalid credentials');
        }
    });
}

function passwordStrength(password) {
    // this object has the special characters, letters everything that is necessary for a strong password
    var mediumRegex = new RegExp("^(((?=.*[a-z])(?=.*[A-Z]))|((?=.*[a-z])(?=.*[0-9]))|((?=.*[A-Z])(?=.*[0-9])))(?=.{6,})");
    // comparing user inputted password with the condition for strong password
    if (mediumRegex.test(password) == true) {
        return true;
    }
    else {
        return false;
    }
}

function validateEmail(emailID) {
    // getting posotion of @ from user input 
    let atpos = emailID.indexOf("@");
    // getting position of . from the user input 
    let dotpos = emailID.lastIndexOf(".");

    // checking if @ and . is there in the email and if there is it in a valid position
    if (atpos < 1 || (dotpos - atpos < 2)) {
        // if the condition evaluates to false then alert pops up 
        alert("Please enter correct email ID");
        return false;
    }
    return (true);
}

function register() {
    const username = document.getElementById('register-username').value;
    const password = document.getElementById('register-password').value;
    const cpassword = document.getElementById('register-cpassword').value;
    const email = document.getElementById('register-email').value;

    
    // checking if the user has entered first name 
    if (username == "") {
        alert("Name field cannot be empty");
        return false;
    }

    // checking if the user has entered email and if user has entered a valid email
    else if (email == "" || validateEmail(email) == false) {
        alert("Email field cannot be empty");
        return false;
    }

    // checking if the user has entered a password
    else if (password == "") {
        alert("Password field cannot be empty");
        return false;
    }

    // checking if the user has entered confirm passowrd field as well 
    else if (cpassword == "") {
        alert("Confirm Password field cannot be empty");
        return false;
    }

    // checking if the user has entered same passowrd in both the fields that is password and confirm password 
    else if (password != cpassword) {
        alert("Your password is not matching");
        return false;
    }

    // Validate the password strength before proceeding
    else if (!passwordStrength(password)) {
        alert('Password does not meet the strength requirements.');
        return; // Stop the registration process if the password is weak
    }

    fetch('http://localhost:3001/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, password, email })
    }).then(response => {
        if (response.ok) {
            alert('Registration successful, please login.');
            showLoginForm();
        } else {
            response.text().then(text => alert(text)); // Show error message from server
        }
    }).catch(error => {
        console.error('Error:', error);
        alert('Error during registration.');
    });
}

function performVerification() {
    const text = document.getElementById("text-input").value;
    const image = document.getElementById("image-input").value;

    fetch('http://localhost:3000/predict', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ text: text, image: image })
    })
        .then(response => response.json())
        .then(data => {
            console.log("Received data:", data);
            if (data.prediction) {
                document.getElementById('prediction-result').textContent = 'Prediction: ' + data.prediction[0];
                displayReason(data.reasons);
            } else {
                alert('Failed to retrieve prediction and reason.');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Error performing verification.');
        });        
}

function displayReason(reasons) {
    const reasonElement = document.getElementById('reason-result');
    if (reasons == 'No distinctive words found based on the current TF-IDF model.'){
        reasonElement.innerHTML = 'Reasons for Classification:<br>' + reasons;
    }
    else {
        reasonElement.innerHTML = '';
        reasonElement.innerHTML = 'These words and their frequencies in the text led to the prediction<br>';
        reasons.forEach(reason => {
            reasonElement.innerHTML += `${reason.term}: ${reason.tfidf}<br>`;
        });
    }
    
}

function showLoginForm() {
    document.getElementById('login-form').style.display = 'block';
    document.getElementById('register-form').style.display = 'none';
}

function showRegisterForm() {
    document.getElementById('login-form').style.display = 'none';
    document.getElementById('register-form').style.display = 'block';
}

function logout() {
    location.reload(); // Or redirect to the login page
}

app.post('/register', async (req, res) => {
    const { username, password, email } = req.body;
    const hashedPassword = await bcrypt.hash(password, 8);

    connection.query(
        'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
        [username, hashedPassword, email],
        (err, results) => {
            if (err) {
                console.error(err);
                res.status(500).send('Error registering new user');
            } else {
                res.status(201).send('User registered');
            }
        }
    );
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    connection.query(
        'SELECT * FROM users WHERE email = ?',
        [email],
        async (err, results) => {
            if (results.length && await bcrypt.compare(password, results[0].password)) {
                res.status(200).send('Login successful');
            } else {
                res.status(401).send('Login failed');
            }
        }
    );
});

app.listen(3001, () => {
    console.log('Server is running on port 3000');
});
