import React, { useState } from 'react';
import './style.css';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

const Login = () => {
    const [values, setValues] = useState({
        email: '',
        password: ''
    });
    const [error, setError] = useState(null);
    const [loading, setLoading] = useState(false); // Loading state to disable form during request
    const navigate = useNavigate();

    axios.defaults.withCredentials = true; // Ensure you need this based on your backend config

    const handleSubmit = (event) => {
        event.preventDefault();

        // Client-side validation
        if (!values.email || !values.password) {
            setError("Email and password are required");
            return;
        }

        setLoading(true);  // Set loading to true before making the request
        setError(null);    // Reset any previous error

        axios.post('http://localhost:3000/auth/adminlogin', values)
            .then(result => {
                console.log('Login result:', result.data); // Log for debugging

                if (result.data.loginStatus) {
                    localStorage.setItem("valid", true);
                    navigate('/dashboard');
                } else {
                    setError(result.data.Error || "Login failed");
                }
            })
            .catch(err => {
                console.error('Error during login:', err);
                setError("An error occurred. Please try again.");
            })
            .finally(() => {
                setLoading(false); // Stop loading state regardless of success or failure
            });
    };

    return (
        <div className='d-flex justify-content-center align-items-center vh-100 loginPage'>
            <div className='p-3 rounded w-25 border loginForm'>
                {error && <div className='text-warning'>{error}</div>} {/* Display error */}
                <h2>Login Page</h2>
                <form onSubmit={handleSubmit}>
                    <div className='mb-3'>
                        <label htmlFor="email"><strong>Email:</strong></label>
                        <input 
                            type="email" 
                            name='email' 
                            autoComplete='off' 
                            placeholder='Enter Email'
                            onChange={(e) => setValues({...values, email: e.target.value})} 
                            className='form-control rounded-0' 
                            disabled={loading} // Disable input if loading
                        />
                    </div>
                    <div className='mb-3'>
                        <label htmlFor="password"><strong>Password:</strong></label>
                        <input 
                            type="password" 
                            name='password' 
                            placeholder='Enter Password'
                            onChange={(e) => setValues({...values, password: e.target.value})} 
                            className='form-control rounded-0' 
                            disabled={loading} // Disable input if loading
                        />
                    </div>
                    <button 
                        className='btn btn-success w-100 rounded-0 mb-2' 
                        type="submit"
                        disabled={loading} // Disable button if loading
                    >
                        {loading ? 'Logging in...' : 'Log in'}
                    </button>
                    <div className='mb-1'>
                        <input type="checkbox" name="tick" id="tick" className='me-2' />
                        <label htmlFor="tick">You agree with terms & conditions</label>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default Login;
