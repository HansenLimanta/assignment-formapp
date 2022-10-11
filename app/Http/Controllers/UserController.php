<?php

namespace App\Http\Controllers;

use Exception;
use App\Models\User;
use Illuminate\Support\Str;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Validation\Rule;

class UserController extends Controller
{
    public function create() {
        return view('users.register');
    }
    
    public function login() {
        return view('users.login');
    }

    public function store(Request $request) {
        $formFields = $request->validate([
            'name' => ['required', 'min:3'],
            'email' => ['required', 'email', Rule::unique('users','email')],
            'password' => ['required','confirmed','min:10', 'regex:/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*(_|[^\w])).+$/']
        ]);

        // Hash Password
        $formFields['password'] = bcrypt($formFields['password']);

        // Create User
        $user = User::create($formFields);

        // Login
        auth()->login($user);

        return redirect('/')->with('message', 'User created and login');
    }

    public function logout(Request $request) {
        auth()->logout();
        
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect('/')->with('message', 'You have been logged out!');
    }

    public function authenticate(Request $request) {
        if($this->checkTooManyFailedAttempts()){
            RateLimiter::clear($this->throttleKey());
            return view('users.wrong-password')->with('message', 'Try again in 30s');
        }

        $user = User::where('email', $request->email)->first();

        try {
            $credentials = request(['email', 'password']);

            if (!Auth::attempt($credentials))
            {
                RateLimiter::hit($this->throttleKey(), 1800);

                return back()->withErrors(['email' => 'Invalid Credentials'])->onlyInput('email');

            }

            if (!Hash::check($request->password, $user->password, [])) {
                throw new Exception('Error occured while logging in.');
            }

            RateLimiter::clear($this->throttleKey());
            
            $request->session()->regenerate();


            return redirect('/')->with('message', 'You are now logged in!');
        } catch (Exception $error) {
            return back()->withErrors(['email' => 'Invalid Credentials'])->onlyInput('email');
        }
    }

    public function throttleKey() {
        return Str::lower(request('email')) . '|' . request()->ip();
    }

    public function checkTooManyFailedAttempts() {
        if(! RateLimiter::tooManyAttempts($this->throttleKey(),3)){
            return false;
        }
        return true;
    }
}
