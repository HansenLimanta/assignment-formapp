<?php

use App\Http\Controllers\UserController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

Route::get('/', function () {
    return view('welcome');
});

Route::get('/login', [UserController::class, 'login'])->name('login')->middleware('guest');

Route::get('/register', [UserController::class, 'create'])->middleware('guest');

Route::post('/users', [UserController::class, 'store']);

Route::post('/logout', [UserController::class, 'logout'])->middleware('auth');

Route::post('/users/authenticate', [UserController::class, 'authenticate']);

Route::get('/reset-password', [UserController::class, 'showReset'])->middleware('guest')->name('password.request');

Route::post('/reset-password', [UserController::class, 'resetPassword'])->middleware('guest')->name('password.reset');

Route::post('/forget-password', [UserController::class, 'forgetPassword'])->middleware('guest')->name('password.email');