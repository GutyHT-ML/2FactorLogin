<?php

use Illuminate\Support\Facades\Auth;
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

Auth::routes();

Route::get('/home', 'HomeController@index')->name('home');

Route::post('/login-two-factor/{user}', 'Auth\LoginController@login2FA')->name('login.2fa');

Route::post('/login-2-f/{user}', 'Auth\LoginController@signedLogin')->name('signed.login');

Auth::routes();

Route::get('/home', 'HomeController@index')->name('home');
