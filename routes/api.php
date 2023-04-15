<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\SketchController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

Route::controller(AuthController::class)
  ->middleware('guest')->group(function () {
    Route::post('login', 'login');
    Route::post('register', 'register');
    Route::get('password/reset/{token}', 'reset_password')->name('password.reset');
    Route::post('forgot-password', 'forgot_password')->name('password.email');
  })
  ->middleware('auth:sanctum')->group(function () {
    Route::post('logout', 'logout');
  });

Route::middleware('auth:sanctum')
  ->group(function () {
    Route::get('/user', function (Request $request) {
      return $request->user();
    });
  });

Route::controller(SketchController::class)
  ->middleware('auth:sanctum')->group(function () {
    Route::post('sketch/create', 'create');
    Route::post('sketch/update', 'update');
    Route::post('sketch/delete', 'delete');
    Route::post('sketch/get_file', 'get_file');
  })
  ->middleware([])->group(function () {
    Route::post('sketch/fetch', 'fetch');
  });