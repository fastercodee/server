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
Route::middleware('guest')->group(function () {
  Route::post('login', [AuthController::class, 'login']);
  Route::post('register', [AuthController::class, 'register']);
  Route::get('password/reset/{token}', [AuthController::class, 'reset_password'])->name('password.reset');
  Route::post('forgot-password', [AuthController::class, 'forgot_password'])->name('password.email');
});

Route::middleware('auth:sanctum')->group(function () {
  Route::post('logout', [AuthController::class, 'logout']);
  Route::post('destroy', [AuthController::class, 'destroy']);
});


Route::middleware('auth:sanctum')->group(function () {
  Route::get('/user', function (Request $request) {
      return $request->user();
  });
});

Route::middleware('auth:sanctum')->group(function () {
  Route::post('sketch/create', [SketchController::class, 'create']);
  Route::post('sketch/update', [SketchController::class, 'update']);
  Route::post('sketch/delete', [SketchController::class, 'delete']);
});

Route::group([], function () {
  Route::post('sketch/fetch', [SketchController::class, 'fetch']);
  Route::post('sketch/get_file', [SketchController::class, 'get_file']);
});