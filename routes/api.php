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
Route::middleware("guest")->group(function () {
  Route::post("auth/login", [AuthController::class, "login"]);
  Route::post("auth/register", [AuthController::class, "register"]);
  Route::post("auth/check_email", [AuthController::class, "check_email"]);
  Route::post("auth/check_username", [AuthController::class, "check_username"]);

  // oauth 2
  Route::post("auth/oauth2", [AuthController::class, "oauth2"]);

  // restore account
  Route::get("auth/password/reset/{token}", [
    AuthController::class,
    "reset_password",
  ])->name("password.reset");
  Route::post("auth/forgot-password", [
    AuthController::class,
    "forgot_password",
  ])->name("password.email");
});

Route::middleware("auth:sanctum")->group(function () {
  Route::post("auth/logout", [AuthController::class, "logout"]);
  Route::post("auth/destroy", [AuthController::class, "destroy"]);
});

Route::middleware("auth:sanctum")->group(function () {
  Route::get("auth/user", function (Request $request) {
    return $request->user();
  });
});

Route::middleware("auth:sanctum")->group(function () {
  Route::post("sketch/create", [SketchController::class, "create"]);
  Route::post("sketch/update", [SketchController::class, "update"]);
  Route::post("sketch/update_info", [SketchController::class, "update_info"]);
  Route::post("sketch/check_name", [SketchController::class, "check_name"]);
  Route::post("sketch/fork", [SketchController::class, "fork"]);
  Route::post("sketch/delete", [SketchController::class, "delete"]);
});

Route::group([], function () {
  Route::post("sketch/fetch", [SketchController::class, "fetch"]);
  Route::post("sketch/get_file", [SketchController::class, "get_file"]);
});
