<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Str;

class AuthController extends Controller
{
  public function login(Request $request)
  {
    $request->validate([
      'username' => [
        'required',
        function ($attribute, $value, $fail) {
          if (!(filter_var($value, FILTER_VALIDATE_EMAIL)) && !preg_match('/^[a-z\d](?:[a-z\d_]|-(?=[a-z\d_])){0,38}$/i', $value)) {
            return $fail('The :attribute must be either a valid email or match the regex pattern.');
          }
        }
      ],
      // email or username
      'password' => ['required', 'max:50', 'regex:/^(?=.*[A-Z])(?=.*\d).*$/']
    ]);

    $credentials = $request->only(['username', 'password']);
    $credentials['username'] = strtolower($credentials['username']);
    // $credentials['password'] = Hash::make($credentials['password']);

    if (
      !Auth::attempt(!!filter_var($credentials['username'], FILTER_VALIDATE_EMAIL) ? [
        'email' => $credentials['username'],
        'password' => $credentials['password']
      ] : [
          'username_lower' => $credentials['username'],
          'password' => $credentials['password']
        ])
    ) {
      return response()->json([
        'message' => 'Unauthorized'
      ], 401);
    }

    $user = Auth::user();

    $token = $user->createToken('authToken')->plainTextToken;

    return response()->json([
      'user' => $user,
    ], 200, [
        'Authorization' => 'Bearer ' . $token,
      ]);
  }

  public function register(Request $request)
  {
    $request->validate([
      'email' => ['required', 'email', 'unique:users,email'],
      'username' => ['required', 'regex:/^[a-z\d](?:[a-z\d_]|-(?=[a-z\d_])){0,38}$/i'],
      'name' => ['nullable', 'max:50'],
      'password' => ['required', 'regex:/^(?=.*[A-Z])(?=.*\d).*$/']
    ]);

    $input = $request->only(['email', 'username', 'name', 'password']);
    $input['password'] = Hash::make($input['password']);

    // check username exists
    if (User::where('username_lower', strtolower($input['username']))->exists())
      return response()->json([
        'message' => 'The username has already been taken.'
      ]);

    $user = User::create($input);

    $token = $user->createToken('authToken')->plainTextToken;

    return response()->json([
      'user' => $user,
    ], 200, [
        'Authorization' => 'Bearer ' . $token,
      ]);
  }

  public function forgot_password(Request $request)
  {
    $request->validate(['email' => 'required|email']);

    $status = Password::sendResetLink(
      $request->only('email')
    );

    if ($status === Password::RESET_LINK_SENT)
      return response()->json([
        'message' => 'Send link reset password success'
      ]);
    else
      return response()->json([
        'message' => $status
      ]);
  }

  public function reset_password(Request $request)
  {
    $request->validate([
      'token' => 'required',
      'email' => 'required|email',
      'password' => 'required|min:8|confirmed',
    ]);

    $status = Password::reset(
      $request->only('email', 'password', 'password_confirmation', 'token'),
      function (User $user, string $password) {
        $user->forceFill([
          'password' => Hash::make($password)
        ])->setRememberToken(Str::random(60));

        $user->save();

        event(new PasswordReset($user));
      }
    );

    if ($status === Password::PASSWORD_RESET)
      return response()->json([
        'message' => 'Reset password success'
      ]);
    else
      return response()->json([
        'message' => $status
      ]);
  }

  # need auth
  public function logout(Request $request)
  {
    $user = $request->user();
    $user->tokens()->where('id', $user->currentAccessToken()->id)->delete();
    Auth::logout();
  }
}