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

    $is_login_with_email = !!filter_var($credentials['username'], FILTER_VALIDATE_EMAIL);
    if (
      !Auth::attempt($is_login_with_email ? [
        'email' => $credentials['username'],
        'password' => $credentials['password']
      ] : [
          'username_lower' => $credentials['username'],
          'password' => $credentials['password']
        ])
    ) {
      return response()->json([
        'message' => $is_login_with_email ? 'Email or password is incorrect' : 'Username or password is incorrect',
        'code' => $is_login_with_email ? 'email_or_password_incorrect' : 'username_or_password_incorrect'
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
    ], [
        'email.unique' => 'The email has already been taken.',
      ]);

    $input = $request->only(['email', 'username', 'name', 'password']);
    $input['password'] = Hash::make($input['password']);

    // check username exists
    if (User::where('username_lower', strtolower($input['username']))->exists())
      return response()->json([
        'message' => 'The username has already been taken.',
        'code' => 'username_already_taken'
      ], 409);

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


  public function check_email(Request $request) {
		$request->validate([
      'email' => ['required', 'email', 'unique:users,email'],
    ], [
        'email.unique' => 'The email has already been taken.',
      ]);
			
		return response()->json([
			"code" => "not_exists"
		]);
	}
	public function check_username(Request $request) {
		$request->validate([
      'username' => ['required', 'regex:/^[a-z\d](?:[a-z\d_]|-(?=[a-z\d_])){0,38}$/i'],
    ]);
		
    // check username exists
    if (User::where('username_lower', str_replace('-', '_', strtolower($request->get('username'))))->exists())
      return response()->json([
        'message' => 'The username has already been taken.',
        'code' => 'username_already_taken'
      ], 409);
			
		return response()->json([
			"code" => "not_exists"
		]);
	}
	
  # need auth
  public function logout(Request $request)
  {
    $user = $request->user();
    $user->tokens()->where('id', $user->currentAccessToken()->id)->delete();
    Auth::guard('web')->logout();

    return response()->json([
      'message' => "Logout success"
    ]);
  }

  public function destroy(Request $request)
  {
    $request->validate([
      'password' => ['required', 'max:50', 'regex:/^(?=.*[A-Z])(?=.*\d).*$/'],
    ]);

    if (!Hash::check(request()->password,  $request->user()['password'])) {
      return response()->json([
        'message' => 'Incorrect password',
      ], 403);
    }

    $request->user()->delete();

    return response()->json(null, 204);
  }
}
