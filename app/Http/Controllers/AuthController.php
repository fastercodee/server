<?php

namespace App\Http\Controllers;

use App\Models\User;
use Google_Client;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Str;

const REGEX_USERNAME = '/^[a-z\d](?:[a-z\d_]|-(?=[a-z\d_])){0,38}$/i';
function response_user_and_token(User $user)
{
  $token = $user->createToken('authToken')->plainTextToken;

  return response()->json([
    'user' => $user,
  ], 200, [
      'Authorization' => 'Bearer ' . $token,
    ]);
}

/**
 * @return string|null
 */
function transform_name_to_username(string $name)
{
  // Loại bỏ các ký tự không phải chữ cái và số
  $transformedName = preg_replace('/[^a-zA-Z0-9]/', '', $name);

  // Giới hạn độ dài của chuỗi
  $transformedName = substr($transformedName, 0, 39);

  // Đảm bảo chuỗi bắt đầu bằng một ký tự chữ cái hoặc số
  if (!preg_match('/^[a-z\d]/i', $transformedName)) {
    $transformedName = 'a' . $transformedName;
  }

  // Kiểm tra xem chuỗi có hợp lệ không
  if (empty($transformedName) || !preg_match('/^[a-z\d](?:[a-z\d_]|-(?=[a-z\d_])){0,38}$/i', $transformedName)) {
    return null;
  }

  if ($transformedName === '')
    return null;

  return $transformedName;
}

/**
 * @return string
 */
function transform_username_to_username_lower(string $username)
{
  return str_replace('-', '_', $username);
}

class AuthController extends Controller
{
  public function login(Request $request)
  {
    $request->validate([
      'username' => [
        'required',
        function ($attribute, $value, $fail) {
          if (!(filter_var($value, FILTER_VALIDATE_EMAIL)) && !preg_match(REGEX_USERNAME, $value)) {
            return $fail('The :attribute must be either a valid email or match the regex pattern.');
          }
        }
      ],
      // email or username
      'password' => ['required', 'max:50', 'regex:/^(?=.*[A-Z])(?=.*\d).*$/']
    ]);

    $credentials = $request->only(['username', 'password']);
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

    /** @var User $user */
    $user = Auth::user();

    return response_user_and_token($user);
  }

  public function register(Request $request)
  {
    $request->validate([
      'email' => ['required', 'email', 'unique:users,email'],
      'username' => ['required', 'regex:' . REGEX_USERNAME],
      'name' => ['nullable', 'max:50'],
      'password' => ['required', 'regex:/^(?=.*[A-Z])(?=.*\d).*$/']
    ], [
        'email.unique' => 'The email has already been taken.',
      ]);

    $input = $request->only(['email', 'username', 'name', 'password']);
    $input['password'] = Hash::make($input['password']);

    // check username exists
    if (User::where('username_lower', transform_username_to_username_lower($input['username']))->exists())
      return response()->json([
        'message' => 'The username has already been taken.',
        'code' => 'username_already_taken'
      ], 409);

    $uid = User::create($input)->uid;

    $user = User::findOrFail($uid);

    return response_user_and_token($user);
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


  public function check_email(Request $request)
  {
    $request->validate([
      'email' => ['required', 'email', 'unique:users,email'],
    ], [
        'email.unique' => 'The email has already been taken.',
      ]);

    return response()->json([
      "code" => "not_exists"
    ]);
  }
  public function check_username(Request $request)
  {
    $request->validate([
      'username' => ['required', 'regex:' . REGEX_USERNAME],
    ]);

    // check username exists
    if (User::where('username_lower', transform_username_to_username_lower($request->get('username')))->exists())
      return response()->json([
        'message' => 'The username has already been taken.',
        'code' => 'username_already_taken'
      ], 409);

    return response()->json([
      "code" => "not_exists"
    ]);
  }

  public function oauth2(Request $request)
  {
    $request->validate([
      'id_token' => ['required', 'string'],
      'username' => ['nullable', 'regex:' . REGEX_USERNAME],
    ]);
    $username = $request->get('username');
    if ($username && User::where('username_lower', transform_username_to_username_lower($username))->exists())
      return response()->json([
        'message' => 'The username has already been taken.',
        'code' => 'username_already_taken'
      ], 409);


    $id_token = $request->get('id_token');

    $client = new Google_Client();
    $client->setClientId(env('GOOGLE_CLIENT_ID'));

    $payload = $client->verifyIdToken($id_token);

    if (!$payload)
      return response()->json([
        'message' => 'This token invalid',
        'code' => 'token_invalid'
      ], 401);

    $attributes = $payload->getAttributes()['payload'];

    $user_by_sub = User::firstWhere('sub', $attributes['sub']);

    if ($user_by_sub) {
      $email_db = $user_by_sub->email;
      $email_oa = $attributes['email'];

      if (!$email_db)
        $user_by_sub->update(['email' => $email_oa]);

      // ok $email_db and $email_oa ready


      return response_user_and_token($user_by_sub);
    }

    // user by sub not found
    $user_by_email = User::firstWhere('email', $attributes['email']);

    if ($user_by_email) {
      // accept login ok
      // email valid
      return response_user_and_token($user_by_email);
    }

    // user not exists, uid ok, sub ok, email ok
    // continue register new user
    if (is_null($username)) {
      $username = transform_name_to_username($attributes['name']);

      if ($username === null || User::where('username_lower', strtolower(str_replace('-', '_', $username)))->exists()) {
        return response()->json([
          'message' => 'Username required',
          'code' => 'username_required'
        ], 201);
      }
    }

    // $username exists
    // ['email', 'username', 'name', 'password']
    $email = $attributes['email'];
    // $username as const
    $name = $attributes['name'];
    // $password = null;
    $picture = $attributes['picture'];
    $oauth2_google_sub = $attributes['sub'];

    $uid = User::create([
      'email' => $email,
      'name' => $name,
      'picture' => $picture,
      'oauth2_google_sub' => $oauth2_google_sub
    ])->uid;
    
    $user = User::findOrFail($uid);

    return response_user_and_token($user);
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

    if (!Hash::check(request()->password, $request->user()['password'])) {
      return response()->json([
        'message' => 'Incorrect password',
      ], 403);
    }

    $request->user()->delete();

    return response()->json(null, 204);
  }
}
