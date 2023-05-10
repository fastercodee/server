<?php
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Tests\TestCase;

class AuthControllerTest extends TestCase
{
  use RefreshDatabase;

  public function test_login()
  {
    $user = User::factory()->create([
      "password" => Hash::make("password"),
    ]);

    $response = $this->postJson("/login", [
      "username" => $user->email,
      "password" => "password",
    ]);

    $response->assertStatus(200);
    $response->assertHeader("Authorization");
    $this->assertAuthenticatedAs($user);
  }
}
