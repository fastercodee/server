<?php
use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;

class UserFactory extends Factory
{
  protected $model = User::class;

  public function definition()
  {
    return [
      "uid" => $this->faker->unique()->randomNumber(),
      "email" => $this->faker->unique()->safeEmail,
      "username" => $this->faker->unique()->userName,
      "name" => $this->faker->name,
      "password" =>
        '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
      "updated_at" => now(),
      "created_at" => now(),
    ];
  }
}
