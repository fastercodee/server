<?php
use App\Models\File;
use Illuminate\Database\Eloquent\Factories\Factory;

class FileFactory extends Factory
{
  protected $model = File::class;

  public function definition()
  {
    return [
      "uid" => $this->faker->unique()->randomNumber(),
      "by_sketch_uid" => $this->faker->randomNumber(),
      "filePath" => $this->faker->filePath(),
      "data" => $this->faker->text,
      "hash" => $this->faker->sha256,
      "size" => $this->faker->numberBetween(0, 1000000),
      "updated_at" => now(),
      "created_at" => now(),
    ];
  }
}
