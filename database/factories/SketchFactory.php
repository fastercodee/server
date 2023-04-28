<?php
use App\Models\Sketch;
use Illuminate\Database\Eloquent\Factories\Factory;

class SketchFactory extends Factory
{
    protected $model = Sketch::class;

    public function definition()
    {
        return [
            'uid' => $this->faker->unique()->randomNumber(),
            'by_user_uid' => $this->faker->randomNumber(),
            'private' => $this->faker->boolean,
            'name' => $this->faker->word,
            'total_files_size' => $this->faker->numberBetween(0, 1000000),
            'updated_at' => now(),
            'created_at' => now(),
        ];
    }
}