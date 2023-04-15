<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Laravel\Sanctum\HasApiTokens;

class Sketch extends Model
{
  use HasApiTokens, HasFactory;

  protected $table = 'sketches';
  protected $primaryKey = 'uid';

  protected $fillable = [
    'uid',
    'by_user_uid',
    'private',
    'name',
    'name_lower',
    'total_files_size',
    'updated_at',
    'created_at'
  ];


  public function user()
  {
    return $this->belongsTo(User::class, 'by_user_uid', 'uid');
  }
  public function files()
  {
    return $this->hasMany(File::class, 'by_sketch_uid', 'uid');
  }
  public function files_short($paths = null)
  {
    $query = $this->hasMany(File::class, 'by_sketch_uid', 'uid')
      ->select(['uid', 'by_sketch_uid', 'filePath', /*'data'*/'hash', 'size', 'updated_at', 'created_at']);


    if (!is_null($paths)) {
      $query->whereIn('filePath', $paths);
    }

    return $query;
  }
  public function file($filepath)
  {
    return File::where('by_sketch_uid', $this->uid)
      ->where('filePath', $filepath)
      ->first();
  }

  protected $hidden = [
    'by_user_uid',
    'name_lower'
  ];

  protected $casts = [
    'private' => 'boolean'
    // 'email_verified_at' => 'datetime',
  ];
}