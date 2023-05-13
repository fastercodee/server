<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Laravel\Sanctum\HasApiTokens;
use Illuminate\Support\Facades\DB;

class Sketch extends Model
{
  use HasApiTokens, HasFactory;

  protected $table = "sketches";
  protected $primaryKey = "uid";

  protected $fillable = [
    "uid",
    "by_user_uid",
    "private",
    "name",
    "description",
    "name_lower",
    "total_files_size",
    "forked_from",
    "updated_at",
    "created_at",
  ];

  public function user()
  {
    return $this->belongsTo(User::class, "by_user_uid", "uid");
  }
  public function files()
  {
    return $this->hasMany(File::class, "by_sketch_uid", "uid")->addSelect([
      "*",
      DB::raw('IF(unencodable_data = "1", NULL, data) as data'),
    ]);
  }
  public function files_raw()
  {
    return $this->hasMany(File::class, "by_sketch_uid", "uid");
  }
  public function files_short($paths = null)
  {
    $query = $this->hasMany(File::class, "by_sketch_uid", "uid")->select([
      "uid",
      "by_sketch_uid",
      "filePath",
      /*'data'*/ "hash",
      "size",
      "updated_at",
      "created_at",
    ]);

    if (!is_null($paths)) {
      $query->whereIn("filePath", $paths);
    }

    return $query;
  }
  public function file($filepath, $force = false)
  {
    $query = File::where("by_sketch_uid", $this->uid)->where(
      "filePath",
      $filepath
    );

    if (!$force) {
      $query = $query->selectRaw(
        '*, IF(unencodable_data = "1", NULL, data) as data'
      );
    }

    return $query->first();
  }

  public function forks()
  {
    return $this->hasMany(Sketch::class, "uid", "forked_from");
  }

  public function setPrivateAttribute($value)
  {
    if (in_array($value, [0, 1, 2], true)) {
      $this->attributes["private"] = $value;
    } else {
      $this->attributes["private"] = (bool) $value;
    }
  }

  public function getNotAccessPublicAttribute()
  {
    return $this->attributes["private"] === "2";
  }

  protected $hidden = ["by_user_uid", "name_lower"];

  protected $casts = [
    "private" => "boolean",
    // 'email_verified_at' => 'datetime',
  ];
}
