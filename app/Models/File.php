<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Laravel\Sanctum\HasApiTokens;

class File extends Model
{
    use HasApiTokens, HasFactory;

    protected $table = 'files';
    protected $primaryKey = 'uid';

    protected $fillable = [
        'uid',
        'by_sketch_uid',
        'filePath',
        'data',
        'hash',
        'size',
        'updated_at',
        'created_at',
        'unencodable_data'
    ];

   
    public function sketch() {
        return $this->belongsTo(Sketch::class, 'by_sketch_uid', 'uid');
    }


    protected $hidden = [
        'by_sketch_uid'
    ];

    protected static function boot()
    {
        parent::boot();
        static::saving(function ($file) {
            if ($file->size > 1000000 || json_encode($file->data) === false) {
                $file->unencodable_data = true;
            } else {
                $file->unencodable_data = false;
            }
        });
    }

    protected $casts = [
      'unencodable_data' => 'boolean'
      // 'email_verified_at' => 'datetime',
    ];
}
