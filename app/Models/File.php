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
        'created_at'
    ];

   
    public function sketch() {
        return $this->belongsTo(Sketch::class, 'by_sketch_uid', 'uid');
    }


    protected $hidden = [
        'by_sketch_uid'
    ];
}
