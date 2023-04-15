<?php

namespace App\Http\Controllers;

use App\Models\File;
use App\Models\Sketch;
use Illuminate\Http\Request;



class SketchController extends Controller
{


  public function create(Request $request)
  {
    $request->validate([
      'name' => ['nullable', 'string', 'max:50'],
      'private' => ['nullable', 'in:0,1'],

      'meta' => [
        'required',
        'array',
        'max:120',
        function ($attribute, $value, $fail) {
          if (count($value) !== count(request()->file('files')))
            return $fail('The number of meta must be equal to the number of files')
            ;
        }
      ],
      'meta.*' => ['string', 'min:1', 'max:260', 'regex:/^([a-zA-Z0-9_]+\/)*[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+$/'],
      'files' => ['required', 'array', 'min:1', 'max:120'],
      'files.*' => ['file', 'max:5120']
    ]);

    $totalSize = 0;
    foreach ($request->file('files') as $file) {
      $totalSize += $file->getSize();

      if ($totalSize > 13 * 1024 * 1024) {
        return response()->json([
          'message' => 'Total size files <= 13MB',
          'code' => 'total_size_gt_13mb'
        ], 422);
      }
    }

    // save base sketch
    $input = request()->only(['name', 'private']);
    $input['by_user_uid'] = $request->user()->uid;
    $input['total_files_size'] = $totalSize;
    // ready name private by_user_uid;

    if (isset($input['name']) && Sketch::where('by_user_uid', request()->user()->uid)->where('name_lower', strtolower($input['name']))->exists())
      return response()->json([
        'message' => 'Sketch name exists in sketches of you',
        'code' => 'sketch_name_exists'
      ], 409);


    $sketch = Sketch::findOrFail(Sketch::create($input)->uid);

    // save files
    $meta = $request->get('meta');
    $by_sketch_uid = $sketch->uid;
    $files = [];
    $now = now();

    foreach ($request->file('files') as $index => $file) {
      $path = $file->getRealPath();
      $size = $file->getSize();
      $hash = hash_file('sha256', $path);

      $files[$index] = [
        'by_sketch_uid' => $by_sketch_uid,
        'filePath' => $meta[$index],
        'data' => file_get_contents($path),
        'hash' => $hash,
        'size' => $size,
        'created_at' => $now,
        'updated_at' => $now
      ];
    }

    File::insert($files);

    $sketch->user;
    return response()->json([
      'sketch' => $sketch,
    ]);
  }

  public static function mapFileData($file)
  {
    if ($file->size > 1_000_000 || json_encode($file->data) === false) {
      // delete field 'data'. need call request /sketch/get_file
      unset($file['data']);
    }
    return $file;
  }

  public function get_file(Request $request)
  {
    $validated = $request->validate([
      'uid' => ['required', 'integer', 'max:99999999999999999999'],
    ]);

    $user = request()->user();

    $file = File::where('uid', $validated['uid'])
      ->whereHas('sketch', function ($query) use ($user) {
        $query->where('by_user_uid', $user->uid);
      })
      ->firstOrFail();

    return response($file['data'])->header('Content-Type', 'application/octet-stream');
  }

  public function fetch(Request $request)
  {
    $validated = $request->validate([
      'uid' => ['required', 'integer', 'max:99999999999999999999'],

      'meta' => [
        'array',
        'max:120',
        function ($attribute, $value, $fail) {
          if (!is_array(request()->get('hashes')) || count($value) !== count(request()->get('hashes')))
            return $fail('The number of meta must be equal to the number of hashes')
            ;
        }
      ],
      'meta.*' => ['string', 'min:1', 'max:260', 'regex:/^([a-zA-Z0-9_]+\/)*[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+$/'],
      'hashes' => ['array'],
      'hashes.*' => ['string', 'size:64', 'regex:/^[0-9a-f]{64}$/']
    ]);

    $sketch = Sketch::findOrFail($validated['uid']);


    if ($sketch->private ? request()->user() === null || $sketch->by_user_uid !== request()->user()->uid : false) {
      return response()->json([
        'message' => "Sketch is private",
        'code' => 'sketch_is_private'
      ], 403);
    }

    $meta = request()->get('meta');
    if ($meta == null) {
      // client not exists

      $sketch->user;
      foreach ($sketch->files as $file)
        [SketchController::class, 'mapFileData']($file);

      return response()->json([
        'sketch' => $sketch
      ]);
    }

    $hashes = request()->get('hashes');
    $files_local = array_combine($meta, $hashes);

    $files_change = []; // all files of sketch on cloud : $sketch->files;
    // all files of sketch on client: request->only(['meta', 'hashes'])
    // check files diff 
    foreach ($sketch->files_short as $file) {
      // check this file in client?
      if (isset($files_local[$file->filePath])) {
        // check file changes
        $hash_in_client = $files_local[$file->filePath];
        if ($hash_in_client === $file->hash) {
          // file not change
          continue;
        } else {
          // file changes
          $files_change[$file->filePath] = [
            "type" => "M",
            "file" => [SketchController::class, 'mapFileData']($sketch->file($file->filePath))
          ];
        }
      } else {
        // file not in client // mark this file added;
        $files_change[$file->filePath] = [
          "type" => "U+",
          "file" => [SketchController::class, 'mapFileData']($sketch->file($file->filePath))
        ];
      }
      unset($files_local[$file->filePath]);
    }
    // check new file on locals
    foreach ($files_local as $filePath => $hash) {
      $files_change[$filePath] = [
        'type' => 'U'
      ];
    }

    $sketch->user;
    unset($sketch['files_short']);
    return response()->json([
      'sketch' => $sketch,
      'file_changes' => $files_change
    ]);
  }

  public function update(Request $request)
  {
    $validated = $request->validate([
      'uid' => ['required', 'integer', 'max:99999999999999999999'],

      'meta' => [
        'array',
        'max:120',
        function ($attribute, $value, $fail) {
          if (!is_array(request()->file('files')) || count($value) !== count(request()->file('files')))
            return $fail('The number of meta must be equal to the number of files')
            ;
        }
      ],
      'meta.*' => ['string', 'min:1', 'max:260', 'regex:/^([a-zA-Z0-9_]+\/)*[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+$/'],
      'files' => ['array', 'max:120'],
      'files.*' => ['file', 'max:5120'],
      'deletes' => ['array', 'max:120'],
      'deletes.*' => ['string', 'min:1', 'max:260', 'regex:/^([a-zA-Z0-9_]+\/)*[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+$/']
    ]);

    $sketch = Sketch::findOrFail($validated['uid']);
    if ($sketch->by_user_uid !== $request->user()->uid)
      return response()->json([
        "message" => "You do not have permission to update this sketch",
        'code' => 'do_not_have_permission_to_update'
      ], 403);

    $files = $request->file('files');
    $files_delete = isset($validated['deletes']) ? $validated['deletes'] : null;
    if (!($files) && !($files_delete))
      return response()->json([
        'message' => 'No need action',
        'code' => 'no_need_action'
      ], 201);

    $total_files_size = $sketch->total_files_size;

    $files_update = [];
    $files_update_on_db = [];
    $files_add = [];
    if ($files !== null) {
      $files_update_on_db = $sketch->files_short($validated['meta'])->get()->keyBy('filePath');
      $meta = $validated['meta'];

      foreach ($files as $index => $file) {
        $hash = hash_file('sha256', $file->getRealPath());
        $size = $file->getSize();
        $filePath = $meta[$index];

        if (!isset($files_update_on_db[$filePath])) {
          // file new
          $total_files_size += $size;
          array_push($files_add, [
            'filePath' => $filePath,
            'file' => $file,
            'hash' => $hash,
            'size' => $size
          ]);
          continue;
        }
        $short_on_db = $files_update_on_db[$meta[$index]];

        if ($size === $short_on_db->size && $hash === $short_on_db->hash)
          continue;

        $total_files_size += $size - $short_on_db->size;
        // file change
        $files_update[$filePath] = [
          'filePath' => $filePath,
          'file' => $file,
          'hash' => $hash,
          'size' => $size
        ];
      }
    }

    if ($files_delete) {
      $files_delete = $sketch->files_short($files_delete);

      foreach ($files_delete as $file_short) {
        $total_files_size -= $file_short->size;
      }
    }


    if ($total_files_size > 13 * 1024 * 1024) {
      return response()->json([
        'message' => 'Total size files <= 13MB',
        'code' => 'total_size_gt_13mb'
      ], 422);
    }

    if (!$files_delete && count($files_update) === 0 && count($files_add) === 0)
      return response()->json([
        'message' => 'No need action',
        'code' => 'no_need_action'
      ], 201);

    // update total size sketch
    $sketch->update(['total_files_size' => $total_files_size]);
    // delete files
    if ($files_delete)
      $files_delete->delete();
    // update files
    foreach ($files_update as $filePath => $diff) {
      $files_update_on_db[$filePath]->update($diff);
    }
    // add files
    $now = now();
    File::insert(array_map(function ($diff) use ($sketch, $now) {
      $diff['by_sketch_uid'] = $sketch->uid;
      $diff['data'] = file_get_contents($diff['file']->getRealPath());

      $diff['created_at'] = $now;
      $diff['updated_at'] = $now;

      unset($diff['file']);
      return $diff;
    }, $files_add));

    return response()->json([
      'sketch' => $sketch,
    ]);
  }

  public function delete(Request $request)
  {
    $validated = $request->validate([
      'uid' => ['required', 'integer', 'max:99999999999999999999'],
    ]);

    $sketch = Sketch::findOrFail($validated['uid']);

    if ($sketch->by_user_uid !== $request->user()->uid)
      return response()->json([
        "message" => "You do not have permission to update this sketch",
        'code' => 'do_not_have_permission_to_update'
      ]);

    $sketch->delete();

    return response()->json([
      'message' => 'Deleted sketch'
    ]);
  }
}