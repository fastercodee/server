<?php

namespace App\Http\Controllers;

use App\Models\File;
use App\Models\Sketch;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Database\Eloquent\ModelNotFoundException;

define("RULE_FILEPATH", 'regex:/^(?:[^\/\0]+\/)*[^\/\0]+$/');
define("RULE_UID", ["required", "integer", "max:99999999999999999999"]);

class SketchController extends Controller
{
  public function create(Request $request)
  {
    $request->validate([
      "name" => ["nullable", "string", "min:1", "max:50"],
      "private" => ["nullable", "in:0,1"],

      "meta" => [
        "required",
        "array",
        "max:120",
        function ($attribute, $value, $fail) {
          if (count($value) !== count(request()->file("files"))) {
            return $fail(
              "The number of meta must be equal to the number of files"
            );
          }
        },
      ],
      "meta.*" => ["string", "min:1", "max:260", RULE_FILEPATH],
      "files" => ["required", "array", "min:1", "max:120"],
      "files.*" => ["file", "max:5120"],
    ]);

    $totalSize = 0;
    foreach ($request->file("files") as $file) {
      $totalSize += $file->getSize();

      if ($totalSize > 13 * 1024 * 1024) {
        return response()->json(
          [
            "message" => "Total size files <= 13MB",
            "code" => "total_size_gt_13mb",
          ],
          422
        );
      }
    }

    // save base sketch
    $input = request()->only(["name", "private"]);
    $input["by_user_uid"] = $request->user()->uid;
    $input["total_files_size"] = $totalSize;
    // ready name private by_user_uid;

    if (
      isset($input["name"]) &&
      Sketch::where("by_user_uid", request()->user()->uid)
        ->where("name_lower", strtolower($input["name"]))
        ->exists()
    ) {
      return response()->json(
        [
          "message" => "Sketch name exists in sketches of you",
          "code" => "sketch_name_exists",
        ],
        409
      );
    }

    $sketch = Sketch::findOrFail(Sketch::create($input)->uid);

    // save files
    $meta = $request->get("meta");
    $by_sketch_uid = $sketch->uid;
    $files = [];
    $now = now();

    foreach ($request->file("files") as $index => $file) {
      $path = $file->getRealPath();
      $size = $file->getSize();
      $hash = hash_file("sha256", $path);
      $data = file_get_contents($path);

      $files[$index] = [
        "by_sketch_uid" => $by_sketch_uid,
        "filePath" => $meta[$index],
        "data" => $data,
        "hash" => $hash,
        "size" => $size,
        "created_at" => $now,
        "updated_at" => $now,
        "unencodable_data" => $size > 1000000 || json_encode($data) === false,
      ];
    }

    File::insert($files);

    $sketch->user;
    $sketch->loadCount("forks");
    return response()->json([
      "sketch" => $sketch,
    ]);
  }

  public function get_file(Request $request)
  {
    $validated = $request->validate([
      "uid" => RULE_UID,
    ]);

    $user = request()->user("sanctum");

    try {
      $file = File::where("uid", $validated["uid"])
        ->whereHas("sketch", function ($query) use ($user) {
          $query = $query->where("private", false);
          if ($user) {
            $query->orWhere("by_user_uid", $user->uid);
          }
        })
        ->firstOrFail();

      return response($file["data"])->header(
        "Content-Type",
        "application/octet-stream"
      );
    } catch (ModelNotFoundException $e) {
      return response()->json(
        [
          "message" => "File not exists",
          "code" => "file_not_exists",
        ],
        404
      );
    }
  }

  public function fetch(Request $request)
  {
    $validated = $request->validate([
      "uid" => RULE_UID,

      "meta" => [
        "array",
        "max:120",
        function ($attribute, $value, $fail) {
          if (
            !is_array(request()->get("hashes")) ||
            count($value) !== count(request()->get("hashes"))
          ) {
            return $fail(
              "The number of meta must be equal to the number of hashes"
            );
          }
        },
      ],
      "meta.*" => ["string", "max:260", RULE_FILEPATH],
      "hashes" => ["array"],
      "hashes.*" => ["string", "size:64", 'regex:/^[0-9a-f]{64}$/'],

      "deletes" => ["array", "max:120"],
      "deletes.*" => ["required", "string", "max:260", RULE_FILEPATH],
    ]);

    try {
      $sketch = Sketch::findOrFail($validated["uid"]);
    } catch (ModelNotFoundException $e) {
      return response()->json(
        [
          "message" => "Sketch not exists",
          "code" => "sketch_not_exists",
        ],
        404
      );
    }
    $user = request()->user("sanctum");

    if ($sketch->private && (!$user || $sketch->by_user_uid !== $user->uid)) {
      return response()->json(
        [
          "message" => "Sketch is private",
          "code" => "sketch_is_private",
        ],
        403
      );
    }

    $meta = request()->get("meta");
    $deletes = request()->get("deletes") ?? [];
    if ($meta == null) {
      // client not exists

      $sketch->user;
      $files_change = [];
      foreach ($sketch->files as $file) {
        if (in_array($file->filePath, $deletes)) {
          unset($file->data);
          $files_change[$file->filePath] = [
            "type" => "D",
            "file" => $file,
          ];
        } else {
          $files_change[$file->filePath] = [
            "type" => "U+",
            "file" => $file,
          ];
        }
      }
      unset($sketch->files);
      $sketch->loadCount("forks");
      return response()->json([
        "sketch" => $sketch,
        "file_changes" => $files_change,
      ]);
    }

    $hashes = request()->get("hashes");
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
          // file not change, result to id file
          $files_change[$file->filePath] = [
            "type" => "N",
            "file" => $file,
          ];
        } else {
          // file changes
          $files_change[$file->filePath] = [
            "type" => "M",
            "file" => $file,
          ];
        }
      } else {
        // file not in client // mark this file added;
        if (in_array($file->filePath, $deletes)) {
          $files_change[$file->filePath] = [
            "type" => "D",
            "file" => $file,
          ];
        } else {
          $files_change[$file->filePath] = [
            "type" => "U+",
            "file" => $sketch->file($file->filePath),
          ];
        }
      }
      unset($files_local[$file->filePath]);
    }
    // check new file on locals
    foreach ($files_local as $filePath => $hash) {
      $files_change[$filePath] = [
        "type" => "U",
      ];
    }

    $sketch->user;
    unset($sketch["files_short"]);
    $sketch->loadCount("forks");
    return response()->json([
      "sketch" => $sketch,
      "file_changes" => $files_change,
    ]);
  }

  public function update(Request $request)
  {
    $validated = $request->validate([
      "uid" => RULE_UID,

      "meta" => [
        "array",
        "min:1",
        "max:120",
        function ($attribute, $value, $fail) {
          if (
            !is_array(request()->file("files")) ||
            count($value) !== count(request()->file("files"))
          ) {
            return $fail(
              "The number of meta must be equal to the number of files"
            );
          }
        },
      ],
      "meta.*" => ["string", "max:260", RULE_FILEPATH],
      "files" => ["array", "max:120"],
      "files.*" => ["file", "max:5120"],
      "deletes" => ["array", "max:120"],
      "deletes.*" => ["string", "min:1", "max:260", RULE_FILEPATH],
    ]);

    try {
      $sketch = Sketch::findOrFail($validated["uid"]);
    } catch (ModelNotFoundException $e) {
      return response()->json(
        [
          "message" => "Sketch not exists",
          "code" => "sketch_not_exists",
        ],
        404
      );
    }
    if ($sketch->by_user_uid !== $request->user()->uid) {
      return response()->json(
        [
          "message" => "You do not have permission to update this sketch",
          "code" => "do_not_have_permission_to_update",
        ],
        403
      );
    }

    $files = $request->file("files");
    $files_delete = isset($validated["deletes"]) ? $validated["deletes"] : null;
    if (!$files && !$files_delete) {
      return response()->json(
        [
          "message" => "No need action",
          "code" => "no_need_action",
        ],
        201
      );
    }

    $total_files_size = $sketch->total_files_size;

    $files_update = [];
    $files_update_on_db = [];
    $files_add = [];
    if ($files !== null) {
      $files_update_on_db = $sketch
        ->files_short($validated["meta"])
        ->get()
        ->keyBy("filePath");
      $meta = $validated["meta"];

      foreach ($files as $index => $file) {
        $hash = hash_file("sha256", $file->getRealPath());
        $size = $file->getSize();
        $filePath = $meta[$index];

        if (!isset($files_update_on_db[$filePath])) {
          // file new
          $total_files_size += $size;
          array_push($files_add, [
            "filePath" => $filePath,
            "file" => $file,
            "hash" => $hash,
            "size" => $size,
          ]);
          continue;
        }
        $short_on_db = $files_update_on_db[$meta[$index]];

        if ($size === $short_on_db->size && $hash === $short_on_db->hash) {
          continue;
        }

        $total_files_size += $size - $short_on_db->size;
        // file change
        $files_update[$filePath] = [
          "filePath" => $filePath,
          "file" => $file,
          "hash" => $hash,
          "size" => $size,
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
      return response()->json(
        [
          "message" => "Total size files <= 13MB",
          "code" => "total_size_gt_13mb",
        ],
        422
      );
    }

    if (
      !$files_delete &&
      count($files_update) === 0 &&
      count($files_add) === 0
    ) {
      return response()->json(
        [
          "message" => "No need action",
          "code" => "no_need_action",
        ],
        201
      );
    }

    // update total size sketch
    $sketch->update(["total_files_size" => $total_files_size]);
    // delete files
    if ($files_delete) {
      $files_delete->delete();
    }
    // update files
    foreach ($files_update as $filePath => $diff) {
      $files_update_on_db[$filePath]->update($diff);
    }
    // add files
    $now = now();
    $records = array_map(function ($diff) use ($sketch, $now) {
      $diff["by_sketch_uid"] = $sketch->uid;
      $diff["data"] = file_get_contents($diff["file"]->getRealPath());

      $diff["created_at"] = $now;
      $diff["updated_at"] = $now;

      $diff["unencodable_data"] =
        $diff["size"] > 1000000 || json_encode($diff["data"]) === false;

      unset($diff["file"]);
      return $diff;
    }, $files_add);

    $files_added = [];
    foreach ($records as $record) {
      $files_added[] = [
        "uid" => DB::table("files")->insertGetId($record),
        "hash" => $record["hash"],
      ];
    }

    $sketch->loadCount("forks");
    return response()->json([
      "sketch" => $sketch,
      "files_added" => $files_added,
    ]);
  }

  public function update_info(Request $request)
  {
    $validated = $request->validate([
      "uid" => RULE_UID,
      "name" => [
        "nullable",
        "string",
        "min:1",
        "max:50",
        "required_without_all:private,description",
      ],
      "private" => [
        "nullable",
        "in:0,1",
        "required_without_all:name,description",
      ],
      "description" => [
        "nullable",
        "string",
        "min:1",
        "max:120",
        "required_without_all:name,private",
      ],
    ]);

    try {
      $sketch = Sketch::findOrFail($validated["uid"]);
    } catch (ModelNotFoundException $e) {
      return response()->json(
        [
          "message" => "Sketch not exists",
          "code" => "sketch_not_exists",
        ],
        404
      );
    }
    if ($sketch->by_user_uid !== $request->user()->uid) {
      return response()->json(
        [
          "message" => "You do not have permission to update this sketch",
          "code" => "do_not_have_permission_to_update",
        ],
        403
      );
    }

    if (isset($validated["name"])) {
      $sketch->name = $validated["name"];
    }
    if (isset($validated["private"])) {
      if ($sketch->not_access_public) {
        return response()->json(
          [
            "message" =>
              "This sketch cannot be made public because it was fork from a private sketch",
            "code" => "cannot_public_because_it_fork_from_sketch_private",
          ],
          403
        );
      }
      $sketch->private = $validated["private"];
    }
    if (isset($validated["description"])) {
      $sketch->description = $validated["description"];
    }

    $sketch->save();
    $sketch->user;
    $sketch->loadCount("forks");
    return response()->json([
      "sketch" => $sketch,
    ]);
  }

  public function check_name(Request $request)
  {
    $validated = $request->validate([
      "uid" => RULE_UID,
      "name" => ["required", "string", "min:1", "max:50"],
    ]);
    $user = $request->user();

    $exists = Sketch::where("by_user_uid", $user->uid)
      ->where("name_lower", strtolower($validated["name"]))
      ->where("uid", "!=", $validated["uid"])
      ->exists();

    if ($exists) {
      return response()->json(
        [
          "message" => "The name has already been taken.",
          "code" => "sketch_name_exists",
        ],
        409
      );
    } else {
      return response()->json([
        "code" => "not_exists",
      ]);
    }
  }

  public function fork(Request $request)
  {
    $validated = $request->validate([
      "uid" => RULE_UID,
    ]);

    try {
      $sketch = Sketch::findOrFail($validated["uid"]);
    } catch (ModelNotFoundException $e) {
      return response()->json(
        [
          "message" => "Sketch not exists",
          "code" => "sketch_not_exists",
        ],
        404
      );
    }
    if ($sketch->by_user_uid !== $request->user()->uid) {
      return response()->json(
        [
          "message" => "You do not have permission to update this sketch",
          "code" => "do_not_have_permission_to_update",
        ],
        403
      );
    }

    $user = $request->user();

    $newSketch = $sketch->replicate();
    $newSketch->by_user_uid = $user->uid;
    $newSketch->fork_from = $sketch->uid;
    if ($sketch->private) {
      $newSketch->private = "2";
    }

    $newSketch->save();

    $newSketch->load("user");
    $sketch->loadCount("forks");
    return response()->json([
      "sketch" => $newSketch,
    ]);
  }

  public function delete(Request $request)
  {
    $validated = $request->validate([
      "uid" => RULE_UID,
    ]);

    try {
      $sketch = Sketch::findOrFail($validated["uid"]);
    } catch (ModelNotFoundException $e) {
      return response()->json(
        [
          "message" => "Sketch not exists",
          "code" => "sketch_not_exists",
        ],
        404
      );
    }

    if ($sketch->by_user_uid !== $request->user()->uid) {
      return response()->json([
        "message" => "You do not have permission to update this sketch",
        "code" => "do_not_have_permission_to_update",
      ]);
    }

    $sketch->delete();

    return response()->json([
      "message" => "Deleted sketch",
    ]);
  }
}
