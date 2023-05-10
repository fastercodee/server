<?php
namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class EmailAndUsernameLower
{
    public function handle(Request $request, Closure $next)
    {
        if ($request->has('email'))
            $request->merge(['email' => trim(strtolower($request->input('email')))]);

        if ($request->has('username'))
            $request->merge(['username' => trim($request->input('username'))]);

        if ($request->has('name'))
            $request->merge(['name' => trim($request->input('name'))]);

        if ($request->has('description'))
            $request->merge(['description' => trim($request->input('description'))]);

        return $next($request);
    }
}