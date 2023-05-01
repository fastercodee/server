<?php
namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class EmailAndUsernameLower
{
    public function handle(Request $request, Closure $next)
    {
        if ($request->has('email'))
            $request->merge(['email' => trim(strtolower($request->input('email')))]);

        if ($request->has('username'))
            $request->merge(['username' => trim(strtolower($request->input('username')))]);

        return $next($request);
    }
}