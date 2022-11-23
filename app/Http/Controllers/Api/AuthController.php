<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);
        $credentials = $request->only('email', 'password');

        $token = Auth::attempt($credentials);
        if (!$token) {
            return response()->json([
                'status' => 'error',
                'message' => 'Unauthorized',
            ], 401);
        }

        $user = Auth::user();
        return response()->json([
                'user' => $user,
                'token' => $token
            ]);

    }

    public function register(Request $request)
    {
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6',
        ]);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        return response()->json([
            'user' => $user
        ], 201);
    }

    public function oauth(Request $request) {

        $user = User::where(
            'email', $request->email
        )->first();

        if ($user) {
            $token = auth()->login($user);
            return response()->json([
                'user' => $user,
                'token' => $token
            ]);
        } else {
            $user = User::create([
                'email' => $request->email,
                'name' => $request->name,
                'avatar_url' => $request->picture,
                'token_oauth' => $request->access_token,
                'provider' => $request->provider,
            ]);

            $token = auth()->login($user);
            return response()->json([
                'user' => $user,
                'token' => $token
            ]);
        }


    }

    public function logout()
    {
        Auth::logout();
        return response()->json([]);
    }

    public function refresh()
    {
        return response()->json([
            'status' => 'success',
            'user' => Auth::user(),
            'authorisation' => [
                'token' => Auth::refresh(),
                'type' => 'bearer',
            ]
        ]);
    }

}
