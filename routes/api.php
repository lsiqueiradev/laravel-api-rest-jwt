<?php

use App\Http\Controllers\Api\AuthController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/


Route::post('login', [AuthController::class, 'login']);
Route::post('login/oauth', [AuthController::class, 'oauth']);
Route::post('register', [AuthController::class, 'register']);

Route::group(['middleware' => ['auth:api']],  function () {
    Route::get('me', function(Request $request) {
        return $request->user();
    });


    Route::post('logout', [AuthController::class, 'logout']);
});
