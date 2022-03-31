<?php

namespace App\Http\Controllers\Auth;

use App\User;
use Illuminate\Http\Request;
use PragmaRX\Google2FA\Google2FA;
use App\Http\Controllers\Controller;
use App\Providers\RouteServiceProvider;
use Illuminate\Support\Facades\Auth;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Writer as BaconQrCodeWriter;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use BaconQrCode\Renderer\Image\ImagickImageBackEnd;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use Illuminate\Support\Facades\Hash;

class LoginController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Login Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles authenticating users for the application and
    | redirecting them to your home screen. The controller uses a trait
    | to conveniently provide its functionality to your applications.
    |
    */
    public function login2FA(Request $request, User $user)
    {
    $request->validate(['code_verification' => 'required']);

    if (Hash::check( $request->code_verification, $user->token_login)) {
        $request->session()->regenerate();

        Auth::login($user);

        return redirect()->intended($this->redirectPath());
    }

    return redirect()->back()->withErrors(['error'=> 'Código de verificación incorrecto']);
    }

    public function createUserUrlQR($str)
    {
    $bacon = new BaconQrCodeWriter(new ImageRenderer(
        new RendererStyle(400),
        new ImagickImageBackEnd()
    ));
    $data = $bacon->writeString($str, 'utf-8');

    return 'data:image/png;base64,' . base64_encode($data);
    }

    use AuthenticatesUsers;

    /**
     * Where to redirect users after login.
     *
     * @var string
     */
    protected $redirectTo = RouteServiceProvider::HOME;

    public function login(Request $request)
    {
    $this->validateLogin($request);

    if ($this->hasTooManyLoginAttempts($request)) {
        $this->fireLockoutEvent($request);

        return $this->sendLockoutResponse($request);
    }

    $user = User::where($this->username(), '=', $request->email)->first();

    if (password_verify($request->password, optional($user)->password)) {
        $this->clearLoginAttempts($request);

        $str = chr(rand(65,90)) . chr(rand(65,90)) . chr(rand(65,90)) . chr(rand(65,90)) . chr(rand(65,90));

        $user->token_login = Hash::make($str);

        $user->save();

        $urlQR = $this->createUserUrlQR($str);
        
        return view("auth.2fa", compact('urlQR', 'user'));
    }
    
    $this->incrementLoginAttempts($request);
    
    return $this->sendFailedLoginResponse($request);
}

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest')->except('logout');
    }
}
