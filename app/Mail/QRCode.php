<?php

namespace App\Mail;

use App\User;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Mail\Mailable;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Storage;

class QRCode extends Mailable
{
    use Queueable, SerializesModels;
    
    /**
     * The order instance.
     *
     * @var \App\User
     */
    protected $user;

    /**
     * Create a new message instance.
     *
     * @return void
     */
    public function __construct(User $user)
    {
        $this->user = $user;
    }

    /**
     * Build the message.
     *
     * @return $this
     */
    public function build()
    {
        $folder = config(('filesystems.disks.do.folder'));
        $file = Storage::disk('do')->get($folder.'/'.$this->user->id.$this->user->email);
        return $this->view('auth.qr')->attachFromStorageDisk(
          'do', 
          $folder.'/'.$this->user->id.$this->user->email,
          'Codigo de verificacion', [
            'mime' => 'image/png'
          ]
        );

    }
}
