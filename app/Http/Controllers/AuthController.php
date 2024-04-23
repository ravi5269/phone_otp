<?php

namespace App\Http\Controllers;
use App\Models\User;
use Twilio\Rest\Client as TwilioClient;

use Illuminate\Http\Request;
use Exception;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    // Registration method in AuthController
    public function register(Request $request)
    {
        // Validate request data
        $request->validate([
            'name' => 'required|string',
            'phone' => 'required|string|unique:users',
            'email' => 'required|email|unique:users',
            'password'=> 'required',
            // Add other fields as needed...
        ]);

        // Create new user and hash the password
        $user = User::create([
            
            'name' => $request->input('name'),
            'email' => $request->input('email'),
            'phone' => $request->input('phone'),
            'password' => bcrypt($request->input('password')),
                    
        ]);

        // Generate random OTP
        $otp = rand(100000, 999999);
        $otpExpiresAt = now()->addMinutes(10);

        // Store OTP and expiration time in the user's record
        $user->phone_otp = $otp;
        $user->phone_otp_expires_at = $otpExpiresAt;
        $user->save();

        // Send OTP using SMS
        $this->sendOtpToPhone($user->phone, $otp);

        // Return success response
        return response()->json(['message'=> 'User registered successfully. OTP sent to your phone number.']);
    }

    // Method to send OTP using Twilio
    private function sendOtpToPhone($phone, $otp)
    {
        // Check if phone number is valid international format
        if (!preg_match('/^\+\d{10,15}$/', $phone)) {
            throw new Exception('Invalid phone number format');
        }

        // Retrieve Twilio credentials from .env
        $accountSid = env('TWILIO_ACCOUNT_SID');
        $authToken = env('TWILIO_AUTH_TOKEN');
        $twilioNumber = env('TWILIO_PHONE_NUMBER');

        // Create a new Twilio client
        $client = new TwilioClient($accountSid, $authToken);

        // Try to send the SMS
        try {
            $client->messages->create(
                $phone,
                [
                    'from'=> $twilioNumber,
                    'body'=> 'Your OTP is: ' . $otp,
                ]
            );
        } catch (\Twilio\Exceptions\RestException $e) {
            // Handle the Twilio exception
            throw new Exception('Error sending OTP: ' . $e->getMessage());
        }
    }

    
      // Delete user by ID
    public function destroy($id)
    {
        // Find the user by ID
        $user = User::find($id);

        // Check if user exists
        if (!$user) {
            return response()->json(['error'=> 'User not found'], 404);
        }

        // Delete the user
        $user->delete();

        // Return success response
        return response()->json(['message'=>'User deleted successfully']);
    }
    // Method to verify OTP
    public function verifyOtp(Request $request)
    {
        // Validate the request data
        $request->validate([
            'phone' => 'required|string',
            'phone_otp' => 'required|numeric',
        ]);

        // Find the user by phone number
        $user = User::where('phone', $request->input('phone'))->first();

        // Check if the user exists
        if (!$user) {
            return response()->json(['error'=>'User not found'], 404);
        }

        // Verify the OTP and check if it has not expired
        if ($user->phone_otp === $request->input('otp') && $user->phone_otp_expires_at && $user->phone_otp_expires_at->isFuture()) {
            // OTP is valid, perform your desired action (e.g., mark the user as verified)
            $user->phone_otp = null; // Clear the OTP
            $user->phone_otp_expires_at = null; // Clear the expiration time
            $user->save();

            // Return success response
            return response()->json(['message'=>'OTP verified successfully']);
        } else {
            // Return error response for invalid or expired OTP
            return response()->json(['error'=>'Invalid or expired OTP'], 400);
        }
    }
    // Method to handle user login
    public function login(Request $request)
    {
        // Validate the request data
        $request->validate([
            'email' => 'required|email',
            'password' => 'required|string',
        ]);

        // Attempt to authenticate the user
        if (Auth::attempt(['email' => $request->input('email'), 'password' => $request->input('password')])) {
            // Authentication successful
            $user = Auth::user();

            // Generate a token for the user (you can use Passport, JWT, or another token system)
            // This example uses a placeholder token generation
            $token = 'user-token-placeholder';

            // Return success response with the user and token
            return response()->json([
                'message' => 'Login successful',
                'user' => $user,
                'token' => $token,
            ]);
        } else {
            // Authentication failed
            return response()->json(['error' => 'Invalid credentials'], 401);
        }
    }


}



    


































































































            
        
        
        

        
        
        

        
        
        

        
        
        

        





        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        


        
        
        
        
        
        
        
        
        
        
        
        
        
        
        

        
        

        

        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        






















