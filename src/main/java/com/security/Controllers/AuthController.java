package com.security.Controllers;
import com.security.Payloads.EmailDto;
import com.security.Payloads.ForgetPassword;
import com.security.Payloads.OtpDto;
import com.security.Payloads.UserDto;
import com.security.Security.JwtAuthRequest;
import com.security.Service.AuthService;
import com.security.Service.JWTTokenGenerator;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.concurrent.ExecutionException;
@RestController @RequiredArgsConstructor
@RequestMapping(path ="/api/auth")
public class AuthController {
    private final AuthService userService;
    private final JWTTokenGenerator jwtTokenGenerator;

// User as well as the host login API and          -------------------------/TOKEN GENERATOR User/-----------------------
    @Operation(summary = "This is the API to login into the Application as user, it also acts as a token generator")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Login Successful, Access Token and Refresh Token is generated", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "404", description = "User Not found", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "401", description = "Wrong Password", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "400", description = "(Validation)Invalid Email or Password Format", content = @Content(mediaType = "application/json"))})
    @PostMapping("/login")
    public ResponseEntity<?> createToken(@Valid @RequestBody JwtAuthRequest request) {
        return this.userService.LoginAPI(request, 1002);
    }

//Regenerate refresh token
    @Operation(summary = "This is the API to regenerate access token")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "The refresh token is correct and access token is generated", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "408", description = "Token Expired", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "404", description = "User Not found", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "400", description = "Enter string is not a refresh token", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "400", description = "(Validation)Invalid Email or Password Format", content = @Content(mediaType = "application/json"))
    })
    @GetMapping("/regenerateToken")
    public ResponseEntity<?> refreshToken(@RequestParam String token) {
        return this.jwtTokenGenerator.getRefreshTokenGenerate(token);
    }

//Register Email
    @Operation(summary = "Email to verify for signup")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "OTP successfully send to user account", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "409", description = "User already exist", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "503", description = "Can't able to make your request", content = @Content(mediaType = "application/json"))
    })
    @PostMapping("/signupEmail")
    public ResponseEntity<?> registerEmail(@Valid @RequestBody EmailDto emailDto) throws Exception {
        return this.userService.registerEmail(emailDto);
    }

//Verify OTP for activation of user/host account
    @Operation(summary = "Email OTP verification")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "OTP verified Successfully", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "403", description = "Invalid Action not required to send the API request", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "406", description = "Invalid OTP", content = @Content(mediaType = "application/json"))
    })
    @PostMapping("/verifyotp")
    public ResponseEntity<?> verifyOtp(@Valid @RequestBody OtpDto otpDto) throws ExecutionException {
        return this.userService.verifyToRegister(otpDto);
    }

//SignUP API for user
    @Operation(summary = "Completing signup process after the registration")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "408", description = "Session Time-Out, please try again", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "200", description = "User registerd successfully", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "503", description = "Invalid Action", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "401", description = "Invalid OTP", content = @Content(mediaType = "application/json"))
    })
    @PostMapping("/signupUser")
    public ResponseEntity<?> registerUserDetails(@Valid @RequestBody UserDto userDto) throws ExecutionException {
        return this.userService.signupUser(userDto);
    }

//Forget Password and otp generator API
    @Operation(summary = "To send the OTP to the requested email id if the user forget their credentials")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "OTP successfully sent", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "404", description = "No user with entered email is found", content = @Content(mediaType = "application/json")),
    })
    @PostMapping("/forget")
    public ResponseEntity<?> sendOTP(@Valid @RequestBody EmailDto emailDto) throws Exception {
        return userService.sendOTPForget(emailDto);
    }

//Verify OTP for Password Change
    @Operation(summary = "To verify the OTP to change the password")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "OTP verified Successfully", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "408", description = "Session Time-Out, please try again", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "406", description = "Invalid OTP", content = @Content(mediaType = "application/json"))
    })
    @PostMapping("/verifyPassOtp")
    public ResponseEntity<?> verifyOtpPassChange(@Valid @RequestBody OtpDto otpDto) throws ExecutionException {
        return userService.verifyOTPPasswordChange(otpDto);
    }

//Reset Password OTP to change the password
    @Operation(summary = "Used to reset the password after verifying the OTP if password is forgot by the user")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "408", description = "Invalid OTP input", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "200", description = "Password Reset SUCCESS", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "406", description = "Invalid Action", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "403", description = "Invalid OTP", content = @Content(mediaType = "application/json")),
    })
    @PostMapping("/resetpass")
    public ResponseEntity<?> resetPass(@Valid @RequestBody ForgetPassword forgetPassword) throws ExecutionException {
        return this.userService.resetPassword(forgetPassword);
    }
}