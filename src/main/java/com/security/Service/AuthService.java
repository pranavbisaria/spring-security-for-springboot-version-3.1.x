package com.security.Service;

import com.security.Payloads.EmailDto;
import com.security.Payloads.ForgetPassword;
import com.security.Payloads.OtpDto;
import com.security.Payloads.UserDto;
import com.security.Security.JwtAuthRequest;
import org.springframework.http.ResponseEntity;

import java.util.concurrent.ExecutionException;

public interface AuthService {
    ResponseEntity<?> LoginAPI(JwtAuthRequest request, Integer RoleID);
    ResponseEntity<?> registerEmail(EmailDto emailDto) throws Exception;
    ResponseEntity<?> verifyToRegister(OtpDto otpDto) throws ExecutionException;
    ResponseEntity<?> signupUser(UserDto userDto) throws ExecutionException;
    ResponseEntity<?> verifyOTPPasswordChange(OtpDto otpDto) throws ExecutionException;
    ResponseEntity<?> resetPassword(ForgetPassword forgetPassword) throws ExecutionException;
    ResponseEntity<?> sendOTPForget(EmailDto emailDto) throws Exception;
}
