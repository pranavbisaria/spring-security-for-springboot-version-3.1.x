package com.security.Service;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Random;

@Service @RequiredArgsConstructor
@Slf4j
public class OTPService {
    private final EmailService emailService;

    public int OTPRequest(String email) {
        Random rand = new Random();
        int otpCheck = rand.nextInt(899999) + 100000;
        String subject = "OTP Verification";
        String message = "Dear User," +
                "\nThe One Time Password (OTP) to verify your Email Address is " + otpCheck +
                "\nThe One Time Password is valid for the next 10 minutes." +
                "\n(This is an auto generated email, so please do not reply back. Email at pranavbisariya29@gmail.com)" +
                "\nRegards," +
                "\nPranav Bisaria";
        String to = email;
        this.emailService.sendEmail(subject, message, to);
        return otpCheck;
    }

    public void SuccessRequest(String email, String name) {
        String subject = "Successfully registered on Pranav's Backend Server";
        String message = "Dear " + name + "," +
                "\nThank you for registering on my Server" +
                "\nPlease let me know if you love the application and if you need anything else from me at this point." +
                "\n(This is an auto generated email, so please do not reply back. Email at pranavbisariya29@gmail.com)" +
                "\nRegards," +
                "\nPranav Bisaria";
        String to = email;
        this.emailService.sendEmail(subject, message, to);
    }
}