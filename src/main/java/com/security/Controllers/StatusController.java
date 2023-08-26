package com.security.Controllers;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class StatusController {
    @Operation(summary = "This is developer information")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Server Working Successfully", content = @Content(mediaType = "application/json"))
    })
    @GetMapping("/")
    public String test(){
        return "<head> <meta charset=\"UTF-8\"> <title>Pranav Bisaria's Server</title> <link rel=\"icon\" type=\"image/x-icon\" href=\"https://elasticbeanstalk-ap-south-1-665793442236.s3.ap-south-1.amazonaws.com/resources/images/ProfilePhoto.jpeg\"> <meta name=\"author\" content=\"Pranav Bisaria\"> <style> html{ scroll-behavior: smooth; } #mainContainer{ margin: 50px; display: flex; flex-wrap: wrap; flex-direction: column; align-items: center; text-align: center; } #profileImage{ border: 2px solid black; border-radius: 150px; margin: 20px auto; height:300px; width: 300px; } #social{ margin: 70px auto 20px; font-size: 20px; } #resume{ font-size: 30px; } @media screen and (max-width: 1000px){ html{ font-size: 2em; } #profileImage{ border: 2px solid black; border-radius: 45vw; margin: 20px auto; height:auto; width: 90vw; } } </style></head><body><div id =\"mainContainer\">This is the backend server of GreenStitch Task <img id=\"profileImage\" src=\"https://elasticbeanstalk-ap-south-1-665793442236.s3.ap-south-1.amazonaws.com/resources/images/ProfilePhoto.jpeg\" alt=\"APPLICATION LOGO\"> <h1>Designed and Developed by <b>Pranav Bisaria</b></h1> <a target=\"_blank\" rel=\"noopener\" href = \"/swagger-ui/index.html\">API Documentation (Swagger)</a> <a target=\"_blank\" rel=\"noopener\" href = \"https://github.com/pranavbisaria/Login-Signup\">Github Repo (Source Code)</a> <div id=\"social\"> <a target=\"_blank\" rel=\"noopener\" href = \"https://github.com/pranavbisaria\">Github Profile</a> and <a target=\"_blank\" rel=\"noopener\" href = \"https://www.linkedin.com/in/pranavbisaria/\">LinkedIn Profile</a> </div> <a target=\"_blank\" rel=\"noopener\" id=\"resume\" href = \"https://drive.google.com/file/d/1I9uzLdoeBwxPGcw47hLH0yhvA48pgwS6/view?usp=share_link\">Resume</a></div></body>";
    }
}
