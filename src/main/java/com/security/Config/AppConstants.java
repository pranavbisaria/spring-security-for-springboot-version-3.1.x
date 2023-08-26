package com.security.Config;

public class AppConstants {
    public static final Integer ROLE_ADMIN = 1001;
    public static final Integer ROLE_NORMAL = 1002;
    public static final Integer ROLE_OTHER = 1003;
    public static final long JWT_ACCESS_TOKEN_VALIDITY = 24 * 60 *60; //30 sec
    public static final long JWT_REFRESH_TOKEN_VALIDITY = 100 * 24 * 60 *60; //2 min
    public static final Integer EXPIRE_MINs = 10;
    public static final String secret = "jwtTokenKeyJwtTokenKeyJwtTokenKeyJwtTokenKeyJwtTokenKeyJwtTokenKeyjwtTokenKeyJwtTokenKey";
    public static  final String malePhoto = "https://elasticbeanstalk-ap-south-1-665793442236.s3.ap-south-1.amazonaws.com/resources/images/Male.jpg";
    public static  final String femalePhoto = "https://elasticbeanstalk-ap-south-1-665793442236.s3.ap-south-1.amazonaws.com/resources/images/Female.jpg";
    public static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";
}
