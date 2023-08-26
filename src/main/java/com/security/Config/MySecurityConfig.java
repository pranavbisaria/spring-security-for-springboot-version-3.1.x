package com.security.Config;
import com.security.Security.CustomUserDetailService;
import com.security.Security.JwtAuthenticationEntryPoint;
import com.security.Security.JwtAuthenticationFilter;
import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class MySecurityConfig{
    //    May be available in future versions => refer ("")
//    private String[] PUBLIC_URLS = {
//            "/api/auth/*", "/file/*", "/swagger-ui.html", "/v3/*", "/swagger-resources/*",
//            "/swagger-ui/*", "/v2/*", "/error/*", "/error", "/"
//    };
    private final CustomUserDetailService customUserDetailService;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    MvcRequestMatcher.Builder mvc(HandlerMappingIntrospector introspector) {
        return new MvcRequestMatcher.Builder(introspector);
    }

    @Bean
    public SecurityFilterChain configure(HttpSecurity http, MvcRequestMatcher.Builder mvc) throws Exception {
        http
                .headers(header -> header.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(mvc.pattern("/api/auth/*")).permitAll()
                        .requestMatchers(mvc.pattern("/file/*")).permitAll()
                        .requestMatchers(mvc.pattern("/swagger-ui.html")).permitAll()
                        .requestMatchers(mvc.pattern("/v3/*")).permitAll()
                        .requestMatchers(mvc.pattern("/swagger-resources/*")).permitAll()
                        .requestMatchers(mvc.pattern("/swagger-ui/*")).permitAll()
                        .requestMatchers(mvc.pattern("/v2/*")).permitAll()
                        .requestMatchers(mvc.pattern("/error/*")).permitAll()
                        .requestMatchers(mvc.pattern("/error")).permitAll()
                        .requestMatchers(mvc.pattern("/")).permitAll()
                        .requestMatchers(antMatcher("/h2-console/**")).permitAll()
                        .anyRequest().authenticated())
                .exceptionHandling(exceptionHandler -> exceptionHandler.authenticationEntryPoint(this.jwtAuthenticationEntryPoint))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(this.jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .authenticationProvider(daoAuthenticationProvider());

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    @Bean
    public AuthenticationManager authenticationManagerBean(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(this.customUserDetailService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }
}