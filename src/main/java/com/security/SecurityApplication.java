package com.security;

import com.security.Config.AppConstants;
import com.security.Models.Role;
import com.security.Repository.RoleRepo;
import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Info;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableAsync;
import java.util.List;

@SpringBootApplication
@EnableCaching
@EnableAsync
@RequiredArgsConstructor
@OpenAPIDefinition(info = @Info(title = "Spring Security- By Pranav Bisaria", version = "3.1.3", description = "This is a springboot application demonstration for login/signup along with the JWT token filter with access and refresh token and email OTP verification and caching using Guava cache."))
public class SecurityApplication implements CommandLineRunner {
	private final RoleRepo roleRepo;
	@Bean
	public ModelMapper modelMapper(){
		return new ModelMapper();
	}

	public static void main(String[] args) {
		SpringApplication.run(SecurityApplication.class, args);
	}

	@Override
	public void run(String... args){
		try{
			Role role1 = new Role();
			role1.setId(AppConstants.ROLE_ADMIN);
			role1.setName("ROLE_ADMIN");

			Role role2 = new Role();
			role2.setId(AppConstants.ROLE_NORMAL);
			role2.setName("ROLE_NORMAL");

			Role role3 = new Role();
			role3.setId(AppConstants.ROLE_OTHER);
			role3.setName("ROLE_OTHER");

			List<Role> roles= List.of(role1, role2, role3);
			this.roleRepo.saveAll(roles);
		}
		catch (Exception e){
			e.printStackTrace();
		}
	}
}
