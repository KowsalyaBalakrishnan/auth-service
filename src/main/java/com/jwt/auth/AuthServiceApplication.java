package com.jwt.auth;

import com.jwt.auth.domain.AppUser;
import com.jwt.auth.domain.AppUserRole;
import com.jwt.auth.service.UserService;
import lombok.extern.log4j.Log4j2;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
@Log4j2
public class AuthServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthServiceApplication.class, args);
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		log.info("Initialized PassWord Encoder Bean");
		return new BCryptPasswordEncoder();
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
		log.info("AuthenticationManager is Initializing");
		AuthenticationManager authenticationManager = authenticationConfiguration.getAuthenticationManager();
		log.info("AuthenticationManager is Initialized and it's hashcode is {}", authenticationManager.hashCode());
		return authenticationManager;
	}

	@Bean
	CommandLineRunner run(UserService userService) {
		return args -> {
			userService.saveRole(new AppUserRole(null, "ROLE_USER"));
			userService.saveRole(new AppUserRole(null, "ROLE_MANAGER"));
			userService.saveRole(new AppUserRole(null, "ROLE_ADMIN"));
			userService.saveRole(new AppUserRole(null, "ROLE_SUPER_ADMIN"));

			userService.saveUser(new AppUser(null, "John Trovolta", "John", "123", new ArrayList<>()));
			userService.saveUser(new AppUser(null, "Will Smith", "Will", "456", new ArrayList<>()));
			userService.saveUser(new AppUser(null, "Jim Carry", "Jim", "789", new ArrayList<>()));
			userService.saveUser(new AppUser(null, "Arnold Ketz", "Arnold", "012", new ArrayList<>()));

			userService.addRoleToUser("John", "ROLE_USER");
			userService.addRoleToUser("John", "ROLE_MANAGER");

			userService.addRoleToUser("Will", "ROLE_MANAGER");

			userService.addRoleToUser("Jim", "ROLE_ADMIN");

			userService.addRoleToUser("Arnold", "ROLE_USER");
			userService.addRoleToUser("Arnold", "ROLE_ADMIN");
			userService.addRoleToUser("Arnold", "ROLE_SUPER_ADMIN");

		};
	}
}
