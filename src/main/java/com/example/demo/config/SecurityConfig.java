package com.example.demo.config;

import java.io.IOException;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

		http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
				.formLogin(form -> form
						.loginPage("/loginPage")
						.loginProcessingUrl("/loginProc")
						.defaultSuccessUrl("/",true)
						.failureUrl("/login")
						.usernameParameter("username")
						.passwordParameter("password")
						.successHandler(new AuthenticationSuccessHandler() {
							
							@Override
							public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
									Authentication authentication) throws IOException, ServletException {
								System.out.print("Authentication : " + authentication);
								response.sendRedirect("/home");
								
							}
						})
						.failureHandler((request, response, exception) -> {
							System.out.print("exception : " + exception.getMessage());
							response.sendRedirect("/login");
						}));

		return http.build();
	}

	@Bean
	public UserDetailsService userDetailsService() {
		UserDetails user = User.withUsername("user").password("{noop}1111").roles("USER").build();
		UserDetails user2 = User.withUsername("user2").password("{noop}1111").roles("USER").build();
		UserDetails user3 = User.withUsername("user3").password("{noop}1111").roles("USER").build();
		return new InMemoryUserDetailsManager(user, user2, user3);
	}

}
