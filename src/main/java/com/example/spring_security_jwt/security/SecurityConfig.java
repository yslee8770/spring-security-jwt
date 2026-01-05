package com.example.spring_security_jwt.security;


import com.example.spring_security_jwt.service.BlacklistService;
import com.example.spring_security_jwt.domain.AppUser;
import com.example.spring_security_jwt.repository.UserRepository;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

@Configuration
@EnableMethodSecurity
@EnableConfigurationProperties(JwtProperties.class)
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(UserRepository userRepository) {
        return username -> {
            AppUser u = userRepository.findByUsername(username)
                    .orElseThrow(() -> new UsernameNotFoundException(username));

            var authorities = u.getRoles().stream()
                    .flatMap(r -> {
                        var role = new SimpleGrantedAuthority(r.getName());
                        var perms = r.getPermissions().stream()
                                .map(p -> new SimpleGrantedAuthority(p.getName()));
                        return java.util.stream.Stream.concat(java.util.stream.Stream.of(role), perms);
                    })
                    .toList();

            return User.withUsername(u.getUsername())
                    .password(u.getPasswordHash())
                    .authorities(authorities)
                    .build();
        };
    }

    @Bean
    public SecretKey jwtSecretKey(JwtProperties props) {
        return new SecretKeySpec(props.secret().getBytes(StandardCharsets.UTF_8), "HmacSHA256");
    }

    @Bean
    public JwtEncoder jwtEncoder(SecretKey key) {
        var jwkSource = new com.nimbusds.jose.jwk.source.ImmutableSecret<>(key);
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public JwtDecoder jwtDecoder(SecretKey key) {
        return NimbusJwtDecoder.withSecretKey(key).macAlgorithm(MacAlgorithm.HS256).build();
    }

    @Bean
    public org.springframework.security.authentication.AuthenticationManager authenticationManager(
            UserDetailsService uds,
            PasswordEncoder encoder,
            JwtAuthenticationProvider jwtProvider
    ) {
        var dao = new org.springframework.security.authentication.dao.DaoAuthenticationProvider(uds);
        dao.setPasswordEncoder(encoder);

        return new ProviderManager(java.util.List.of(dao, jwtProvider));
    }

    @Bean
    public SecurityFilterChain filterChain(
            HttpSecurity http,
            org.springframework.security.authentication.AuthenticationManager authenticationManager,
            BlacklistService blacklistService
    ) throws Exception {

        var jwtFilter = new JwtAuthFilter(authenticationManager, blacklistService);

        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(sm -> sm.sessionCreationPolicy(
                        org.springframework.security.config.http.SessionCreationPolicy.STATELESS
                ))
                .exceptionHandling(eh -> eh
                        .authenticationEntryPoint(new RestAuthEntryPoint())
                        .accessDeniedHandler(new RestAccessDeniedHandler())
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.GET, "/health").permitAll()
                        .requestMatchers(HttpMethod.POST, "/auth/login", "/auth/refresh").permitAll()
                        .requestMatchers(HttpMethod.POST, "/auth/logout").authenticated()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .httpBasic(AbstractHttpConfigurer::disable);

        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
