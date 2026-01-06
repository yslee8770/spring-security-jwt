package com.example.spring_security_jwt.web;

import com.example.spring_security_jwt.domain.AppUser;
import com.example.spring_security_jwt.domain.Role;
import com.example.spring_security_jwt.repository.RoleRepository;
import com.example.spring_security_jwt.repository.UserRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class RefreshFlowMvcTest {

    @Autowired MockMvc mvc;
    @Autowired UserRepository userRepository;
    @Autowired RoleRepository roleRepository;
    @Autowired PasswordEncoder encoder;

    private final ObjectMapper om = new ObjectMapper();

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
        roleRepository.deleteAll();

        Role userRole = roleRepository.save(new Role("ROLE_USER"));

        AppUser user = new AppUser("user", encoder.encode("1234"));
        user.addRole(userRole);
        userRepository.save(user);
    }

    @Test
    void refresh_rotation_success_and_old_refresh_reuse_is_rejected() throws Exception {
        // 1) login -> refresh 확보
        Tokens first = login("user", "1234");
        assertThat(first.refreshToken()).isNotBlank();

        // 2) refresh 1회 사용 -> 새 access/refresh 발급
        Tokens rotated = refresh(first.refreshToken());
        assertThat(rotated.refreshToken()).isNotBlank();
        assertThat(rotated.refreshToken()).isNotEqualTo(first.refreshToken());

        // 3) "이전 refresh" 재사용 -> 401 (revoke된 토큰)
        mvc.perform(post("/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"refreshToken":"%s"}
                                """.formatted(first.refreshToken())))
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.code").value("REFRESH_INVALID"));

        // 4) 새 refresh는 정상 동작(연쇄 로테이션)
        Tokens rotated2 = refresh(rotated.refreshToken());
        assertThat(rotated2.refreshToken()).isNotEqualTo(rotated.refreshToken());
    }

    private Tokens login(String username, String password) throws Exception {
        String resp = mvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"%s","password":"%s"}
                                """.formatted(username, password)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists())
                .andReturn().getResponse().getContentAsString();

        JsonNode json = om.readTree(resp);
        return new Tokens(json.get("accessToken").asText(), json.get("refreshToken").asText());
    }

    private Tokens refresh(String refreshToken) throws Exception {
        String resp = mvc.perform(post("/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"refreshToken":"%s"}
                                """.formatted(refreshToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists())
                .andReturn().getResponse().getContentAsString();

        JsonNode json = om.readTree(resp);
        return new Tokens(json.get("accessToken").asText(), json.get("refreshToken").asText());
    }

    private record Tokens(String accessToken, String refreshToken) {}
}
