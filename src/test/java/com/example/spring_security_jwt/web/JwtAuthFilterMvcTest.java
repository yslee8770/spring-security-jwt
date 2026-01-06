package com.example.spring_security_jwt.web;

import com.example.spring_security_jwt.security.JwtTokenService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class JwtAuthFilterMvcTest {

    @Autowired MockMvc mvc;
    @Autowired JwtTokenService tokenService;

    @Test
    void me_without_token_returns_401() throws Exception {
        mvc.perform(get("/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON));
    }

    @Test
    void me_with_tampered_token_returns_401() throws Exception {
        var pair = tokenService.mint(1L, "user", new String[]{"ROLE_USER"});
        String tampered = pair.accessToken() + "x";

        mvc.perform(get("/me")
                        .header("Authorization", "Bearer " + tampered))
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON));
    }

    @Test
    void me_with_valid_token_returns_200() throws Exception {
        var pair = tokenService.mint(1L, "user", new String[]{"ROLE_USER"});

        mvc.perform(get("/me")
                        .header("Authorization", "Bearer " + pair.accessToken()))
                .andExpect(status().isOk());
    }
}
