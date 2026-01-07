# Spring Security JWT (Authentication/Authorization Flow)

JWT 기반 인증/인가를 Spring Security 표준 파이프라인(ProviderManager)에 얹어
**“요청 1건이 어디서 인증되고, 어디서 인가되는지”**를 코드 레벨로 고정한 레포입니다.

---


## Authentication & Authorization Flow (Code-Mapped)

이 문서는 “이 레포에서 인증(Authentication)과 인가(Authorization)가 실제로 어디에서 어떤 순서로 처리되는지”를
클래스/메서드 기준으로 1:1 매핑해서 정리한다.

### 0) 큰 그림: 요청 1건이 지나가는 경로

[Client Request]
  -> SecurityFilterChain (SecurityConfig#filterChain)
      -> JwtAuthFilter#doFilterInternal  (Bearer 파싱 + blacklist + authenticate)
      -> (Spring Security 내부 인가 단계)
      -> Controller
      -> Method Security (@PreAuthorize)  (필요 시)
  -> Response (401/403은 EntryPoint/DeniedHandler가 JSON으로 통일)

핵심: JWT 인증을 UsernamePasswordAuthenticationFilter로 하지 않고,
커스텀 JwtAuthFilter에서 AuthenticationManager.authenticate()로 태우는 구조다.

---

### 1) SecurityFilterChain 구성: “누가 401/403을 내리나?”

#### 1-1. URL 인가 규칙 (SecurityConfig#filterChain)
- GET /health -> permitAll
- POST /auth/login, /auth/refresh -> permitAll
- POST /auth/logout -> authenticated
- /admin/** -> hasRole("ADMIN")
- 나머지 -> authenticated

관련 코드:
- com.example.spring_security_jwt.security.SecurityConfig#filterChain

#### 1-2. 401/403 JSON 응답 통일
- 401(인증 실패/미인증) -> RestAuthEntryPoint
- 403(권한 부족) -> RestAccessDeniedHandler

관련 코드:
- com.example.spring_security_jwt.security.RestAuthEntryPoint#commence
- com.example.spring_security_jwt.security.RestAccessDeniedHandler#handle

---

### 2) “JWT 인증”은 정확히 어디서 일어나나?

#### 2-1. 필터 위치
- SecurityConfig#filterChain:
  - http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)

즉, “Bearer 토큰 기반 인증 시도”가 UsernamePasswordAuthenticationFilter보다 앞에서 실행된다.

관련 코드:
- com.example.spring_security_jwt.security.SecurityConfig#filterChain

---

### 3) JwtAuthFilter의 실제 동작: Bearer 파싱 → 블랙리스트 → authenticate

#### 3-1. Authorization 헤더 파싱
메서드:
- com.example.spring_security_jwt.security.JwtAuthFilter#doFilterInternal

동작:
1) request.getHeader("Authorization") 읽기
2) 헤더가 없거나 "Bearer "로 시작하지 않으면
   - 인증 시도 없이 chain.doFilter로 통과

정리:
- 토큰이 없으면 필터에서 “차단”하지 않는다.
- 대신 나중에 인가 단계에서 authenticated() 요구에 걸려 401이 된다(EntryPoint).

#### 3-2. Bearer 토큰 문자열 추출
- raw = header.substring("Bearer ".length()).trim()

#### 3-3. 블랙리스트 검사(로그아웃 토큰 차단)
- blacklistService.isBlacklisted(raw) == true 면:

1) request.setAttribute(SecurityErrorCodes.ATTR_AUTH_ERROR_CODE, SecurityErrorCodes.TOKEN_BLACKLISTED)
2) SecurityContextHolder.clearContext()
3) chain.doFilter로 진행(= 인증 없음 상태)

중요 포인트:
- 즉시 401을 반환하지 않고,
  “request attribute에 에러코드를 심어두고” 최종 401에서 EntryPoint가 이를 읽어 code/message를 결정한다.

관련 코드:
- JwtAuthFilter#doFilterInternal
- SecurityErrorCodes (ATTR_AUTH_ERROR_CODE, TOKEN_BLACKLISTED)
- RestAuthEntryPoint#commence (request attribute 읽어서 code 결정)

블랙리스트 저장 방식:
- accessToken 원문 저장 X, **jti 기반** 저장
- exp까지 TTL로 유지

관련 코드:
- com.example.spring_security_jwt.service.InMemoryBlacklistService
- com.example.spring_security_jwt.service.RedisJtiBlacklistService

#### 3-4. 실제 인증 시도: AuthenticationManager.authenticate()
블랙리스트가 아니라면:

- authenticationManager.authenticate(JwtAuthenticationToken.unauthenticated(raw))

성공하면:
- SecurityContextHolder.getContext().setAuthentication(auth)

실패하면(예외):
- SecurityContextHolder.clearContext()
- (에러코드는 따로 심지 않음 → 최종 401은 UNAUTHORIZED로 귀결)

관련 코드:
- com.example.spring_security_jwt.security.JwtAuthFilter#doFilterInternal
- com.example.spring_security_jwt.security.JwtAuthenticationToken#unauthenticated

---

### 4) AuthenticationManager는 어떤 Provider를 타나?

SecurityConfig에서 AuthenticationManager를 직접 구성한다.

- ProviderManager(List.of(daoProvider, jwtProvider))

즉,
- UsernamePasswordAuthenticationToken -> DaoAuthenticationProvider
- JwtAuthenticationToken -> JwtAuthenticationProvider

관련 코드:
- com.example.spring_security_jwt.security.SecurityConfig#authenticationManager
- com.example.spring_security_jwt.security.JwtAuthenticationProvider#supports

---

### 5) JWT 검증(서명/만료/issuer)은 어디에서 이뤄지나?

#### 5-1. JwtDecoder 구성 (SecurityConfig#jwtDecoder)
- NimbusJwtDecoder.withSecretKey(...)
- decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(props.issuer()))

decode(token) 시점에:
- 서명 검증
- 만료(exp) 검증
- issuer 검증

관련 코드:
- com.example.spring_security_jwt.security.SecurityConfig#jwtDecoder

#### 5-2. JwtAuthenticationProvider.authenticate
동작:
1) decoder.decode(rawToken)
2) claim "auth" -> authorities로 변환
3) subject(sub) -> principal(username)
4) JwtAuthenticationToken.authenticated(...) 반환

관련 코드:
- com.example.spring_security_jwt.security.JwtAuthenticationProvider#authenticate

---

### 6) 로그인: ID/PW -> Access/Refresh 발급

- AuthController#login -> AuthService#login
- 내부에서 authenticationManager.authenticate(UsernamePasswordAuthenticationToken) 호출
- 성공 시 JwtTokenService#mint로 access/refresh 발급
- refresh는 DB에 “원문 저장 X, sha256 hash 저장” + revoked/rotation 적용

관련 코드:
- com.example.spring_security_jwt.web.AuthController#login
- com.example.spring_security_jwt.service.AuthService#login
- com.example.spring_security_jwt.service.JwtTokenService#mint
- com.example.spring_security_jwt.domain.RefreshToken (tokenHash unique)

---

### 7) Refresh Rotation: refresh 재사용 차단

- AuthController#refresh -> AuthService#refresh
- decodeAndValidateRefresh(typ == refresh)
- DB에서 tokenHash 조회
- 기존 refresh revoke 후 새 refresh 저장(rotate)

관련 코드:
- com.example.spring_security_jwt.service.AuthService#refresh
- com.example.spring_security_jwt.service.AuthService#decodeAndValidateRefresh

---

### 8) 401 vs 403은 어디서 갈리나?

- 401: 인증이 없거나 실패한 상태에서 authenticated()가 필요한 URL 접근
  - 처리: RestAuthEntryPoint
- 403: 인증은 되었지만 hasRole/hasAuthority 조건 불만족
  - 처리: RestAccessDeniedHandler

---

## Test Coverage (High-level)

- AuthFlowMvcTest: 로그인 성공/실패 + /health 공개 + 401/403 기본 흐름
- JwtAuthFilterMvcTest: 토큰 없음/위조/정상 케이스
- AuthorizationMvcTest: ROLE/Permission 기반 403 검증
- LogoutBlacklistMvcTest: logout 후 동일 access 재사용 차단
- RefreshFlowMvcTest: refresh rotation + 이전 refresh 재사용 차단
- JwtTokenServiceTest: access/refresh claim 규약 + 만료 토큰 decode 예외
