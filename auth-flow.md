# Authentication & Authorization Flow (Code-Mapped)

이 문서는 “이 레포에서 인증(Authentication)과 인가(Authorization)가 실제로 어디에서 어떤 순서로 처리되는지”를
클래스/메서드 기준으로 1:1 매핑해서 정리한다.

---

## 0) 큰 그림: 요청 1건이 지나가는 경로

[Client Request]
  -> SecurityFilterChain (SecurityConfig#filterChain)
      -> JwtAuthFilter#doFilterInternal  (Bearer 파싱 + blacklist + authenticate)
      -> (Spring Security 내부 인가 단계)
      -> Controller
      -> Method Security (@PreAuthorize)  (필요 시)
  -> Response (401/403은 EntryPoint/DeniedHandler가 JSON으로 통일)

이 레포의 핵심은 “JWT 인증을 UsernamePasswordAuthenticationFilter로 하지 않고,
커스텀 JwtAuthFilter에서 AuthenticationManager.authenticate()로 태우는 구조”다.

---

## 1) SecurityFilterChain 구성: “누가 401/403을 내리나나”

### 1-1. URL 인가 규칙 (SecurityConfig#filterChain)
- GET /health -> permitAll
- POST /auth/login, /auth/refresh -> permitAll
- POST /auth/logout -> authenticated
- /admin/** -> hasRole("ADMIN")
- 나머지 -> authenticated

관련 코드:
- com.example.spring_security_jwt.security.SecurityConfig#filterChain

### 1-2. 401/403 JSON 응답 통일 (SecurityConfig#filterChain)
- 401(인증 실패/미인증) -> RestAuthEntryPoint
- 403(권한 부족) -> RestAccessDeniedHandler

관련 코드:
- com.example.spring_security_jwt.security.RestAuthEntryPoint#commence
- com.example.spring_security_jwt.security.RestAccessDeniedHandler#handle

응답 예시(개념):
- 401: {"code":"UNAUTHORIZED" or "TOKEN_BLACKLISTED", "message":"..."}
- 403: {"code":"FORBIDDEN","message":"Access denied"}

---

## 2) “JWT 인증”은 정확히 어디서 일어나나

### 2-1. 필터 위치: JwtAuthFilter는 어디에 끼워져 있나
- SecurityConfig#filterChain 에서:
  - http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)

즉, “Bearer 토큰 기반 인증 시도”가 UsernamePasswordAuthenticationFilter보다 앞에서 실행된다.

관련 코드:
- com.example.spring_security_jwt.security.SecurityConfig#filterChain

---

## 3) JwtAuthFilter의 실제 동작(핵심): Bearer 파싱 → 블랙리스트 → authenticate

### 3-1. Authorization 헤더 파싱
메서드:
- com.example.spring_security_jwt.security.JwtAuthFilter#doFilterInternal

동작:
1) request.getHeader("Authorization") 읽기
2) 헤더가 없거나 "Bearer "로 시작하지 않으면
   - “인증 시도 자체를 하지 않고” chain.doFilter로 통과

정리:
- 토큰이 없으면 “필터에서 막지 않는다”
- 대신 나중에 인가 단계에서 “authenticated() 요구”에 걸려 401이 된다(EntryPoint).

### 3-2. Bearer 토큰 문자열 추출
- raw = header.substring("Bearer ".length()).trim()

### 3-3. 블랙리스트 검사(로그아웃 토큰 차단)
- blacklistService.isBlacklisted(raw) 가 true면:

1) request.setAttribute(SecurityErrorCodes.ATTR_AUTH_ERROR_CODE, SecurityErrorCodes.TOKEN_BLACKLISTED)
2) SecurityContextHolder.clearContext()
3) chain.doFilter로 통과

중요 포인트:
- “여기서 즉시 401을 내려서 끝내지 않는다”
- 대신 request attribute에 에러 코드를 심어두고,
  최종적으로 인증이 필요했던 endpoint에서 401이 발생할 때 EntryPoint가 이 코드를 읽어 메시지를 바꾼다.

관련 코드:
- JwtAuthFilter#doFilterInternal
- SecurityErrorCodes (ATTR_AUTH_ERROR_CODE, TOKEN_BLACKLISTED)
- RestAuthEntryPoint#commence (request attribute 읽어서 code 결정)

블랙리스트 구현 디테일(토큰 저장 키):
- InMemoryBlacklistService / RedisJtiBlacklistService 모두 “accessToken의 jti”를 키로 저장한다.
- 즉, blacklist는 “토큰 원문”이 아니라 “jti” 기반이다.

관련 코드:
- com.example.spring_security_jwt.service.InMemoryBlacklistService
  - blacklist(): jwtDecoder.decode(accessToken) -> jwt.getId(), jwt.getExpiresAt() -> store.put(jti, exp)
  - isBlacklisted(): jti가 store에 있고 exp가 미래면 true
- com.example.spring_security_jwt.service.RedisJtiBlacklistService
  - KEY_PREFIX = "jwt:blacklist:jti:"
  - blacklist(): ttl=exp-now 로 redis set
  - isBlacklisted(): redis.hasKey(KEY_PREFIX + jti)

### 3-4. 실제 인증 시도: AuthenticationManager.authenticate()
블랙리스트가 아니라면 JwtAuthFilter는 아래를 수행한다:

- authenticationManager.authenticate(JwtAuthenticationToken.unauthenticated(raw))

성공하면:
- SecurityContextHolder.getContext().setAuthentication(auth)

실패(예외 발생)하면:
- SecurityContextHolder.clearContext()
- (에러코드는 따로 심지 않음)

관련 코드:
- com.example.spring_security_jwt.security.JwtAuthFilter#doFilterInternal
- com.example.spring_security_jwt.security.JwtAuthenticationToken#unauthenticated

---

## 4) AuthenticationManager는 어떤 Provider를 타나

이 레포는 AuthenticationManager를 직접 구성한다.

### 4-1. ProviderManager 구성 (SecurityConfig#authenticationManager)
- ProviderManager(List.of(daoProvider, jwtProvider))

여기서:
- daoProvider = DaoAuthenticationProvider(UserDetailsService + PasswordEncoder)
- jwtProvider = JwtAuthenticationProvider(JwtDecoder)

즉,
- UsernamePasswordAuthenticationToken 이 들어오면 -> DaoAuthenticationProvider가 처리
- JwtAuthenticationToken 이 들어오면 -> JwtAuthenticationProvider가 처리

관련 코드:
- com.example.spring_security_jwt.security.SecurityConfig#authenticationManager
- com.example.spring_security_jwt.security.JwtAuthenticationProvider#supports
- org.springframework.security.authentication.dao.DaoAuthenticationProvider (Spring 기본)

---

## 5) JWT 검증(서명/만료/issuer)은 어디에서 이뤄지나

### 5-1. JwtDecoder 구성 (SecurityConfig#jwtDecoder)
- NimbusJwtDecoder.withSecretKey(jwtSecretKey(props)).build()
- decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(props.issuer()))

즉, decode(token) 시점에:
- 서명(HS256) 검증
- 만료(exp) 검증
- issuer 검증(app.jwt.issuer)

관련 코드:
- com.example.spring_security_jwt.security.SecurityConfig#jwtDecoder
- com.example.spring_security_jwt.security.JwtProperties (issuer, secret, ttl)

### 5-2. JwtAuthenticationProvider.authenticate
메서드:
- com.example.spring_security_jwt.security.JwtAuthenticationProvider#authenticate

동작:
1) (JwtAuthenticationToken) 캐스팅
2) decoder.decode(token.getToken())  // 위조/만료/issuer 불일치면 예외
3) claim "auth"를 List<String>으로 읽어 SimpleGrantedAuthority로 변환
4) subject(sub)를 username으로 사용
5) JwtAuthenticationToken.authenticated(username, authorities) 반환

주의:
- claim "auth"가 없으면 authorities는 빈 리스트가 된다.
- 이후 인가에서 hasRole/hasAuthority가 전부 실패할 수 있다.

---

## 6) “로그인”은 어디서 처리되고, 어떤 토큰을 발급하나

### 6-1. /auth/login API (AuthController#login)
- com.example.spring_security_jwt.web.AuthController#login
  - AuthService#login(username, password) 호출

### 6-2. AuthService#login: Username/Password 인증 후 Token 발급
- com.example.spring_security_jwt.service.AuthService#login (@Transactional)

동작:
1) authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password))
   -> DaoAuthenticationProvider가 UserDetailsService + BCrypt로 검증
2) auth.getAuthorities()를 String[]로 뽑아 JwtTokenService.mint(userId, username, authorities) 호출
3) refreshToken은 “원문 저장이 아니라 SHA-256 해시(tokenHash)”로 DB 저장
   - RefreshToken.tokenHash 는 unique=true
4) TokenPair(access, refresh, accessExpiresAt) 반환

관련 코드:
- AuthService#login
- SecurityConfig#userDetailsService (DB에서 AppUser 로드 + 역할/권한을 GrantedAuthority로 생성)
- SecurityConfig#passwordEncoder (BCryptPasswordEncoder)
- JwtTokenService#mint / #encode
- com.example.spring_security_jwt.domain.RefreshToken (tokenHash unique)

---

## 7) Refresh Token Rotation은 어디서 막히나

### 7-1. /auth/refresh API
- com.example.spring_security_jwt.web.AuthController#refresh
  - AuthService#refresh(refreshToken)

### 7-2. AuthService#refresh: “DB에 저장된 refresh만 유효”
동작:
1) decodeAndValidateRefresh(refreshToken)
   - jwtDecoder.decode(refreshToken)
   - claim "typ"가 "refresh"인지 확인 (아니면 REFRESH_INVALID)
2) hash = sha256(refreshToken)
3) refreshTokenRepository.findByTokenHash(hash) 로 DB 조회 (없으면 실패)
4) revoked=true 이거나 만료면 실패
5) (선택 검증) claim uid가 DB userId와 다르면 실패
6) saved.revoke() 로 “이전 refresh는 폐기”
7) user 조회 후 roles/permissions로 authorities 재구성
8) JwtTokenService.mint(...) 로 새 access/refresh 발급
9) 새 refreshHash를 다시 DB에 저장(회전/로테이션)

관련 코드:
- com.example.spring_security_jwt.service.AuthService#refresh
- com.example.spring_security_jwt.service.AuthService#decodeAndValidateRefresh
- com.example.spring_security_jwt.domain.RefreshToken#revoke

에러 응답:
- REFRESH_INVALID 는 AuthApiExceptionHandler가 401 JSON으로 변환한다.

관련 코드:
- com.example.spring_security_jwt.web.AuthApiExceptionHandler#illegalState

---

## 8) Logout(블랙리스트)는 어디서 적용되나

### 8-1. /auth/logout API
- com.example.spring_security_jwt.web.AuthController#logout
  - Authorization 헤더에서 Bearer 토큰을 substring으로 추출해 AuthService.logout(token) 호출

### 8-2. AuthService#logout
- com.example.spring_security_jwt.service.AuthService#logout
  - blacklistService.blacklist(accessToken) 호출

### 8-3. 다음 요청부터 차단되는 지점
- 이후 같은 accessToken으로 /me 요청 시:
  - JwtAuthFilter#doFilterInternal 에서 blacklistService.isBlacklisted(raw) == true
  - request attribute에 TOKEN_BLACKLISTED 심음
  - 인증을 세팅하지 않고 통과
  - /me 는 authenticated() 이므로 최종 401
  - RestAuthEntryPoint가 TOKEN_BLACKLISTED를 읽고 message를 "Token is blacklisted"로 내려준다

---

## 9) 인가(Authorization)는 어디서 나뉘나 (401 vs 403)

### 9-1. 401 (미인증)
- 토큰이 없거나 / 토큰이 유효하지 않아 SecurityContext에 Authentication이 없는 상태에서
  “authenticated()”가 요구되는 URL로 접근하면 401 발생
- 처리 주체: RestAuthEntryPoint

### 9-2. 403 (권한 부족)
- 토큰은 유효해서 Authentication은 존재하지만,
  - /admin/** hasRole("ADMIN") 조건 불만족
  - 또는 @PreAuthorize("hasAuthority('PERM_REPORT_READ')") 불만족
  이면 403 발생
- 처리 주체: RestAccessDeniedHandler

---
-

## 10) 이 구현의 의도적 단순화
- JWT 인증을 “커스텀 필터 + AuthenticationManager + 커스텀 Provider”로 구성해서
  Spring Security의 표준 인증 파이프라인(ProviderManager)을 그대로 활용하면서,
  JWT 처리 책임을 코드로 명확히 드러낸다.
- Refresh Token은 “원문 저장 금지(해시 저장)” + “회전(rotate) + revoke”를 적용해
  서비스에서 쓰는 패턴을 최소 구현으로 보여준다.
- 블랙리스트는 “토큰 원문이 아니라 jti 기반”으로 저장해 저장 공간/조회 방식을 단순화한다.


