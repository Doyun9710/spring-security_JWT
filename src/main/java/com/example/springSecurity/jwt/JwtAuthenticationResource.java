package com.example.springSecurity.jwt;

import java.time.Instant;
import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwtAuthenticationResource {
	
	private JwtEncoder jwtEncoder;
	
	public JwtAuthenticationResource(JwtEncoder jwtEncoder) {
		this.jwtEncoder = jwtEncoder;
	}

    // @PostMapping("/authenticate") 
	// public Authentication authenticate(Authentication authentication) {
	// 	return authentication;
	// }
	
	@PostMapping("/authenticate") 
	public JwtRespose authenticate(Authentication authentication) {
		return new JwtRespose(createToken(authentication));
	}

	private String createToken(Authentication authentication) {
		var claims = JwtClaimsSet.builder()
								.issuer("doyun")     // 발행자
								.issuedAt(Instant.now())    // 기준 시간
								.expiresAt(Instant.now().plusSeconds(60 * 30))      // 유효 시간 설정 (60 * 30 초)
								.subject(authentication.getName())                  // 이름
								.claim("scope", createScope(authentication))    // 허용 권한
								.build();
		
		return jwtEncoder.encode(JwtEncoderParameters.from(claims))
						.getTokenValue();
	}

	private String createScope(Authentication authentication) {
		return authentication.getAuthorities().stream()
			.map(a -> a.getAuthority())
			.collect(Collectors.joining(" "));			
	}

}

record JwtRespose(String token) {}