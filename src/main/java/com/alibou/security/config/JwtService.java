package com.alibou.security.config;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {
	
	
	@Value("${security.config.secret}")
	private String SECRET_KEY;
	
	public String extractUsuario(String jwtToken) {
		return extractClaim(jwtToken, Claims::getSubject);
	}
	
	public <T> T extractClaim(String jwtToken, Function<Claims,T> claimResolver) {
		final Claims claims = extractAllClaims(jwtToken);
		return claimResolver.apply(claims);
	}
	
	public String generatedToken(UserDetails userDetails) {
		return generatedToken(new HashMap<>(), userDetails);
	}
	
	public String generatedToken(Map<String,Objects> extractClaims, UserDetails userDetails) {
		return Jwts
				.builder()
				.setClaims(extractClaims)
				.setSubject(userDetails.getUsername())
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis()+ 1000 * 60 * 24 )) 
				.signWith(getSignIngKey(), SignatureAlgorithm.HS256)
				.compact();
	}
	
	public boolean isTokenValid(String jwtToken, UserDetails userDetails) {
		final String username = extractUsuario(jwtToken);
		return (username.equals(userDetails.getUsername())) && !isTokenExpired(jwtToken);
	}
	
	
	private boolean isTokenExpired(String jwtToken) {
		return extractExpiration(jwtToken).before(new Date());
	}

	private Date extractExpiration(String jwtToken) {
		return extractClaim(jwtToken,Claims::getExpiration);
	}

	private Claims extractAllClaims(String jwtToken) {
		// Otras 2 formas de no tener error por parseClaimsJwt en vez de parseClaimsJws el cual arroja io.jsonwebtoken.UnsupportedJwtException: Signed Claims JWSs are not supported
		//return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(jwtToken).getBody();
		//return (Claims) Jwts.parserBuilder().setSigningKey(getSignIngKey()).build().parse(jwtToken).getBody();
		return Jwts.parserBuilder().setSigningKey(getSignIngKey()).build().parseClaimsJws(jwtToken).getBody();
		
		
	}

	private Key getSignIngKey() {
		byte [] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
		return Keys.hmacShaKeyFor(keyBytes);
	}
}
