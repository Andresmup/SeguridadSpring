package com.alibou.security.auth;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.alibou.security.config.JwtService;
import com.alibou.security.user.Roles;
import com.alibou.security.user.Usuario;
import com.alibou.security.user.UsuarioRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
	
	private final UsuarioRepository usuarioRepository;
	private final PasswordEncoder passwordEncoder;
	private final JwtService jwtService;
	private final AuthenticationManager authenticationManager;
	
	public AuthenticationResponse register(RegisterRequest request) {
		var usuario = Usuario.builder()
				.nombre(request.getNombre())
				.apellido(request.getApellido())
				.email(request.getEmail())
				.clave(passwordEncoder.encode(request.getClave()))
				.rol(Roles.USER)
				.build();
		
		usuarioRepository.save(usuario);
		var jwtToken = jwtService.generatedToken(usuario);
		return AuthenticationResponse.builder().token(jwtToken).build();
	}

	public AuthenticationResponse authenticate(AuthenticationRequest request) {
		authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getClave()));
		var usuario = usuarioRepository.findByEmail(request.getEmail()).orElseThrow();
		var jwtToken = jwtService.generatedToken(usuario);
		return AuthenticationResponse.builder().token(jwtToken).build();
	}

}
