package com.example.spring.security.with.jwt.auth;

import com.example.spring.security.with.jwt.config.JwtService;
import com.example.spring.security.with.jwt.user.User;
import com.example.spring.security.with.jwt.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private  final UserRepository userRepository;
    private final JwtService jwtService;

    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest registerRequest){
        var user= User.builder()
                .firstName(registerRequest.getFirstName())
                .lastName(registerRequest.getLastName())
                .email(registerRequest.getEmail())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .role(registerRequest.getRole())
                .build();
        var savedUser=userRepository.save(user);
        String jwtToken= jwtService.generateToken(user);
        return AuthenticationResponse.builder().accessToken(jwtToken).build();

    }

    public AuthenticationResponse authenticate(AuthenticationRequest request){

        //first step
          //we need to validate our request (validate whether username and password is correct)
          //verify whether user present in the database
          //which AuthenticationProvider -> DaoAuthenticationProvider(Inject)
          //we need to authenticate using authenticateManager injecting this authenticationProvider

        //second step
          //verify whether username and password is correct -> UserNamePasswordAuthenticationToken
          //verify user present in db
          //generateToken
          //return the token
        authenticationManager.authenticate(
         new UsernamePasswordAuthenticationToken(
                 request.getEmail(),
                 request.getPassword()

         )
        );
        var user=userRepository.findByEmail(request.getEmail()).orElseThrow();
        String jwtToken=jwtService.generateToken(user);
        return AuthenticationResponse.builder().accessToken(jwtToken).build();
    }

}
