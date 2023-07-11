package br.ufg.twssl.config;

import br.ufg.twssl.service.CertificateUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.SecurityFilterChain;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

@Configuration
public class SecurityConfig {
    @Autowired
    private CertificateUserDetailsService certificateUserDetailsService;
    @Bean
    public SecurityFilterChain defaltFilterChain(HttpSecurity http) throws Exception {
        http    .cors().and().csrf().disable()
                .authorizeHttpRequests()
                .antMatchers("/api/token").permitAll()
                .antMatchers("/certificado").permitAll()
                .anyRequest().authenticated()
                .and()
                .x509()
                .subjectPrincipalRegex("CN=(.*?)(?:,|$)")
                .userDetailsService(userDetailsService());
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                try {
                    if(certificateUserDetailsService.isCertificateInTrustStore(username)){
                        return new User(username, "",
                                AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER"));
                    }
                } catch (KeyStoreException e) {
                    throw new RuntimeException(e);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                } catch (CertificateException e) {
                    throw new RuntimeException(e);
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }
                throw new UsernameNotFoundException("user: "+username+" não pertence ao truststore\n");
            }
        };
    }
}
